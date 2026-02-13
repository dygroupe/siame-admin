<?php 

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use App\Models\PaymentRequest;
use App\Traits\Processor;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Exception;

// Définition des constantes de réponse directement dans le contrôleur
const GATEWAYS_DEFAULT_400 = [
    'response_code' => 'gateways_default_400',
    'message' => 'invalid or missing information'
];

const GATEWAYS_DEFAULT_204 = [
    'response_code' => 'gateways_default_204',
    'message' => 'information not found'
];

class OrangeMoneyController extends Controller
{
    use Processor;

    /**
     * Sonatel Sénégal.
     * Base URLs issues de la documentation officielle :
     *  - Sandbox : https://api.sandbox.orange-sonatel.com
     *  - Live    : https://api.orange-sonatel.com
     */
    private const OM_LIVE_BASE_URL = 'https://api.orange-sonatel.com';
    private const OM_SANDBOX_BASE_URL = 'https://api.sandbox.orange-sonatel.com';
    /** Endpoint QR Code eWallet v4 (cf. doc /api/eWallet/v4/qrcode). */
    private const OM_QRCODE_ENDPOINT = '/api/eWallet/v4/qrcode';

    private $config_values;
    private PaymentRequest $payment;
    private $user;
    private $base_url;
    private $access_token;
    private $client_id;
    private $client_secret;
    private $merchant_code;

    public function __construct(PaymentRequest $payment, User $user)
    {
        try {
            $config = $this->payment_config('orange_money', 'payment_config');

            // Récupération des valeurs de configuration (priorité : table payment_config puis config/orange.php)
            if (!is_null($config) && $config->mode === 'live') {
                $this->config_values = json_decode($config->live_values, true);
            } elseif (!is_null($config) && $config->mode === 'test') {
                $this->config_values = json_decode($config->test_values, true);
            } else {
                $this->config_values = [
                    'client_id' => config('orange.client_id', ''),
                    'client_secret' => config('orange.client_secret', ''),
                    'merchant_code' => config('orange.merchant_id', ''),
                    'merchant_name' => config('orange.business_name', 'SIAME'),
                ];
            }

            // Détermination du mode (test / live) et de l'URL de base selon la documentation Sonatel
            $mode = $config->mode ?? config('orange.mode', 'test');
            // On ne lit l'override que depuis l'ENV pour éviter que la valeur par défaut
            // de config/orange.php ("") force api.orange.com.
            $configuredBaseUrl = env('ORANGE_BASE_URL');

            if (!empty($configuredBaseUrl)) {
                // Si l'URL est définie dans l'env, on la respecte (permet de surcharger sandbox/live)
                $this->base_url = rtrim($configuredBaseUrl, '/');
            } else {
                // Sinon on applique strictement la doc Sonatel : sandbox ou live
                $this->base_url = $mode === 'live'
                    ? self::OM_LIVE_BASE_URL
                    : self::OM_SANDBOX_BASE_URL;
            }

            // Extraction des valeurs de configuration (trim pour éviter espaces en copier-coller)
            $this->client_id = trim((string) ($this->config_values['client_id'] ?? ''));
            $this->client_secret = trim((string) ($this->config_values['client_secret'] ?? ''));
            $this->merchant_code = trim((string) ($this->config_values['merchant_code'] ?? ''));

            // Vérification des clés API requises
            if (empty($this->client_id) || empty($this->client_secret)) {
                Log::warning('Orange Money: Credentials manquants - Mode test uniquement');
            }

            if (empty($this->merchant_code)) {
                Log::warning('Orange Money: Code marchand manquant');
            }

        } catch (Exception $e) {
            // Configuration par défaut en cas d'erreur de base
            $this->config_values = [
                'client_id' => config('orange.client_id', ''),
                'client_secret' => config('orange.client_secret', ''),
                'merchant_code' => config('orange.merchant_id', ''),
                'merchant_name' => config('orange.business_name', 'SIAME'),
            ];

            $configuredBaseUrl = env('ORANGE_BASE_URL');
            $mode = config('orange.mode', 'test');
            $this->base_url = !empty($configuredBaseUrl)
                ? rtrim($configuredBaseUrl, '/')
                : ($mode === 'live' ? self::OM_LIVE_BASE_URL : self::OM_SANDBOX_BASE_URL);
            $this->client_id = trim((string) ($this->config_values['client_id'] ?? ''));
            $this->client_secret = trim((string) ($this->config_values['client_secret'] ?? ''));
            $this->merchant_code = trim((string) ($this->config_values['merchant_code'] ?? ''));
        }

        $this->payment = $payment;
        $this->user = $user;

        // Log de la configuration pour débogage
            Log::info('Orange Money: Configuration initialisée', [
                'mode' => $mode ?? 'test',
                'base_url' => $this->base_url,
                'merchant_code' => substr($this->merchant_code, 0, 3) . '...',
            ]);
    }

    /**
     * Obtient un access token Sonatel (form body client_id / client_secret).
     * Cf. doc : POST {base_url}/oauth/v1/token
     */
    private function getAccessToken()
    {
        try {
            if (empty($this->client_id) || empty($this->client_secret)) {
                Log::error('Orange Money: client_id ou client_secret manquant');
                throw new Exception('Identifiants Orange Money non configurés (client_id / client_secret).');
            }

            $cache_key = 'orange_money_access_token_' . md5($this->client_id);
            $cached_token = cache()->get($cache_key);
            if ($cached_token && isset($cached_token['token']) && isset($cached_token['expires_at']) && now()->timestamp < $cached_token['expires_at']) {
                return $cached_token['token'];
            }

            // URL du token strictement conforme à la documentation :
            //  - Sandbox : https://api.sandbox.orange-sonatel.com/oauth/v1/token
            //  - Live    : https://api.orange-sonatel.com/oauth/v1/token
            $tokenUrl = rtrim($this->base_url, '/') . '/oauth/v1/token';

            $response = Http::asForm()
                ->timeout(30)
                ->post($tokenUrl, [
                    'client_id' => $this->client_id,
                    'grant_type' => 'client_credentials',
                    'client_secret' => $this->client_secret,
                ]);

            if (!$response->successful()) {
                $body = $response->json();
                $apiError = trim(($body['error'] ?? '') . ' ' . ($body['error_description'] ?? '')) ?: $response->body();
                if (is_array($body) && isset($body['description'])) {
                    $apiError = trim(($body['message'] ?? '') . ' - ' . ($body['description'] ?? ''));
                }
                if (is_array($body) && (isset($body['code']) && (int) $body['code'] === 60)) {
                    $apiError = 'Resource not found. URL appelée: ' . $tokenUrl;
                }
                // Identifiants refusés (invalid_client) : souvent credentials Sonatel utilisés sur api.orange.com
                $isInvalidClient = $response->status() === 401 && (isset($body['error']) && $body['error'] === 'invalid_client');
                if ($isInvalidClient) {
                    cache()->forget($cache_key);
                    $apiError = 'Identifiants refusés (invalid_client). Vérifiez client_id et client_secret (admin Orange Money). URL: ' . $tokenUrl;
                }
                Log::error('Orange Money: Erreur lors de l\'obtention du token', [
                    'status_code' => $response->status(),
                    'url_called' => $tokenUrl,
                    'response' => $response->body(),
                    'api_error' => $apiError,
                ]);
                throw new Exception('Impossible d\'obtenir le token d\'accès. ' . $apiError);
            }

            $token_data = $response->json();
            
            if (!isset($token_data['access_token'])) {
                throw new Exception('Token d\'accès non reçu');
            }

            $access_token = $token_data['access_token'];
            $expires_in = $token_data['expires_in'] ?? 300; // Par défaut 5 minutes

            // Mettre en cache le token (expire 1 minute avant la date d'expiration réelle)
            cache()->put($cache_key, [
                'token' => $access_token,
                'expires_at' => now()->timestamp + ($expires_in - 60)
            ], now()->addSeconds($expires_in - 60));

            Log::info('Orange Money: Token d\'accès obtenu avec succès');
            
            return $access_token;

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur getAccessToken', [
                'error' => $e->getMessage()
            ]);
            throw $e;
        }
    }

    /**
     * Initialise le processus de paiement Orange Money
     * Utilise uniquement le QR Code selon la documentation officielle
     */
    public function initialize(Request $request)
    {
        try {
            // Validation des données d'entrée
            $validator = Validator::make($request->all(), [
                'payment_id' => 'required|uuid'
            ]);

            if ($validator->fails()) {
                Log::error('Orange Money: Validation échouée', [
                    'errors' => $validator->errors(),
                    'request_data' => $request->all()
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400, 
                    null, 
                    $this->error_processor($validator)
                ), 400);
            }

            // Récupération des données de paiement
            $payment_data = $this->payment::where([
                'id' => $request['payment_id'],
                'is_paid' => 0
            ])->first();

            if (!isset($payment_data)) {
                Log::warning('Orange Money: Données de paiement non trouvées', [
                    'payment_id' => $request['payment_id']
                ]);
                
                return response()->json($this->response_formatter(GATEWAYS_DEFAULT_204), 200);
            }

            // Extraction des informations métier
            $business_name = $this->extractBusinessName($payment_data);
            $payer_info = json_decode($payment_data->payer_information, true);

            // Validation de la devise supportée (XOF uniquement pour Orange Money)
            $supported_currencies = ['XOF'];
            $currency = $payment_data->currency_code ?? 'XOF';
            
            if (!in_array($currency, $supported_currencies)) {
                Log::error('Orange Money: Devise non supportée', [
                    'payment_id' => $payment_data->id,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Devise non supportée par Orange Money: ' . $currency
                ), 400);
            }

            // Calcul du montant
            $raw_amount = (float) $payment_data->payment_amount;
            $amount = $this->normalizeOrangeMoneyAmount($raw_amount);
            
            // Validation du montant minimum
            if ($amount < 1) {
                Log::error('Orange Money: Montant insuffisant', [
                    'payment_id' => $payment_data->id,
                    'raw_amount' => $raw_amount,
                    'normalized_amount' => $amount
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Le montant minimum est de 1 XOF'
                ), 400);
            }

            // Le merchant_code doit être fourni dans le contrat Sonatel et configuré en base/config
            // Il n'existe AUCUN endpoint Sonatel pour récupérer le merchant code dynamiquement
            $merchant_code = $this->merchant_code;
            if (empty($merchant_code)) {
                Log::error('Orange Money: Merchant code non configuré (doit être fourni par Sonatel dans le contrat)');
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Merchant code Orange Money non configuré. Veuillez le configurer dans les paramètres (fourni par Sonatel dans votre contrat).'
                ), 400);
            }

            // Génération d'une référence unique Sonatel-safe (courte, sans caractères spéciaux)
            // Format recommandé: préfixe + UUID ou timestamp + random pour éviter collisions
            $reference = 'PMT' . strtoupper(str_replace('-', '', Str::uuid()->toString()));

            // Préparation de la requête QR Code selon la documentation
            $qr_request = [
                'code' => $merchant_code, // Code marchand (6 chiffres)
                'name' => $business_name, // Nom du marchand
                'amount' => [
                    'value' => $amount,
                    'unit' => 'XOF'
                ],
                'callbackSuccessUrl' => route('orange_money.callback', ['payment_id' => $payment_data->id, 'status' => 'success']),
                'callbackCancelUrl' => route('orange_money.callback', ['payment_id' => $payment_data->id, 'status' => 'cancel']),
                'validity' => 900, // 15 minutes en secondes (max 86400 selon doc)
                'metadata' => [
                    'payment_id' => $payment_data->id,
                    'reference' => $reference
                ]
            ];

            Log::info('Orange Money: Création de paiement', [
                'payment_id' => $payment_data->id,
                'amount' => $amount,
                'merchant_code' => substr($merchant_code, 0, 3) . '...'
            ]);

            // Appel API Sonatel createPaymentQRCode pour obtenir les deepLinks officiels (MAXIT, OM)
            $apiResult = $this->createPaymentQRCodeViaApi($qr_request, $reference, $payment_data->id);

            // Si l'API échoue, on retourne une erreur (pas de fallback manuel - conforme Sonatel)
            if (empty($apiResult['success']) || empty($apiResult['deepLinks'])) {
                Log::error('Orange Money: Échec de createPaymentQRCode - pas de fallback autorisé', [
                    'payment_id' => $payment_data->id,
                    'api_error' => $apiResult['error'] ?? 'Aucun deepLink retourné',
                ]);

                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Impossible de créer le paiement Orange Money. ' . ($apiResult['error'] ?? 'Service temporairement indisponible')
                ), 400);
            }

            // Mise à jour du paiement avec la référence/qrId
            $transaction_id = $apiResult['qrId'] ?? $reference;
            $this->payment::where(['id' => $payment_data->id])->update([
                'transaction_id' => $transaction_id,
                'payment_method' => 'orange_money',
            ]);

            // Stocker les données en session pour le callback
            session([
                'orange_money_reference' => $reference,
                'orange_money_payment_id' => $payment_data->id,
                'orange_money_amount' => $qr_request['amount']['value'],
                'orange_money_merchant_code' => $merchant_code,
                'orange_money_business_name' => $qr_request['name'],
            ]);

            // Liens retournés par l'API Sonatel eWallet v4.
            // Selon le comportement observé, le shortLink HTTPS (SuGu) est souvent le plus fiable côté Max It.
            $shortLink = $apiResult['shortLink'] ?? null;
            $maxitLink = $apiResult['deepLinks']['MAXIT'] ?? null;
            $omLink = $apiResult['deepLinks']['OM'] ?? null;
            $genericDeepLink = $apiResult['deepLink'] ?? null;

            // Lien "principal" côté client : shortLink > MAXIT > OM > deepLink générique
            $primaryLink = $shortLink ?? $maxitLink ?? $omLink ?? $genericDeepLink;

            // Pour la page de choix, on propose Max It (shortLink en priorité) et OM.
            $maxitForWeb = $shortLink ?? $maxitLink ?? $genericDeepLink;

            Log::info('Orange Money: Paiement initialisé avec succès', [
                'payment_id' => $payment_data->id,
                'qrId' => $transaction_id,
                'has_maxit_deeplink' => !empty($maxitLink) || !empty($shortLink),
                'has_om_deeplink' => !empty($omLink),
                'maxit_deeplink_sample' => $maxitForWeb ? substr($maxitForWeb, 0, 80) . (strlen($maxitForWeb) > 80 ? '...' : '') : null,
                'om_deeplink_sample' => $omLink ? substr($omLink, 0, 80) . (strlen($omLink) > 80 ? '...' : '') : null,
                'shortlink_sample' => !empty($shortLink) ? substr($shortLink, 0, 100) . (strlen($shortLink) > 100 ? '...' : '') : null,
            ]);

            // 1) Appels API / mobile (Flutter, etc.) : renvoyer les 2 liens + une URL web "open-app" (page de choix)
            if ($request->expectsJson() || $request->wantsJson()) {
                $openAppParams = [];
                if (!empty($maxitForWeb)) {
                    // base64url (URL-safe) pour éviter que '+' devienne un espace dans la query string
                    $openAppParams['maxit'] = rtrim(strtr(base64_encode($maxitForWeb), '+/', '-_'), '=');
                }
                if (!empty($omLink)) {
                    $openAppParams['om'] = rtrim(strtr(base64_encode($omLink), '+/', '-_'), '=');
                }
                $openAppUrl = !empty($openAppParams) ? route('orange_money.open_app', $openAppParams) : null;

                return response()->json([
                    'success' => true,
                    'payment_id' => $payment_data->id,
                    'reference' => $reference,
                    'qr_id' => $transaction_id,
                    'qr_code' => $apiResult['qrCode'] ?? null,
                    'deep_links' => [
                        'maxit' => $maxitLink,
                        'orange_money' => $omLink,
                    ],
                    'deep_link' => $primaryLink,
                    'short_link' => $shortLink,
                    'open_app_url' => $openAppUrl,
                    'expires_in' => $apiResult['validity'] ?? 900,
                    'metadata' => $apiResult['metadata'] ?? null,
                ], 200);
            }

            // 2) Navigation navigateur : rediriger vers la page de choix (open-app)
            if (!empty($maxitForWeb) || !empty($omLink)) {
                $params = [];
                if (!empty($maxitForWeb)) {
                    $params['maxit'] = rtrim(strtr(base64_encode($maxitForWeb), '+/', '-_'), '=');
                }
                if (!empty($omLink)) {
                    $params['om'] = rtrim(strtr(base64_encode($omLink), '+/', '-_'), '=');
                }
                return redirect()->route('orange_money.open_app', $params);
            }

            // Fallback : aucun lien exploitable
            return response()->json([
                'success' => true,
                'payment_id' => $payment_data->id,
                'reference' => $reference,
                'qr_id' => $transaction_id,
                'qr_code' => $apiResult['qrCode'] ?? null,
                'deep_links' => [
                    'maxit' => $maxitLink,
                    'orange_money' => $omLink,
                ],
                'deep_link' => $primaryLink,
                'short_link' => $shortLink,
                'open_app_url' => null,
                'expires_in' => $apiResult['validity'] ?? 900,
                'metadata' => $apiResult['metadata'] ?? null,
            ], 200);

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors de l\'initialisation', [
                'error' => $e->getMessage(),
                'payment_id' => $request['payment_id'] ?? null,
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de l\'initialisation du paiement: ' . $e->getMessage()
            ], 500);
        }
    }

    /** Package Android officiel Max It Sénégal (Google Play). */
    private const MAXIT_ANDROID_PACKAGE = 'com.orange.myorange.osn';

    /**
     * Page intermédiaire avec liens cliquables pour ouvrir Max It ou Orange Money.
     * Max It : utilise le shortLink Sonatel (HTTPS) en priorité — il redirige correctement vers l'app
     * avec le contexte paiement, évitant "Page introuvable". Le deep link sameaosnapp:// converti en
     * Intent peut corrompre l'URL et faire ouvrir Max It sans les paramètres requis.
     */
    public function openApp(Request $request)
    {
        $maxitUrl = null;
        $omUrl = null;

        // 1) Liens passés dans l'URL (base64) : aucun problème de session/cache/multi-serveur
        $maxitEnc = $request->query('maxit');
        $omEnc = $request->query('om');
        if (!empty($maxitEnc)) {
            // Accepter base64url + corriger le cas où '+' aurait été converti en espace
            $norm = str_replace(' ', '+', $maxitEnc);
            $norm = strtr($norm, '-_', '+/');
            $padLen = 4 - (strlen($norm) % 4);
            if ($padLen < 4) {
                $norm .= str_repeat('=', $padLen);
            }
            $decoded = base64_decode($norm, true);
            if ($decoded !== false && preg_match('/^https?:\/\//i', $decoded)) {
                $maxitUrl = $decoded;
            }
        }
        if (!empty($omEnc)) {
            $norm = str_replace(' ', '+', $omEnc);
            $norm = strtr($norm, '-_', '+/');
            $padLen = 4 - (strlen($norm) % 4);
            if ($padLen < 4) {
                $norm .= str_repeat('=', $padLen);
            }
            $decoded = base64_decode($norm, true);
            if ($decoded !== false && preg_match('/^https?:\/\//i', $decoded)) {
                $omUrl = $decoded;
            }
        }

        // 2) Fallback token (cache) pour compatibilité
        if (empty($maxitUrl) && empty($omUrl)) {
            $token = $request->query('token');
            if (!empty($token)) {
                $cached = Cache::get('orange_money_open_app_' . $token);
                if (is_array($cached)) {
                    $maxitUrl = $cached['maxit'] ?? null;
                    $omUrl = $cached['om'] ?? null;
                    Cache::forget('orange_money_open_app_' . $token);
                }
            }
        }

        // 3) Fallback session
        if (empty($maxitUrl) && empty($omUrl)) {
            $maxitUrl = session('orange_money_open_app_maxit');
            $omUrl = session('orange_money_open_app_om');
            session()->forget(['orange_money_open_app_maxit', 'orange_money_open_app_om']);
        }

        if (empty($maxitUrl) && empty($omUrl)) {
            return redirect()->route('orange_money.callback', ['payment_id' => session('orange_money_payment_id'), 'status' => 'cancel'])
                ->with('error', 'Session expirée. Veuillez relancer le paiement.');
        }

        return view('payment-views.orange-money-open-app', [
            'maxit_url' => $maxitUrl,
            'om_url' => $omUrl,
        ]);
    }

    /**
     * Convertit un deep link Max It (sameaosnapp://...) en Intent URL Android.
     * La WebView/Chrome transmet l'intent au système qui ouvre l'app au lieu d'afficher ERR_UNKNOWN_URL_SCHEME.
     * IMPORTANT: La query string (qrId, reference, etc.) doit être conservée pour que Max It affiche
     * la page de paiement préremplie au lieu de "Page introuvable".
     */
    private function maxitDeepLinkToAndroidIntent(string $deepLink): string
    {
        $parsed = parse_url($deepLink);
        $path = trim(($parsed['host'] ?? '') . ($parsed['path'] ?? ''), '/');
        if ($path === '') {
            return $deepLink;
        }
        // Conserver la query string pour transmettre le contexte paiement (qrId, reference, etc.) à Max It
        if (!empty($parsed['query'])) {
            $path .= '?' . $parsed['query'];
        }
        $fallback = 'https://play.google.com/store/apps/details?id=' . self::MAXIT_ANDROID_PACKAGE;
        return 'intent://' . $path . '#Intent;scheme=sameaosnapp;package=' . self::MAXIT_ANDROID_PACKAGE
            . ';S.browser_fallback_url=' . rawurlencode($fallback) . ';end';
    }

    /**
     * Appelle l'API Sonatel eWallet v4 qrcode (aligné projet de référence).
     */
    private function createPaymentQRCodeViaApi(array $qr_request, string $reference, string $payment_id): array
    {
        try {
            $access_token = $this->getAccessToken();
            $merchant_code = $qr_request['code']; // string ou int selon API
            $name = $this->config_values['merchant_name'] ?? $qr_request['name'] ?? 'SIAME';
            $amount_value = (int) $qr_request['amount']['value'];
            $success_url = route('orange_money.callback', ['payment_id' => $payment_id, 'status' => 'success']);
            $cancel_url = route('orange_money.callback', ['payment_id' => $payment_id, 'status' => 'cancel']);
            // metadata : 'order' comme projet de référence (orderId) + payment_id pour notre traitement
            $metadata = $qr_request['metadata'] ?? ['payment_id' => $payment_id, 'reference' => $reference];
            $metadata['order'] = $payment_id;

            // Payload conforme à la doc Sonatel eWallet v4 (/api/eWallet/v4/qrcode)
            $body = [
                'amount' => ['unit' => 'XOF', 'value' => $amount_value],
                'callbackSuccessUrl' => $success_url,
                'callbackCancelUrl' => $cancel_url,
                'code' => $merchant_code,
                'metadata' => $metadata,
                'name' => $name,
                'validity' => 15,
            ];

            $full_url = rtrim($this->base_url, '/') . '/' . ltrim(self::OM_QRCODE_ENDPOINT, '/');

            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])
                ->timeout(30)
                ->post($full_url, $body);

            if (!$response->successful()) {
                Log::error('Orange Money: createPaymentQRCode API error', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                    'payment_id' => $payment_id,
                ]);
                return [
                    'success' => false,
                    'error' => $this->parseOrangeMoneyError($response->json() ?? []) ?: $response->body(),
                ];
            }

            $data = $response->json();
            $deepLinks = $data['deepLinks'] ?? [];
            // Clés possibles selon doc @sonatel-os/juf : MAXIT, OM (insensible à la casse)
            $deepLinksNormalized = array_change_key_case(is_array($deepLinks) ? $deepLinks : [], CASE_UPPER);
            $maxit = $deepLinksNormalized['MAXIT'] ?? $data['deepLink'] ?? null;
            $om = $deepLinksNormalized['OM'] ?? $data['deepLink'] ?? null;

            if (!$maxit && !$om) {
                Log::warning('Orange Money: createPaymentQRCode sans deepLinks', [
                    'response_keys' => array_keys($data),
                    'payment_id' => $payment_id,
                ]);
            }

            return [
                'success' => true,
                'qrId' => $data['qrId'] ?? null,
                'deepLink' => $data['deepLink'] ?? $maxit ?? $om,
                'deepLinks' => [
                    'MAXIT' => $maxit,
                    'OM' => $om,
                ],
                'qrCode' => $data['qrCode'] ?? null,
                'validity' => $data['validity'] ?? null,
                'shortLink' => $data['shortLink'] ?? null,
            ];
        } catch (Exception $e) {
            Log::error('Orange Money: createPaymentQRCodeViaApi exception', [
                'error' => $e->getMessage(),
                'payment_id' => $payment_id,
                'trace' => $e->getTraceAsString(),
            ]);
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Callback HTTP après redirection Sonatel (callbackSuccessUrl / callbackCancelUrl).
     * Aligné avec le flux du projet de référence : Sonatel redirige ici avec payment_id (équivalent orderId) et status.
     * Le webhook reste la source de vérité pour marquer is_paid = 1.
     */
    public function callback(Request $request)
    {
        try {
            $payment_id = $request->get('payment_id');
            $status = $request->get('status', 'success');

            Log::info('Orange Money: Callback reçu', [
                'payment_id' => $payment_id,
                'status' => $status,
                'all_params' => $request->all()
            ]);

            if (empty($payment_id)) {
                Log::error('Orange Money: Callback sans payment_id');
                return response()->json(['success' => false, 'message' => 'Payment ID manquant'], 400);
            }

            // Récupération des données de paiement
            $payment_data = $this->payment::where(['id' => $payment_id])->first();
            
            if (!isset($payment_data)) {
                Log::error('Orange Money: Données de paiement non trouvées pour le callback', [
                    'payment_id' => $payment_id
                ]);
                return response()->json(['success' => false, 'message' => 'Paiement non trouvé'], 404);
            }

            // Si déjà payé via webhook (source de vérité), retourner succès immédiatement
            if ($payment_data->is_paid == 1) {
                Log::info('Orange Money: Paiement déjà confirmé via webhook (source de vérité)', [
                    'payment_id' => $payment_id
                ]);
                return $this->payment_response($payment_data, 'success');
            }

            if ($status === 'success') {
                // Tentative de vérification via API (best-effort, peut échouer si latence)
                // ⚠️ Le webhook est la source de vérité finale, pas ce callback HTTP
                $reference = $payment_data->transaction_id;
                if ($reference) {
                    $verification_response = $this->verifyPaymentStatus($reference);
                    
                    // Si vérification réussie ET montant validé, on peut marquer comme payé
                    // Sinon, on attend le webhook (source de vérité)
                    if ($verification_response['success'] && isset($verification_response['transaction'])) {
                        $transaction = $verification_response['transaction'];
                        
                        // Validation du montant avant de marquer comme payé (anti-fraude)
                        if ($this->validatePaymentAmount($payment_data, $transaction)) {
                            // Mise à jour du statut de paiement
                            $this->payment::where(['id' => $payment_id])->update([
                                'payment_method' => 'orange_money',
                                'is_paid' => 1,
                                'updated_at' => now()
                            ]);

                            Log::info('Orange Money: Paiement confirmé via callback (en attente confirmation webhook)', [
                                'payment_id' => $payment_id,
                                'reference' => $reference
                            ]);

                            // Traitement post-paiement
                            $this->handleSuccessfulPayment($payment_data);

                            return $this->payment_response($payment_data, 'success');
                        } else {
                            Log::warning('Orange Money: Montant payé ne correspond pas (attente webhook)', [
                                'payment_id' => $payment_id,
                                'expected' => $payment_data->payment_amount,
                                'received' => $transaction['amount']['value'] ?? 'N/A'
                            ]);
                        }
                    } else {
                        // Vérification API échouée ou transactions[] vide → attendre webhook
                        Log::info('Orange Money: Vérification API non concluante, attente webhook (source de vérité)', [
                            'payment_id' => $payment_id,
                            'reference' => $reference,
                            'verification_error' => $verification_response['error'] ?? 'Transactions array vide'
                        ]);
                    }
                }
                
                // Succès mais vérification API non concluante (webhook en attente). On redirige quand même
                // vers l'app / page succès pour ne pas bloquer l'utilisateur (deep link ou web).
                // Le webhook reste la source de vérité pour is_paid ; l'écran commande affichera "en cours" puis se mettra à jour.
                return $this->payment_response($payment_data, 'success');
            }

            // Paiement annulé ou échoué (cancel = annulation, autre = échec) — deep link siame:// si app
            $redirect_flag = ($status === 'cancel') ? 'cancel' : 'fail';
            Log::info('Orange Money: Paiement annulé ou échoué', [
                'payment_id' => $payment_id,
                'status' => $status
            ]);

            $this->payment::where(['id' => $payment_id])->update([
                'payment_method' => 'orange_money',
                'is_paid' => 0,
                'updated_at' => now()
            ]);

            $payment_data = $this->payment::where(['id' => $payment_id])->first();
            
            // Exécution du hook d'échec si disponible
            if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                try {
                    call_user_func($payment_data->failure_hook, $payment_data);
                } catch (Exception $hook_error) {
                    Log::error('Orange Money: Erreur lors de l\'exécution du hook d\'échec', [
                        'error' => $hook_error->getMessage(),
                        'payment_id' => $payment_id
                    ]);
                }
            }

            return $this->payment_response($payment_data, $redirect_flag);

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors du callback', [
                'error' => $e->getMessage(),
                'payment_id' => $request->get('payment_id'),
                'trace' => $e->getTraceAsString()
            ]);

            $payment_id = $request->get('payment_id');
            if ($payment_id) {
                $payment_data = $this->payment::where(['id' => $payment_id])->first();
                if ($payment_data) {
                    if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                        try {
                            call_user_func($payment_data->failure_hook, $payment_data);
                        } catch (Exception $hook_error) {
                            Log::error('Orange Money: Erreur lors de l\'exécution du hook d\'échec', [
                                'error' => $hook_error->getMessage(),
                                'payment_id' => $payment_id
                            ]);
                        }
                    }
                    
                    return $this->payment_response($payment_data, 'fail');
                }
            }

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors du traitement du callback: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Webhook Orange Money pour les notifications de paiement (SOURCE DE VÉRITÉ FINALE).
     * Selon la documentation, les callbacks sont envoyés en POST.
     * 
     * ⚠️ Si contrat Sonatel fournit une signature webhook (header X-Signature),
     * décommentez et configurez la vérification ci-dessous pour sécuriser le webhook.
     */
    public function webhook(Request $request)
    {
        try {
            $payload = $request->all();
            
            Log::info('Orange Money Webhook Received: ' . json_encode($payload));
            
            // Vérification de signature webhook (si fournie par Sonatel selon contrat)
            // Décommentez si votre contrat inclut une signature HMAC et définissez $webhook_secret
            /*
            $signature = $request->header('X-Signature');
            $webhook_secret = 'votre_secret_webhook';
            if ($signature && $webhook_secret) {
                $expected_signature = hash_hmac('sha256', json_encode($payload), $webhook_secret);
                if (!hash_equals($expected_signature, $signature)) {
                    return response()->json(['status' => 'invalid_signature'], 401);
                }
            }
            */
            
            // Traitement du webhook selon la documentation
            // Format du callback selon doc :
            // {
            //   "type": "MERCHANT_PAYMENT",
            //   "status": "SUCCESS",
            //   "reference": "...",
            //   "transactionId": "...",
            //   ...
            // }
            
            if (isset($payload['type']) && $payload['type'] === 'MERCHANT_PAYMENT') {
                $this->processWebhookPayment($payload);
            }

            return response()->json(['status' => 'success'], 200);

        } catch (Exception $e) {
            Log::error('Orange Money Webhook Error: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json(['status' => 'error'], 500);
        }
    }

    /**
     * Traitement du webhook de paiement (SOURCE DE VÉRITÉ FINALE).
     * 
     * Le webhook Sonatel est la seule garantie fiable pour marquer is_paid = 1.
     * Orange peut renvoyer le webhook plusieurs fois → idempotence requise.
     */
    private function processWebhookPayment($payload)
    {
        try {
            $reference = $payload['reference'] ?? null;
            $status = $payload['status'] ?? null;
            $transaction_id = $payload['transactionId'] ?? null;
            $amount = $payload['amount']['value'] ?? null;

            if (!$reference) {
                Log::warning('Orange Money: Webhook sans référence');
                return;
            }

            // Extraction de l'ID de paiement depuis metadata (plus fiable que parsing référence)
            // La référence a changé de format: PMT + UUID, donc on utilise metadata.payment_id
            $payment_id = $payload['metadata']['payment_id'] ?? null;
            
            // Fallback: chercher par transaction_id si metadata non disponible
            if (!$payment_id && $transaction_id) {
                $payment_data = $this->payment::where('transaction_id', $transaction_id)->first();
                if ($payment_data) {
                    $payment_id = $payment_data->id;
                }
            }
            
            // Dernier fallback: chercher par référence (si ancien format encore utilisé)
            if (!$payment_id && preg_match('/PAYMENT_([a-f0-9-]+)_/', $reference, $matches)) {
                $payment_id = $matches[1];
            }

            if (!$payment_id) {
                Log::warning('Orange Money: Impossible d\'extraire payment_id du webhook', [
                    'reference' => $reference,
                    'transaction_id' => $transaction_id,
                    'metadata' => $payload['metadata'] ?? null
                ]);
                return;
            }

            $payment_data = $this->payment::find($payment_id);
            
            if (!$payment_data) {
                Log::warning('Orange Money: Paiement non trouvé pour le webhook', [
                    'payment_id' => $payment_id,
                    'reference' => $reference
                ]);
                return;
            }

            // IDEMPOTENCE: Si déjà payé, ne pas retraiter (Orange peut renvoyer le webhook)
            if ($payment_data->is_paid == 1) {
                Log::info('Orange Money: Webhook déjà traité (idempotence)', [
                    'payment_id' => $payment_id,
                    'reference' => $reference
                ]);
                return;
            }

            if ($status === 'SUCCESS' || $status === 'success') {
                // Validation du montant avant de marquer comme payé (anti-fraude)
                $transaction_data = [
                    'amount' => [
                        'value' => $amount ?? $payment_data->payment_amount
                    ]
                ];
                
                if (!$this->validatePaymentAmount($payment_data, $transaction_data)) {
                    Log::error('Orange Money: Montant webhook ne correspond pas (fraude possible)', [
                        'payment_id' => $payment_id,
                        'expected' => $payment_data->payment_amount,
                        'received' => $amount
                    ]);
                    return;
                }

                // Mise à jour du statut de paiement (source de vérité)
                $this->payment::where(['id' => $payment_id])->update([
                    'payment_method' => 'orange_money',
                    'is_paid' => 1,
                    'transaction_id' => $transaction_id ?? $reference,
                    'updated_at' => now()
                ]);

                $this->handleSuccessfulPayment($payment_data);

                Log::info('Orange Money: Paiement confirmé via webhook (source de vérité)', [
                    'payment_id' => $payment_id,
                    'transaction_id' => $transaction_id,
                    'reference' => $reference
                ]);
            } else {
                Log::info('Orange Money: Webhook reçu avec statut non-success', [
                    'payment_id' => $payment_id,
                    'status' => $status,
                    'reference' => $reference
                ]);
            }

        } catch (Exception $e) {
            Log::error('Orange Money Webhook Processing Error: ' . $e->getMessage());
        }
    }

    /**
     * Vérifie le statut d'un paiement Orange Money
     * GET /api/eWallet/v1/transactions/{transactionId}/status
     */
    public function verifyPaymentStatus($reference)
    {
        try {
            // D'abord, chercher la transaction par référence
            // GET /api/eWallet/v1/transactions?reference=...
            $access_token = $this->getAccessToken();
            
            $endpoint = '/api/eWallet/v1/transactions';
            $full_url = $this->base_url . $endpoint;

            $headers = [
                'Authorization' => 'Bearer ' . $access_token,
                'Accept' => 'application/json'
            ];

            $response = Http::withHeaders($headers)
                ->timeout(30)
                ->get($full_url, [
                    'reference' => $reference,
                    'size' => 1
                ]);

            if ($response->successful()) {
                $transactions = $response->json();
                
                if (is_array($transactions) && count($transactions) > 0) {
                    $transaction = $transactions[0];
                    
                    // Vérification selon la documentation
                    if (isset($transaction['status']) && 
                        ($transaction['status'] === 'SUCCESS' || $transaction['status'] === 'success')) {
                        return [
                            'success' => true,
                            'transaction' => $transaction
                        ];
                    } else {
                        return [
                            'success' => false,
                            'error' => 'Paiement échoué ou en attente. Statut: ' . ($transaction['status'] ?? 'inconnu')
                        ];
                    }
                } else {
                    // Transactions[] vide ne signifie PAS forcément échec
                    // Peut être dû à latence API ou endpoint non activé selon contrat
                    // On retourne success=false mais avec un message explicite pour attendre webhook
                    return [
                        'success' => false,
                        'error' => 'Transaction non trouvée dans l\'API (peut être en latence). Attente webhook (source de vérité).',
                        'wait_for_webhook' => true
                    ];
                }
            } else {
                $error_data = $response->json();
                $error_message = $this->parseOrangeMoneyError($error_data);
                
                return [
                    'success' => false,
                    'error' => $error_message
                ];
            }

        } catch (Exception $e) {
            Log::error('Orange Money Verify Payment Status Error: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Erreur lors de la vérification du paiement'
            ];
        }
    }

    /**
     * Parse les erreurs Orange Money selon le format de la documentation
     */
    private function parseOrangeMoneyError($error_data)
    {
        if (is_array($error_data)) {
            // Format d'erreur selon la doc : array avec code, detail, etc.
            if (isset($error_data[0]) && is_array($error_data[0])) {
                $error = $error_data[0];
                $code = $error['code'] ?? 'unknown';
                $detail = $error['detail'] ?? 'Erreur inconnue';
                return "Code {$code}: {$detail}";
            } elseif (isset($error_data['code']) && isset($error_data['detail'])) {
                return "Code {$error_data['code']}: {$error_data['detail']}";
            } elseif (isset($error_data['detail'])) {
                return $error_data['detail'];
            }
        }
        
        return 'Erreur inconnue de l\'API Orange Money';
    }

    /**
     * Valide le montant du paiement
     */
    private function validatePaymentAmount($payment_data, $transaction_data)
    {
        $expected_amount = (float) $payment_data->payment_amount;
        
        // Le montant dans la transaction est dans amount.value
        $received_amount = null;
        if (isset($transaction_data['amount']) && is_array($transaction_data['amount'])) {
            $received_amount = (float) ($transaction_data['amount']['value'] ?? null);
        } elseif (isset($transaction_data['amount'])) {
            $received_amount = (float) $transaction_data['amount'];
        }

        if ($received_amount === null) {
            return true; // Si le montant n'est pas retourné, on fait confiance
        }

        // Tolérance de 1 XOF pour les arrondis
        return abs($expected_amount - $received_amount) <= 1;
    }

    /**
     * Normalise le montant pour Orange Money (XOF uniquement, entier)
     */
    private function normalizeOrangeMoneyAmount(float $amount): int
    {
        return max(1, (int) floor($amount));
    }

    /**
     * Gère le paiement réussi
     */
    private function handleSuccessfulPayment($payment_data)
    {
        try {
            // Mise à jour du statut de paiement
            $this->payment::where(['id' => $payment_data->id])->update([
                'is_paid' => 1,
                'updated_at' => now()
            ]);

        } catch (Exception $e) {
            Log::error('Orange Money Handle Successful Payment Error: ' . $e->getMessage());
        }
    }

    /**
     * Extrait le nom de l'entreprise depuis les données de paiement
     */
    private function extractBusinessName($payment_data)
    {
        $business_name = $this->config_values['merchant_name'] ?? 'SIAME';
        
        if (isset($payment_data->business_id)) {
            // Récupération du nom de l'entreprise depuis la base de données
            $business = DB::table('business_settings')
                ->where('key', 'business_name')
                ->first();
            
            if ($business) {
                $business_name = $business->value;
            }
        }
        
        return $business_name;


    }
}
























