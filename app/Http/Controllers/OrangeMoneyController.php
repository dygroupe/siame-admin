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

    private $config_values;
    private PaymentRequest $payment;
    private $user;
    private $base_url;
    private $access_token;
    private $client_id;
    private $client_secret;
    private $merchant_code;
    private $api_key;

    public function __construct(PaymentRequest $payment, User $user)
    {
        try {
            $config = $this->payment_config('orange_money', 'payment_config');
            
            if (!is_null($config) && $config->mode == 'live') {
                $this->config_values = json_decode($config->live_values, true);
                $this->base_url = 'https://api.orange-sonatel.com';
            } elseif (!is_null($config) && $config->mode == 'test') {
                $this->config_values = json_decode($config->test_values, true);
                $this->base_url = 'https://api.sandbox.orange-sonatel.com';
            } else {
                // Configuration par défaut si pas de config en base
                $this->config_values = [
                    'client_id' => config('orange_money.client_id', ''),
                    'client_secret' => config('orange_money.client_secret', ''),
                    'merchant_code' => config('orange_money.merchant_code', ''),
                    'api_key' => config('orange_money.api_key', ''),
                    'merchant_name' => config('orange_money.merchant_name', 'SIAME')
                ];
                $this->base_url = config('orange_money.base_url', 'https://api.sandbox.orange-sonatel.com');
            }

            // Extraction des valeurs de configuration
            $this->client_id = $this->config_values['client_id'] ?? '';
            $this->client_secret = $this->config_values['client_secret'] ?? '';
            $this->merchant_code = $this->config_values['merchant_code'] ?? '';
            $this->api_key = $this->config_values['api_key'] ?? '';

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
                'client_id' => config('orange_money.client_id', ''),
                'client_secret' => config('orange_money.client_secret', ''),
                'merchant_code' => config('orange_money.merchant_code', ''),
                'api_key' => config('orange_money.api_key', ''),
                'merchant_name' => config('orange_money.merchant_name', 'SIAME')
            ];
            $this->base_url = config('orange_money.base_url', 'https://api.sandbox.orange-sonatel.com');
        }

        $this->payment = $payment;
        $this->user = $user;

        // Log de la configuration pour débogage
        Log::info('Orange Money: Configuration initialisée', [
            'mode' => $this->config_values['mode'] ?? 'test',
            'base_url' => $this->base_url,
            'merchant_code' => substr($this->merchant_code, 0, 3) . '...'
        ]);
    }

    /**
     * Obtient un access token via OAuth 2.0
     * Selon la documentation : POST /oauth/v1/token
     */
    private function getAccessToken()
    {
        try {
            // Si on a déjà un token valide en cache, le réutiliser
            $cache_key = 'orange_money_access_token_' . md5($this->client_id);
            $cached_token = cache()->get($cache_key);
            
            if ($cached_token && isset($cached_token['token']) && isset($cached_token['expires_at'])) {
                if (now()->timestamp < $cached_token['expires_at']) {
                    return $cached_token['token'];
                }
            }

            // Obtenir un nouveau token
            $endpoint = '/oauth/v1/token';
            $full_url = $this->base_url . $endpoint;

            $response = Http::asForm()
                ->timeout(30)
                ->post($full_url, [
                    'client_id' => $this->client_id,
                    'client_secret' => $this->client_secret,
                    'grant_type' => 'client_credentials'
                ]);

            if (!$response->successful()) {
                Log::error('Orange Money: Erreur lors de l\'obtention du token', [
                    'status_code' => $response->status(),
                    'response' => $response->body()
                ]);
                throw new Exception('Impossible d\'obtenir le token d\'accès');
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

            // Le merchant_code peut être obtenu via l'API ou configuré manuellement
            // Si non fourni, on essaie de le récupérer via l'API ou on utilise une valeur par défaut
            $merchant_code = $this->merchant_code;
            if (empty($merchant_code)) {
                // Essayer de récupérer le merchant code via l'API ou utiliser une valeur par défaut
                // Note: Le merchant code devrait être fourni dans votre contrat Orange Money
                Log::warning('Orange Money: Code marchand non configuré, tentative de récupération via API');
                $merchant_code = $this->getMerchantCodeFromAPI();
                
                if (empty($merchant_code)) {
                    Log::error('Orange Money: Code marchand manquant - Veuillez le configurer dans les paramètres');
                    return response()->json($this->response_formatter(
                        GATEWAYS_DEFAULT_400,
                        null,
                        'Code marchand non configuré. Veuillez le configurer dans les paramètres Orange Money.'
                    ), 400);
                }
            }

            // Génération d'une référence unique
            $reference = 'PAYMENT_' . $payment_data->id . '_' . time();

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

            // Détection des applications installées (Max It et/ou Orange Money)
            $appDetection = $this->detectOrangeMoneyApps($request);

            Log::info('Orange Money: Détection des applications', [
                'payment_id' => $payment_data->id,
                'has_max_it' => $appDetection['has_max_it'],
                'has_orange_money' => $appDetection['has_orange_money'],
                'preferred_app' => $appDetection['preferred_app'],
                'user_agent' => $request->header('User-Agent', ''),
                'platform' => $request->header('X-Platform', 'web')
            ]);

            // Vérifier qu'au moins une application est détectée
            if (!$appDetection['has_max_it'] && !$appDetection['has_orange_money']) {
                Log::warning('Orange Money: Aucune application détectée', [
                    'payment_id' => $payment_data->id
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Aucune application de paiement détectée. Veuillez installer Max It ou Orange Money pour effectuer le paiement.'
                ), 400);
            }

            // Génération des DeepLinks pour les applications détectées
            return $this->generatePaymentDeepLinks($qr_request, $payment_data, $reference, $merchant_code, $appDetection);

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

    /**
     * Récupère le code marchand via l'API Orange Money
     * Si disponible dans les informations du compte
     */
    private function getMerchantCodeFromAPI()
    {
        try {
            // Note: Selon la documentation, il n'y a pas d'endpoint direct pour récupérer le merchant code
            // Le merchant code est généralement fourni dans le contrat/fiche d'identification
            // On retourne null pour forcer la configuration manuelle
            return null;
        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors de la récupération du merchant code', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Détecte si l'utilisateur a Max It et/ou Orange Money installées
     * Retourne un tableau avec les informations de détection
     * Priorité : Max It > Orange Money (si les deux sont installées)
     */
    private function detectOrangeMoneyApps(Request $request)
    {
        $result = [
            'has_max_it' => false,
            'has_orange_money' => false,
            'preferred_app' => null, // 'maxit', 'orangemoney', ou null
            'detection_method' => 'none'
        ];

        // Méthode 1: Vérification via paramètres explicites (depuis JavaScript ou app mobile)
        $has_max_it_param = $request->get('has_max_it', false);
        $has_orange_money_param = $request->get('has_orange_money', false);
        
        if ($has_max_it_param === 'true' || $has_max_it_param === true || $has_max_it_param === '1') {
            $result['has_max_it'] = true;
            $result['detection_method'] = 'parameter';
        }
        
        if ($has_orange_money_param === 'true' || $has_orange_money_param === true || $has_orange_money_param === '1') {
            $result['has_orange_money'] = true;
            $result['detection_method'] = 'parameter';
        }

        // Méthode 2: Détection via User-Agent
        $user_agent = $request->header('User-Agent', '');
        
        // Détection Max It
        if (stripos($user_agent, 'MaxIt') !== false || 
            stripos($user_agent, 'Max-It') !== false ||
            stripos($user_agent, 'Maxit') !== false) {
            $result['has_max_it'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'user_agent';
            }
        }
        
        // Détection Orange Money (mais pas Max It)
        if ((stripos($user_agent, 'OrangeMoney') !== false || 
             stripos($user_agent, 'Orange Money') !== false ||
             stripos($user_agent, 'Orange-Money') !== false) &&
            !$result['has_max_it']) {
            $result['has_orange_money'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'user_agent';
            }
        }

        // Méthode 3: Détection via headers personnalisés (si l'app mobile envoie un header)
        $x_platform = $request->header('X-Platform', '');
        $x_app_name = $request->header('X-App-Name', '');
        $x_user_agent = $request->header('X-User-Agent', '');
        
        // Détection Max It via headers
        if (stripos($x_app_name, 'MaxIt') !== false ||
            stripos($x_app_name, 'Max-It') !== false ||
            stripos($x_user_agent, 'MaxIt') !== false) {
            $result['has_max_it'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'header';
            }
        }
        
        // Détection Orange Money via headers (mais pas Max It)
        if ((stripos($x_app_name, 'OrangeMoney') !== false ||
             stripos($x_app_name, 'Orange Money') !== false ||
             stripos($x_user_agent, 'OrangeMoney') !== false) &&
            !$result['has_max_it']) {
            $result['has_orange_money'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'header';
            }
        }

        // Méthode 4: Détection via session (si déjà détecté précédemment)
        if (session('has_max_it_app') === true) {
            $result['has_max_it'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'session';
            }
        }
        
        if (session('has_orange_money_app') === true) {
            $result['has_orange_money'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'session';
            }
        }

        // Méthode 5: Détection via cookies (si JavaScript a déjà détecté)
        if ($request->cookie('has_max_it_app') === 'true') {
            $result['has_max_it'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'cookie';
            }
        }
        
        if ($request->cookie('has_orange_money_app') === 'true') {
            $result['has_orange_money'] = true;
            if ($result['detection_method'] === 'none') {
                $result['detection_method'] = 'cookie';
            }
        }

        // Déterminer l'application préférée selon la priorité : Max It > Orange Money
        if ($result['has_max_it']) {
            $result['preferred_app'] = 'maxit';
            session(['has_max_it_app' => true]);
        } elseif ($result['has_orange_money']) {
            $result['preferred_app'] = 'orangemoney';
            session(['has_orange_money_app' => true]);
        }

        return $result;
    }

    /**
     * Génère un DeepLink pour ouvrir Max It ou Orange Money avec les paramètres de paiement
     */
    private function generateAppDeepLink($qr_request, $reference, $payment_data, $app_type = 'maxit')
    {
        // Schémas de DeepLink possibles pour chaque application
        $schemes = [
            'maxit' => [
                'maxit://payment',
                'maxit://pay',
                'maxit://orangemoney/payment',
                'maxit://orange-money/payment'
            ],
            'orangemoney' => [
                'orangemoney://payment',
                'orange-money://payment',
                'orangemoney://pay',
                'om://payment'
            ]
        ];

        // Sélectionner le schéma selon l'application
        $app_schemes = $schemes[$app_type] ?? $schemes['maxit'];
        $scheme = $app_schemes[0]; // Utiliser le premier schéma par défaut

        // Paramètres du paiement à passer dans le DeepLink
        $params = [
            'merchant_code' => $qr_request['code'],
            'amount' => $qr_request['amount']['value'],
            'currency' => $qr_request['amount']['unit'],
            'reference' => $reference,
            'merchant_name' => $qr_request['name'],
            'callback_success' => urlencode($qr_request['callbackSuccessUrl']),
            'callback_cancel' => urlencode($qr_request['callbackCancelUrl'])
        ];

        // Construire le DeepLink
        $query_string = http_build_query($params);
        $deeplink = $scheme . '?' . $query_string;

        Log::info('Orange Money: DeepLink généré', [
            'app_type' => $app_type,
            'scheme' => $scheme,
            'payment_id' => $payment_data->id,
            'reference' => $reference
        ]);

        return $deeplink;
    }

    /**
     * Génère les DeepLinks pour Max It et/ou Orange Money
     * Ne génère plus de QR Code, uniquement des DeepLinks
     */
    private function generatePaymentDeepLinks($qr_request, $payment_data, $reference, $merchant_code, $appDetection)
    {
        try {
            // Mise à jour du paiement avec la référence
            $this->payment::where(['id' => $payment_data->id])->update([
                'transaction_id' => $reference,
                'payment_method' => 'orange_money'
            ]);

            Log::info('Orange Money: Génération des DeepLinks', [
                'payment_id' => $payment_data->id,
                'reference' => $reference,
                'has_max_it' => $appDetection['has_max_it'],
                'has_orange_money' => $appDetection['has_orange_money']
            ]);

            // Stocker les données en session
            session([
                'orange_money_reference' => $reference,
                'orange_money_payment_id' => $payment_data->id,
                'orange_money_amount' => $qr_request['amount']['value'],
                'orange_money_merchant_code' => $merchant_code,
                'orange_money_business_name' => $qr_request['name']
            ]);

            // Générer le DeepLink pour l'application préférée
            $preferred_app = $appDetection['preferred_app'];
            $deeplink = $this->generateAppDeepLink($qr_request, $reference, $payment_data, $preferred_app);
            
            // Générer aussi le DeepLink alternatif si les deux apps sont disponibles
            $alternate_deeplink = null;
            if ($appDetection['has_max_it'] && $appDetection['has_orange_money']) {
                // Les deux sont installées, générer aussi celui d'Orange Money
                $alternate_deeplink = $this->generateAppDeepLink($qr_request, $reference, $payment_data, 'orangemoney');
            }
            
            session([
                'orange_money_deeplink' => $deeplink,
                'orange_money_app_type' => $preferred_app,
                'orange_money_has_max_it' => $appDetection['has_max_it'],
                'orange_money_has_orange_money' => $appDetection['has_orange_money'],
                'orange_money_alternate_deeplink' => $alternate_deeplink
            ]);
            
            Log::info('Orange Money: DeepLinks générés, redirection vers page de choix', [
                'payment_id' => $payment_data->id,
                'preferred_app' => $preferred_app,
                'has_max_it' => $appDetection['has_max_it'],
                'has_orange_money' => $appDetection['has_orange_money'],
                'deeplink' => substr($deeplink, 0, 50) . '...'
            ]);

            // Redirection vers la page qui tentera d'ouvrir l'application
            return redirect()->route('orange_money.choose_payment', ['payment_id' => $payment_data->id]);

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors de la génération des DeepLinks', [
                'error' => $e->getMessage(),
                'payment_id' => $payment_data->id
            ]);
            throw $e;
        }
    }

    /**
     * Page de choix du mode de paiement (Max It, Orange Money ou QR Code)
     * Tente d'ouvrir l'application préférée, avec fallback sur QR Code
     */
    public function choosePaymentMethod(Request $request)
    {
        $payment_id = $request->get('payment_id');
        
        if (!$payment_id) {
            return response()->json(['error' => 'Payment ID manquant'], 400);
        }

        $deeplink = session('orange_money_deeplink');
        $app_type = session('orange_money_app_type', 'maxit');
        $has_max_it = session('orange_money_has_max_it', false);
        $has_orange_money = session('orange_money_has_orange_money', false);
        $alternate_deeplink = session('orange_money_alternate_deeplink');
        $reference = session('orange_money_reference');
        $amount = session('orange_money_amount');

            if (!$deeplink || !$reference) {
            // Si pas de DeepLink, retourner une erreur
            return response()->json([
                'success' => false,
                'message' => 'Aucune application de paiement détectée. Veuillez installer Max It ou Orange Money.'
            ], 400);
        }

        // Déterminer le nom de l'application à afficher
        $app_name = $app_type === 'maxit' ? 'Max It' : 'Orange Money';
        $app_name_alt = $app_type === 'maxit' ? 'Orange Money' : 'Max It';
        $has_max_it_js = $has_max_it ? 'true' : 'false';
        $has_orange_money_js = $has_orange_money ? 'true' : 'false';

        // Construire le bouton alternatif si disponible
        $alternate_button = '';
        if ($alternate_deeplink) {
            $alternate_button = '<button class="app-button secondary" onclick="openApp(\'' . 
                htmlspecialchars($alternate_deeplink, ENT_QUOTES) . '\', \'' . 
                htmlspecialchars($app_name_alt, ENT_QUOTES) . '\')">Ouvrir ' . 
                htmlspecialchars($app_name_alt, ENT_QUOTES) . '</button>';
        }

        // Retourner une page HTML qui tentera d'ouvrir l'application
        // Si l'app ne s'ouvre pas, afficher les options disponibles
        $callback_url = route('orange_money.callback', ['payment_id' => $payment_id, 'status' => 'cancel']);
        
        $html = <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paiement Orange Money</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 400px;
        }
        .loading {
            margin: 20px 0;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #FF6600;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .fallback-link {
            margin-top: 20px;
            padding: 15px;
            background: #FF6600;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
        }
        .app-buttons {
            margin-top: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .app-button {
            padding: 12px;
            background: #FF6600;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .app-button.secondary {
            background: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Ouverture de {$app_name}...</h2>
        <div class="loading">
            <div class="spinner"></div>
            <p>Ouverture de l'application <strong>{$app_name}</strong> pour finaliser le paiement...</p>
        </div>
        <div class="app-buttons" id="appButtons" style="display: none;">
            <button class="app-button" onclick="openApp('{$deeplink}', '{$app_name}')">
                Ouvrir {$app_name}
            </button>
            {$alternate_button}
            <a href="{$callback_url}" class="app-button secondary" style="text-decoration: none; display: block;">
                Annuler le paiement
            </a>
        </div>
        <p style="margin-top: 20px; color: #666; font-size: 14px;">
            Si l'application ne s'ouvre pas automatiquement, cliquez sur le bouton ci-dessus pour l'ouvrir manuellement.
            <br><br>
            <strong>Note :</strong> Vous devez avoir Max It ou Orange Money installée sur votre téléphone pour effectuer le paiement.
        </p>
    </div>
    
    <script>
        // Configuration
        const deeplink = '{$deeplink}';
        const alternateDeeplink = '{$alternate_deeplink}';
        const callbackUrl = '{$callback_url}';
        const appType = '{$app_type}';
        const hasMaxIt = {$has_max_it_js};
        const hasOrangeMoney = {$has_orange_money_js};
        
        // Fonction pour détecter si on est sur mobile
        function isMobile() {
            return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        }
        
        // Fonction pour ouvrir une application
        function openApp(link, appName) {
            if (isMobile()) {
                // Tentative d'ouverture
                window.location.href = link;
                
                // Afficher les boutons après 2 secondes si l'app ne s'ouvre pas
                setTimeout(function() {
                    if (document.hasFocus()) {
                        document.getElementById('appButtons').style.display = 'block';
                    }
                }, 2000);
            } else {
                // Sur desktop, afficher un message
                alert('Veuillez utiliser un appareil mobile avec Max It ou Orange Money installée pour effectuer le paiement.');
                document.getElementById('appButtons').style.display = 'block';
            }
        }
        
        // Tentative d'ouverture automatique de l'app préférée
        if (isMobile()) {
            // Ouvrir l'application préférée (Max It en priorité)
            openApp(deeplink, appType === 'maxit' ? 'Max It' : 'Orange Money');
            
            // Si après 3 secondes on est toujours sur la page, afficher les options
            setTimeout(function() {
                if (document.hasFocus()) {
                    document.getElementById('appButtons').style.display = 'block';
                }
            }, 3000);
            
            // Détection de retour depuis l'app
            let hidden = false;
            document.addEventListener('visibilitychange', function() {
                if (document.hidden) {
                    hidden = true;
                } else if (hidden) {
                    // L'utilisateur est revenu, peut-être depuis l'app
                    setTimeout(function() {
                        // Optionnel: vérifier le statut du paiement
                    }, 1000);
                }
            });
        } else {
            // Sur desktop, afficher les boutons directement
            document.getElementById('appButtons').style.display = 'block';
            alert('Veuillez utiliser un appareil mobile avec Max It ou Orange Money installée pour effectuer le paiement.');
        }
    </script>
</body>
</html>
HTML;

        return response($html)->header('Content-Type', 'text/html');
    }


    /**
     * Gère le callback de Orange Money après le paiement
     * Les callbacks sont envoyés via webhook, mais on garde cette méthode pour les redirections
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

            if ($status === 'success') {
                // Vérifier le statut via l'API de recherche de transaction
                $reference = $payment_data->transaction_id;
                if ($reference) {
                    $verification_response = $this->verifyPaymentStatus($reference);
                    
                    if ($verification_response['success']) {
                        // Mise à jour du statut de paiement
                        $this->payment::where(['id' => $payment_id])->update([
                            'payment_method' => 'orange_money',
                            'is_paid' => 1,
                            'updated_at' => now()
                        ]);

                        Log::info('Orange Money: Paiement confirmé avec succès', [
                            'payment_id' => $payment_id,
                            'reference' => $reference
                        ]);

                        // Traitement post-paiement
                        $this->handleSuccessfulPayment($payment_data);

                        return $this->payment_response($payment_data, 'success');
                    }
                }
            }

            // Paiement annulé ou échoué
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

            return $this->payment_response($payment_data, 'fail');

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
     * Webhook Orange Money pour les notifications de paiement
     * Selon la documentation, les callbacks sont envoyés en POST
     */
    public function webhook(Request $request)
    {
        try {
            $payload = $request->all();
            
            Log::info('Orange Money Webhook Received: ' . json_encode($payload));
            
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
            Log::error('Orange Money Webhook Error: ' . $e->getMessage());
            return response()->json(['status' => 'error'], 500);
        }
    }

    /**
     * Traitement du webhook de paiement
     */
    private function processWebhookPayment($payload)
    {
        try {
            $reference = $payload['reference'] ?? null;
            $status = $payload['status'] ?? null;
            $transaction_id = $payload['transactionId'] ?? null;

            if (!$reference) {
                Log::warning('Orange Money: Webhook sans référence');
                return;
            }

            // Extraction de l'ID de paiement depuis la référence
            if (preg_match('/PAYMENT_([a-f0-9-]+)_/', $reference, $matches)) {
                $payment_id = $matches[1];
                $payment_data = $this->payment::find($payment_id);
                
                if ($payment_data && ($status === 'SUCCESS' || $status === 'success')) {
                    $this->payment::where(['id' => $payment_id])->update([
                        'payment_method' => 'orange_money',
                        'is_paid' => 1,
                        'transaction_id' => $transaction_id ?? $reference,
                        'updated_at' => now()
                    ]);

                    $this->handleSuccessfulPayment($payment_data);

                    Log::info('Orange Money: Paiement confirmé via webhook', [
                        'payment_id' => $payment_id,
                        'transaction_id' => $transaction_id
                    ]);
                } else {
                    Log::info('Orange Money: Webhook reçu avec statut non-success', [
                        'payment_id' => $payment_id,
                        'status' => $status
                    ]);
                }
            } else {
                Log::warning('Orange Money: Impossible d\'extraire payment_id de la référence', [
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
                    return [
                        'success' => false,
                        'error' => 'Transaction non trouvée'
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
























