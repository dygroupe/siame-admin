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

class WaveController extends Controller
{
    use Processor;

    private $config_values;
    private PaymentRequest $payment;
    private $user;
    private $base_url;
    private $headers;

    public function __construct(PaymentRequest $payment, User $user)
    {
        try {
            $config = $this->payment_config('wave', 'payment_config');
            
            if (!is_null($config) && $config->mode == 'live') {
                $this->config_values = json_decode($config->live_values);
                $this->base_url = 'https://api.wave.com';
            } elseif (!is_null($config) && $config->mode == 'test') {
                $this->config_values = json_decode($config->test_values);
                $this->base_url = 'https://api.wave.com';
            } else {
                // Configuration par défaut si pas de config en base
                $this->config_values = (object) [
                    'api_key' => config('wave.api_key', ''),
                    'business_name' => config('wave.business_name', 'SIAME')
                ];
                $this->base_url = config('wave.base_url', 'https://api.wave.com');
            }
        } catch (Exception $e) {
            // Configuration par défaut en cas d'erreur de base
            $this->config_values = (object) [
                'api_key' => config('wave.api_key', ''),
                'business_name' => config('wave.business_name', 'SIAME')
            ];
            $this->base_url = config('wave.base_url', 'https://api.wave.com');
        }

        // Vérification des clés API requises (optionnelle pour les tests)
        if (empty($this->config_values->api_key)) {
            Log::warning('Wave: Clé API manquante - Mode test uniquement');
            $this->config_values->api_key = 'test-api-key';
        }
        
        if (empty($this->config_values->business_name)) {
            $this->config_values->business_name = 'SIAME';
        }

        $this->payment = $payment;
        $this->user = $user;

        // Configuration des en-têtes HTTP selon la documentation officielle Wave
        $this->headers = [
            'Authorization' => 'Bearer ' . $this->config_values->api_key,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];

        // Log de la configuration pour débogage
        Log::info('Wave: Configuration initialisée', [
            'mode' => $this->config_values->mode ?? 'test',
            'base_url' => $this->base_url,
            'endpoint_create' => $this->base_url . '/v1/checkout/sessions'
        ]);
    }

    /**
     * Initialise le processus de paiement Wave
     * Crée une session de checkout et redirige vers la page de paiement
     */
    public function initialize(Request $request)
    {
        try {
            // Validation des données d'entrée
            $validator = Validator::make($request->all(), [
                'payment_id' => 'required|uuid'
            ]);

            if ($validator->fails()) {
                Log::error('Wave: Validation échouée', [
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
                Log::warning('Wave: Données de paiement non trouvées', [
                    'payment_id' => $request['payment_id']
                ]);
                
                return response()->json($this->response_formatter(GATEWAYS_DEFAULT_204), 200);
            }

            // Extraction des informations métier
            $business_name = $this->extractBusinessName($payment_data);
            $payer_info = json_decode($payment_data->payer_information, true);

            // Validation de la devise supportée
            $supported_currencies = ['XOF', 'EUR', 'USD', 'GBP'];
            $currency = $payment_data->currency_code ?? 'XOF';
            
            if (!in_array($currency, $supported_currencies)) {
                Log::error('Wave: Devise non supportée', [
                    'payment_id' => $payment_data->id,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Devise non supportée par Wave: ' . $currency
                ), 400);
            }

            // Calcul du montant selon la devise (Wave utilise des strings)
            $raw_amount = (float) $payment_data->payment_amount;
            $amount = $this->normalizeWaveAmount($raw_amount, $currency);
            
            // Validation stricte des montants selon la documentation Wave
            if (!$this->validateWaveAmount($amount, $currency)) {
                Log::error('Wave: Montant invalide selon les règles Wave', [
                    'payment_id' => $payment_data->id,
                    'amount' => $amount,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Montant invalide selon les règles Wave pour ' . $currency
                ), 400);
            }
            
            // Validation du montant minimum selon la devise
            $min_amount = ($currency === 'XOF') ? '1' : '0.01';
            if (($currency === 'XOF' && (int)$amount < 1) || ($currency !== 'XOF' && (float)$amount < 0.01)) {
                Log::error('Wave: Montant insuffisant', [
                    'payment_id' => $payment_data->id,
                    'raw_amount' => $raw_amount,
                    'normalized_amount' => $amount,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Le montant minimum est de ' . $min_amount . ' ' . $currency
                ), 400);
            }

            // Préparation de la requête Wave selon la documentation officielle
            $wave_request = [
                'amount' => $amount,
                'currency' => $currency,
                'client_reference' => 'PAYMENT_' . $payment_data->id . '_' . time(),
                'success_url' => route('wave.callback', ['payment_id' => $payment_data->id, 'status' => 'successful']),
                'error_url' => route('wave.callback', ['payment_id' => $payment_data->id, 'status' => 'cancelled'])
            ];

            // Ajout du paramètre restrict_payer_mobile si disponible (sécurité anti-fraude)
            if (isset($payer_info['phone']) && !empty($payer_info['phone'])) {
                $phone = $payer_info['phone'];
                // Validation du format E.164 (+country_code + number)
                if (preg_match('/^\+[1-9]\d{1,14}$/', $phone)) {
                    $wave_request['restrict_payer_mobile'] = $phone;
                }
            }

            // Ajout du paramètre aggregated_merchant_id si configuré (pour les agrégateurs)
            if (isset($this->config_values->aggregated_merchant_id) && !empty($this->config_values->aggregated_merchant_id)) {
                $wave_request['aggregated_merchant_id'] = $this->config_values->aggregated_merchant_id;
            }

            Log::info('Wave: Création de session de checkout', [
                'payment_id' => $payment_data->id,
                'raw_amount' => $raw_amount,
                'normalized_amount' => $amount,
                'business' => $business_name
            ]);

            // Appel à l'API Wave pour créer la session de checkout
            $endpoint = '/v1/checkout/sessions';
            $full_url = $this->base_url . $endpoint;
            
            Log::info('Wave: Appel API', [
                'endpoint' => $endpoint,
                'full_url' => $full_url,
                'mode' => $this->config_values->mode ?? 'test',
                'headers' => $this->headers,
                'request_data' => $wave_request
            ]);
            
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->post($full_url, $wave_request);

            // Log de la réponse pour débogage
            Log::info('Wave: Réponse reçue', [
                'status_code' => $response->status(),
                'response_body' => $response->body(),
                'response_headers' => $response->headers()
            ]);

            if (!$response->successful()) {
                Log::error('Wave: Erreur API lors de la création de session', [
                    'status_code' => $response->status(),
                    'response' => $response->body(),
                    'payment_id' => $payment_data->id
                ]);
                
                throw new Exception('Erreur lors de la création de la session Wave: ' . $response->status());
            }

            $response_data = $response->json();
            
            // Vérification de la réponse Wave selon la documentation
            if (!isset($response_data['id']) || !isset($response_data['wave_launch_url'])) {
                Log::error('Wave: Échec de création de session', [
                    'response' => $response_data,
                    'payment_id' => $payment_data->id
                ]);
                
                // Gestion des erreurs Wave selon la documentation
                $error_message = 'Erreur inconnue';
                if (isset($response_data['error_code'])) {
                    $error_message = $this->getWaveErrorMessage($response_data['error_code']);
                } elseif (isset($response_data['error_message'])) {
                    $error_message = $response_data['error_message'];
                }
                
                throw new Exception('Échec de création de session Wave: ' . $error_message);
            }

            // Mise à jour du paiement avec l'ID de session Wave
            $this->payment::where(['id' => $payment_data->id])->update([
                'transaction_id' => $response_data['id'],
                'payment_method' => 'wave'
            ]);

            Log::info('Wave: Session créée avec succès', [
                'payment_id' => $payment_data->id,
                'session_id' => $response_data['id']
            ]);

            // Redirection vers la page de paiement Wave
            $checkout_url = $response_data['wave_launch_url'];
            
            Log::info('Wave: Redirection vers la page de paiement', [
                'payment_id' => $payment_data->id,
                'session_id' => $response_data['id'],
                'checkout_url' => $checkout_url
            ]);
            
            return redirect()->away($checkout_url);

        } catch (Exception $e) {
            Log::error('Wave: Erreur lors de l\'initialisation', [
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
     * Gère le callback de Wave après le paiement
     * Vérifie le statut du paiement et met à jour la base de données
     */
    public function callback(Request $request)
    {
        try {
            $payment_id = $request->get('payment_id');
            $status = $request->get('status', 'successful');
            $session_id = $request->get('session_id');

            Log::info('Wave: Callback reçu', [
                'payment_id' => $payment_id,
                'status' => $status,
                'session_id' => $session_id,
                'all_params' => $request->all()
            ]);

            if (empty($payment_id)) {
                Log::error('Wave: Callback sans payment_id');
                return response()->json(['success' => false, 'message' => 'Payment ID manquant'], 400);
            }

            // Récupération des données de paiement
            $payment_data = $this->payment::where(['id' => $payment_id])->first();
            
            if (!isset($payment_data)) {
                Log::error('Wave: Données de paiement non trouvées pour le callback', [
                    'payment_id' => $payment_id
                ]);
                return response()->json(['success' => false, 'message' => 'Paiement non trouvé'], 404);
            }

            // Wave ne renvoie pas toujours session_id dans l'URL de redirection success_url.
            // On utilise l'ID de session enregistré à la création du checkout (transaction_id).
            if ($status === 'successful' && empty($session_id) && !empty($payment_data->transaction_id)) {
                $session_id = $payment_data->transaction_id;
                Log::info('Wave: session_id récupéré depuis transaction_id (payment_data)', [
                    'payment_id' => $payment_id,
                    'session_id' => $session_id
                ]);
            }

            if ($status === 'successful' && $session_id) {
                // Vérification du paiement avec l'API Wave
                $verification_response = $this->verifyPayment($session_id);
                
                if ($verification_response['success']) {
                    $session_data = $verification_response['session'];
                    
                    // Vérification du montant et du statut
                    if ($this->validatePaymentAmount($payment_data, $session_data)) {
                        // Mise à jour du statut de paiement
                        $this->payment::where(['id' => $payment_id])->update([
                            'payment_method' => 'wave',
                            'is_paid' => 1,
                            'transaction_id' => $session_id,
                            'updated_at' => now()
                        ]);

                        Log::info('Wave: Paiement confirmé avec succès', [
                            'payment_id' => $payment_id,
                            'session_id' => $session_id,
                            'amount_paid' => $session_data['amount']
                        ]);

                        // Traitement post-paiement
                        $this->handleSuccessfulPayment($payment_data);

                        // Redirection selon la plateforme (mobile ou web)
                        return $this->payment_response($payment_data, 'success');
                    } else {
                        Log::error('Wave: Montant de paiement invalide', [
                            'payment_id' => $payment_id,
                            'expected_amount' => $payment_data->payment_amount,
                            'received_amount' => $session_data['amount']
                        ]);
                        
                        // Exécution du hook d'échec si disponible
                        if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                            try {
                                call_user_func($payment_data->failure_hook, $payment_data);
                            } catch (Exception $hook_error) {
                                Log::error('Wave: Erreur lors de l\'exécution du hook d\'échec', [
                                    'error' => $hook_error->getMessage(),
                                    'payment_id' => $payment_id
                                ]);
                            }
                        }
                        
                        // Redirection selon la plateforme (mobile ou web)
                        return $this->payment_response($payment_data, 'fail');
                    }
                } else {
                    Log::error('Wave: Échec de vérification du paiement', [
                        'payment_id' => $payment_id,
                        'session_id' => $session_id,
                        'error' => $verification_response['error'] ?? 'Erreur inconnue'
                    ]);
                    
                    // Exécution du hook d'échec si disponible
                    if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                        try {
                            call_user_func($payment_data->failure_hook, $payment_data);
                        } catch (Exception $hook_error) {
                            Log::error('Wave: Erreur lors de l\'exécution du hook d\'échec', [
                                'error' => $hook_error->getMessage(),
                                'payment_id' => $payment_id
                            ]);
                        }
                    }
                    
                    // Redirection selon la plateforme (mobile ou web)
                    return $this->payment_response($payment_data, 'fail');
                }
            } else {
                // Paiement annulé ou échoué (cancelled = annulation utilisateur, autre = échec)
                $redirect_flag = ($status === 'cancelled') ? 'cancel' : 'fail';
                Log::info('Wave: Paiement annulé ou échoué', [
                    'payment_id' => $payment_id,
                    'status' => $status
                ]);

                $this->payment::where(['id' => $payment_id])->update([
                    'payment_method' => 'wave',
                    'is_paid' => 0,
                    'updated_at' => now()
                ]);

                // Récupération des données de paiement pour la redirection
                $payment_data = $this->payment::where(['id' => $payment_id])->first();
                
                // Exécution du hook d'échec si disponible
                if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                    try {
                        call_user_func($payment_data->failure_hook, $payment_data);
                    } catch (Exception $hook_error) {
                        Log::error('Wave: Erreur lors de l\'exécution du hook d\'échec', [
                            'error' => $hook_error->getMessage(),
                            'payment_id' => $payment_id
                        ]);
                    }
                }

                // Redirection selon la plateforme (mobile = deep link siame://, web = payment-fail/cancel)
                return $this->payment_response($payment_data, $redirect_flag);
            }

        } catch (Exception $e) {
            Log::error('Wave: Erreur lors du callback', [
                'error' => $e->getMessage(),
                'payment_id' => $request->get('payment_id'),
                'trace' => $e->getTraceAsString()
            ]);

            // Récupération des données de paiement pour la redirection en cas d'erreur
            $payment_id = $request->get('payment_id');
            if ($payment_id) {
                $payment_data = $this->payment::where(['id' => $payment_id])->first();
                if ($payment_data) {
                    // Exécution du hook d'échec si disponible
                    if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                        try {
                            call_user_func($payment_data->failure_hook, $payment_data);
                        } catch (Exception $hook_error) {
                            Log::error('Wave: Erreur lors de l\'exécution du hook d\'échec', [
                                'error' => $hook_error->getMessage(),
                                'payment_id' => $payment_id
                            ]);
                        }
                    }
                    
                    // Redirection selon la plateforme (mobile ou web)
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
     * Webhook Wave pour les notifications de paiement
     */
    public function webhook(Request $request)
    {
        try {
            // Vérification de la signature du webhook (si Wave l'implémente)
            $payload = $request->all();
            
            Log::info('Wave Webhook Received: ' . json_encode($payload));
            
            // Traitement du webhook selon le type d'événement
            if (isset($payload['checkout_session'])) {
                $checkout_session = $payload['checkout_session'];
                $this->processWebhookPayment($checkout_session);
            }

            return response()->json(['status' => 'success'], 200);

        } catch (Exception $e) {
            Log::error('Wave Webhook Error: ' . $e->getMessage());
            return response()->json(['status' => 'error'], 500);
        }
    }

    /**
     * Traitement du webhook de paiement
     */
    private function processWebhookPayment($checkout_session)
    {
        try {
            $client_reference = $checkout_session['client_reference'];
            
            // Extraction de l'ID de paiement depuis la référence client
            if (preg_match('/PAYMENT_([a-f0-9-]+)_/', $client_reference, $matches)) {
                $payment_id = $matches[1];
                $payment_data = $this->payment::find($payment_id);
                
                if ($payment_data && $checkout_session['payment_status'] === 'succeeded') {
                    $this->payment::where(['id' => $payment_id])->update([
                        'payment_method' => 'wave',
                        'is_paid' => 1,
                        'transaction_id' => $checkout_session['id'],
                        'updated_at' => now()
                    ]);

                    $this->handleSuccessfulPayment($payment_data);
                }
            }

        } catch (Exception $e) {
            Log::error('Wave Webhook Processing Error: ' . $e->getMessage());
        }
    }

    /**
     * Vérifie le statut d'un paiement Wave
     */
    public function verifyPayment($session_id)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->get($this->base_url . '/v1/checkout/sessions/' . $session_id);

            if ($response->successful()) {
                $session_data = $response->json();
                
                // Vérification selon la documentation Wave
                if ($session_data['payment_status'] === 'succeeded' && $session_data['checkout_status'] === 'complete') {
                    return [
                        'success' => true,
                        'session' => $session_data
                    ];
                } else {
                    // Gestion des erreurs de paiement selon la documentation
                    $error_message = 'Paiement échoué';
                    if (isset($session_data['last_payment_error'])) {
                        $error_code = $session_data['last_payment_error']['code'] ?? 'unknown';
                        $error_message = $this->getWaveErrorMessage($error_code);
                    }
                    
                    return [
                        'success' => false,
                        'error' => $error_message
                    ];
                }
            } else {
                $error_data = $response->json();
                $error_message = 'Impossible de vérifier le statut du paiement';
                
                if (isset($error_data['error_code'])) {
                    $error_message = $this->getWaveErrorMessage($error_data['error_code']);
                }
                
                return [
                    'success' => false,
                    'error' => $error_message
                ];
            }

        } catch (Exception $e) {
            Log::error('Wave Verify Payment Error: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Erreur lors de la vérification du paiement'
            ];
        }
    }

    /**
     * Valide le montant du paiement
     */
    private function validatePaymentAmount($payment_data, $session_data)
    {
        $currency = $payment_data->currency_code ?? 'XOF';

        // Utiliser exactement la même normalisation que pour l'envoi à Wave
        $expected_normalized = $this->normalizeWaveAmount((float) $payment_data->payment_amount, $currency);
        $received_normalized = $this->normalizeWaveAmount((float) $session_data['amount'], $currency);

        return $expected_normalized === $received_normalized;
    }

    /**
     * Valide le format des montants selon les règles strictes de Wave
     * Conforme à la documentation officielle Wave Checkout API
     */
    private function validateWaveAmount($amount, $currency)
    {
        // Règles Wave pour les montants :
        // - Représentés comme des strings
        // - Entre 0 et 2 décimales (voir Currency pour le max par devise)
        // - Pas de zéros en tête où la valeur est >= 1
        // - Un zéro en tête où la valeur est < 1
        // - Peut inclure des zéros en queue
        // - Doit être positif pour les requêtes

        if (!is_string($amount) || empty($amount)) {
            return false;
        }

        // Vérifier que c'est un nombre valide
        if (!is_numeric($amount)) {
            return false;
        }

        $numeric_amount = (float) $amount;

        // Doit être positif
        if ($numeric_amount <= 0) {
            return false;
        }

        // Règles spécifiques par devise
        if ($currency === 'XOF') {
            // XOF : pas de décimales autorisées
            if (strpos($amount, '.') !== false) {
                return false;
            }
            // Pas de zéros en tête pour les valeurs >= 1
            if ($numeric_amount >= 1 && strpos($amount, '0') === 0) {
                return false;
            }
        } else {
            // Autres devises : max 2 décimales
            $parts = explode('.', $amount);
            if (count($parts) > 2) {
                return false;
            }
            if (count($parts) === 2 && strlen($parts[1]) > 2) {
                return false;
            }
            // Un zéro en tête pour les valeurs < 1
            if ($numeric_amount < 1 && strpos($amount, '0.') !== 0) {
                return false;
            }
            // Pas de zéros en tête pour les valeurs >= 1
            if ($numeric_amount >= 1 && strpos($amount, '0') === 0 && $amount[1] !== '.') {
                return false;
            }
        }

        return true;
    }

    /**
     * Normalise le montant selon la documentation Wave.
     * - Représentation en string
     * - XOF: entier sans décimales (arrondi à l'unité la plus proche vers le bas)
     * - Autres: jusqu'à 2 décimales, séparateur '.'
     */
    private function normalizeWaveAmount(float $amount, string $currency): string
    {
        if (strtoupper($currency) === 'XOF') {
            // Pas de décimales pour XOF
            $normalized = (string) max(0, (int) floor($amount));
            return $normalized;
        }

        // Autres devises: 2 décimales max
        $normalized = number_format($amount, 2, '.', '');
        return (string) $normalized;
    }

    /**
     * Retourne le message d'erreur Wave selon le code d'erreur
     * Conforme à la documentation officielle Wave Checkout API
     */
    private function getWaveErrorMessage($error_code)
    {
        // Erreurs d'authentification (401)
        $auth_errors = [
            'missing-auth-header' => 'Votre requête doit inclure un en-tête d\'autorisation HTTP.',
            'invalid-auth' => 'Votre en-tête d\'autorisation HTTP ne peut pas être traité.',
            'api-key-not-provided' => 'Votre requête doit inclure une clé API.',
            'no-matching-api-key' => 'La clé que vous avez fournie n\'existe pas dans notre système.',
            'api-key-revoked' => 'Votre clé API a été révoquée.',
            'authorization-error' => 'La clé API est manquante ou incomplète.'
        ];

        // Erreurs de portefeuille (403)
        $wallet_errors = [
            'invalid-wallet' => 'Votre portefeuille ne peut pas être utilisé avec cette API particulière.',
            'disabled-wallet' => 'Votre portefeuille a été temporairement désactivé.',
            'unauthorized-wallet' => 'Le compte que vous utilisez n\'est pas autorisé à utiliser cette API.'
        ];

        // Erreurs de session de checkout
        $checkout_errors = [
            'checkout-session-not-found' => 'Session de checkout non trouvée dans notre système.',
            'checkout-refund-failed' => 'Impossible de rembourser la session de checkout.',
            'request-validation-error' => 'Votre requête ne correspond pas au type d\'objet requis.',
            'service-unavailable' => 'Service temporairement indisponible pour maintenance.',
            'internal-server-error' => 'Une erreur technique s\'est produite dans le système Wave.'
        ];

        // Erreurs de paiement
        $payment_errors = [
            'blocked-account' => 'Le client a utilisé un compte bloqué pour essayer de payer.',
            'cross-border-payment-not-allowed' => 'Les paiements transfrontaliers sont souvent restreints pour des raisons réglementaires.',
            'customer-age-restricted' => 'Le client est mineur mais essaie de payer pour un produit/service restreint par l\'âge.',
            'insufficient-funds' => 'L\'utilisateur n\'avait pas assez de solde de compte.',
            'kyb-limits-exceeded' => 'Votre entreprise a dépassé ses limites de compte.',
            'payer-mobile-mismatch' => 'Le numéro de mobile du payeur ne correspond pas à celui spécifié.',
            'payment-failure' => 'Une erreur technique s\'est produite dans le système Wave.'
        ];

        // Fusion de tous les messages d'erreur
        $all_errors = array_merge($auth_errors, $wallet_errors, $checkout_errors, $payment_errors);

        return $all_errors[$error_code] ?? 'Erreur inconnue: ' . $error_code;
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

            // Envoi d'email de confirmation
            // TODO: Implémenter l'envoi d'email

            // Notification au vendeur
            // TODO: Implémenter la notification

            // Mise à jour des statistiques
            // TODO: Implémenter la mise à jour des stats

        } catch (Exception $e) {
            Log::error('Wave Handle Successful Payment Error: ' . $e->getMessage());
        }
    }

    /**
     * Extrait le nom de l'entreprise depuis les données de paiement
     */
    private function extractBusinessName($payment_data)
    {
        $business_name = 'SIAME'; // Valeur par défaut
        
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

    /**
     * Recherche d'une session de checkout par référence client
     */
    public function searchCheckout($client_reference)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->get($this->base_url . '/v1/checkout/sessions/search', [
                    'client_reference' => $client_reference
                ]);

            if ($response->successful()) {
                $data = $response->json();
                return $data['result'] ?? [];
            }

            return [];

        } catch (Exception $e) {
            Log::error('Wave Search Checkout Error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Récupération d'une session de checkout par transaction ID
     * GET /v1/checkout/sessions?transaction_id=xxx
     */
    public function getCheckoutByTransactionId($transaction_id)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->get($this->base_url . '/v1/checkout/sessions', [
                    'transaction_id' => $transaction_id
                ]);

            if ($response->successful()) {
                return $response->json();
            }

            return null;

        } catch (Exception $e) {
            Log::error('Wave Get Checkout by Transaction ID Error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Remboursement d'un paiement Wave
     */
    public function refund($session_id)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->post($this->base_url . '/v1/checkout/sessions/' . $session_id . '/refund');

            if ($response->successful()) {
                return [
                    'success' => true,
                    'message' => 'Remboursement effectué avec succès'
                ];
            } else {
                $error_data = $response->json();
                $error_message = 'Erreur lors du remboursement';
                
                if (isset($error_data['error_code'])) {
                    $error_message = $this->getWaveErrorMessage($error_data['error_code']);
                }
                
                return [
                    'success' => false,
                    'message' => $error_message
                ];
            }

        } catch (Exception $e) {
            Log::error('Wave Refund Error: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Erreur lors du remboursement'
            ];
        }
    }

    /**
     * Expiration d'une session de checkout
     */
    public function expire($session_id)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->post($this->base_url . '/v1/checkout/sessions/' . $session_id . '/expire');

            if ($response->successful()) {
                return [
                    'success' => true,
                    'message' => 'Session expirée avec succès'
                ];
            } else {
                $error_data = $response->json();
                $error_message = 'Erreur lors de l\'expiration';
                
                if (isset($error_data['error_code'])) {
                    $error_message = $this->getWaveErrorMessage($error_data['error_code']);
                }
                
                return [
                    'success' => false,
                    'message' => $error_message
                ];
            }

        } catch (Exception $e) {
            Log::error('Wave Expire Error: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Erreur lors de l\'expiration'
            ];
        }
    }

    /**
     * Récupération de la configuration de paiement
     */
    private function payment_config($gateway, $type)
    {
        try {
            $config = DB::table('addon_settings')
                ->where('key_name', $gateway)
                ->where('settings_type', $type)
                ->first();

            return $config;
        } catch (Exception $e) {
            Log::warning("Wave: Impossible de récupérer la configuration {$gateway}", [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }
}
