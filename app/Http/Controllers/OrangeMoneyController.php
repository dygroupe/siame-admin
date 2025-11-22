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
    private $headers;

    public function __construct(PaymentRequest $payment, User $user)
    {
        try {
            $config = $this->payment_config('orange_money', 'payment_config');
            
            if (!is_null($config) && $config->mode == 'live') {
                $this->config_values = json_decode($config->live_values);
                $this->base_url = 'https://api.orange.com';
            } elseif (!is_null($config) && $config->mode == 'test') {
                $this->config_values = json_decode($config->test_values);
                $this->base_url = 'https://api.orange.com';
            } else {
                // Configuration par défaut si pas de config en base
                $this->config_values = (object) [
                    'client_id' => config('orange.client_id', ''),
                    'client_secret' => config('orange.client_secret', ''),
                    'merchant_id' => config('orange.merchant_id', ''),
                    'business_name' => config('orange.business_name', 'SIAME')
                ];
                $this->base_url = config('orange.base_url', 'https://api.orange.com');
            }
        } catch (Exception $e) {
            // Configuration par défaut en cas d'erreur de base
            $this->config_values = (object) [
                'client_id' => config('orange.client_id', ''),
                'client_secret' => config('orange.client_secret', ''),
                'merchant_id' => config('orange.merchant_id', ''),
                'business_name' => config('orange.business_name', 'SIAME')
            ];
            $this->base_url = config('orange.base_url', 'https://api.orange.com');
        }

        // Vérification des clés API requises (optionnelle pour les tests)
        if (empty($this->config_values->client_id)) {
            Log::warning('Orange Money: Client ID manquant - Mode test uniquement');
            $this->config_values->client_id = 'test-client-id';
        }
        
        if (empty($this->config_values->client_secret)) {
            Log::warning('Orange Money: Client Secret manquant - Mode test uniquement');
            $this->config_values->client_secret = 'test-client-secret';
        }

        if (empty($this->config_values->merchant_id)) {
            $this->config_values->merchant_id = 'test-merchant-id';
        }

        if (empty($this->config_values->business_name)) {
            $this->config_values->business_name = 'SIAME';
        }

        $this->payment = $payment;
        $this->user = $user;

        // Configuration des en-têtes HTTP selon la documentation officielle Orange Money
        $this->headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];

        // Log de la configuration pour débogage
        Log::info('Orange Money: Configuration initialisée', [
            'mode' => $this->config_values->mode ?? 'test',
            'base_url' => $this->base_url,
            'endpoint_token' => $this->base_url . '/oauth/v2/token'
        ]);
    }

    /**
     * Initialise le processus de paiement Orange Money
     * Crée une session de paiement et redirige vers la page de paiement
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

            // Validation de la devise supportée
            $supported_currencies = ['XOF', 'EUR', 'USD', 'GBP'];
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

            // Calcul du montant selon la devise
            if ($currency === 'XOF') {
                // Pour XOF, pas de décimales selon la documentation
                $amount = (string) (int) ($payment_data->payment_amount * 100);
            } else {
                // Pour les autres devises, garder les décimales (max 2)
                $amount = number_format($payment_data->payment_amount, 2, '.', '');
                $amount = (string) $amount;
            }
            
            // Validation stricte des montants selon la documentation Orange Money
            if (!$this->validateOrangeMoneyAmount($amount, $currency)) {
                Log::error('Orange Money: Montant invalide selon les règles Orange Money', [
                    'payment_id' => $payment_data->id,
                    'amount' => $amount,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Montant invalide selon les règles Orange Money pour ' . $currency
                ), 400);
            }
            
            // Validation du montant minimum selon la devise
            $min_amount = ($currency === 'XOF') ? '100' : '0.01';
            if (($currency === 'XOF' && (int)$amount < 100) || ($currency !== 'XOF' && (float)$amount < 0.01)) {
                Log::error('Orange Money: Montant insuffisant', [
                    'payment_id' => $payment_data->id,
                    'amount' => $amount,
                    'currency' => $currency
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Le montant minimum est de ' . $min_amount . ' ' . $currency
                ), 400);
            }

            // Obtention du token d'accès OAuth2
            $access_token = $this->getAccessToken();
            if (!$access_token) {
                Log::error('Orange Money: Impossible d\'obtenir le token d\'accès', [
                    'payment_id' => $payment_data->id
                ]);
                
                return response()->json($this->response_formatter(
                    GATEWAYS_DEFAULT_400,
                    null,
                    'Erreur d\'authentification Orange Money'
                ), 400);
            }

            // Préparation de la requête Orange Money selon la documentation officielle
            $orange_request = [
                'merchant_id' => $this->config_values->merchant_id,
                'amount' => $amount,
                'currency' => $currency,
                'order_id' => 'PAYMENT_' . $payment_data->id . '_' . time(),
                'return_url' => route('orange_money.callback', ['payment_id' => $payment_data->id, 'status' => 'successful']),
                'cancel_url' => route('orange_money.callback', ['payment_id' => $payment_data->id, 'status' => 'cancelled']),
                'notif_url' => route('orange_money.webhook', ['payment_id' => $payment_data->id]),
                'lang' => 'fr',
                'reference' => $payment_data->id
            ];

            // Ajout du numéro de téléphone si disponible (sécurité anti-fraude)
            if (isset($payer_info['phone']) && !empty($payer_info['phone'])) {
                $phone = $payer_info['phone'];
                // Validation du format international
                if (preg_match('/^\+[1-9]\d{1,14}$/', $phone)) {
                    $orange_request['customer_phone'] = $phone;
                }
            }

            Log::info('Orange Money: Création de session de paiement', [
                'payment_id' => $payment_data->id,
                'amount' => $amount,
                'business' => $business_name
            ]);

            // Appel à l'API Orange Money pour créer la session de paiement
            $endpoint = '/orange-money-webpay/v1/payment';
            $full_url = $this->base_url . $endpoint;
            
            Log::info('Orange Money: Appel API', [
                'endpoint' => $endpoint,
                'full_url' => $full_url,
                'mode' => $this->config_values->mode ?? 'test',
                'request_data' => $orange_request
            ]);
            
            $response = Http::withHeaders(array_merge($this->headers, [
                'Authorization' => 'Bearer ' . $access_token
            ]))
                ->timeout(30)
                ->post($full_url, $orange_request);

            // Log de la réponse pour débogage
            Log::info('Orange Money: Réponse reçue', [
                'status_code' => $response->status(),
                'response_body' => $response->body(),
                'response_headers' => $response->headers()
            ]);

            if (!$response->successful()) {
                Log::error('Orange Money: Erreur API lors de la création de session', [
                    'status_code' => $response->status(),
                    'response' => $response->body(),
                    'payment_id' => $payment_data->id
                ]);
                
                throw new Exception('Erreur lors de la création de la session Orange Money: ' . $response->status());
            }

            $response_data = $response->json();
            
            // Vérification de la réponse Orange Money selon la documentation
            if (!isset($response_data['pay_token']) || !isset($response_data['payment_url'])) {
                Log::error('Orange Money: Échec de création de session', [
                    'response' => $response_data,
                    'payment_id' => $payment_data->id
                ]);
                
                // Gestion des erreurs Orange Money selon la documentation
                $error_message = 'Erreur inconnue';
                if (isset($response_data['error_code'])) {
                    $error_message = $this->getOrangeMoneyErrorMessage($response_data['error_code']);
                } elseif (isset($response_data['error_message'])) {
                    $error_message = $response_data['error_message'];
                }
                
                throw new Exception('Échec de création de session Orange Money: ' . $error_message);
            }

            // Mise à jour du paiement avec le token Orange Money
            $this->payment::where(['id' => $payment_data->id])->update([
                'transaction_id' => $response_data['pay_token'],
                'payment_method' => 'orange_money'
            ]);

            Log::info('Orange Money: Session créée avec succès', [
                'payment_id' => $payment_data->id,
                'pay_token' => $response_data['pay_token']
            ]);

            // Redirection vers la page de paiement Orange Money
            $payment_url = $response_data['payment_url'];
            
            Log::info('Orange Money: Redirection vers la page de paiement', [
                'payment_id' => $payment_data->id,
                'pay_token' => $response_data['pay_token'],
                'payment_url' => $payment_url
            ]);
            
            return redirect()->away($payment_url);

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
     * Gère le callback d'Orange Money après le paiement
     * Vérifie le statut du paiement et met à jour la base de données
     */
    public function callback(Request $request)
    {
        try {
            $payment_id = $request->get('payment_id');
            $status = $request->get('status', 'successful');
            $pay_token = $request->get('pay_token');

            Log::info('Orange Money: Callback reçu', [
                'payment_id' => $payment_id,
                'status' => $status,
                'pay_token' => $pay_token,
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

            if ($status === 'successful' && $pay_token) {
                // Vérification du paiement avec l'API Orange Money
                $verification_response = $this->verifyPayment($pay_token);
                
                if ($verification_response['success']) {
                    $payment_data_verification = $verification_response['payment'];
                    
                    // Vérification du montant et du statut
                    if ($this->validatePaymentAmount($payment_data, $payment_data_verification)) {
                        // Mise à jour du statut de paiement
                        $this->payment::where(['id' => $payment_id])->update([
                            'payment_method' => 'orange_money',
                            'is_paid' => 1,
                            'transaction_id' => $pay_token,
                            'updated_at' => now()
                        ]);

                        Log::info('Orange Money: Paiement confirmé avec succès', [
                            'payment_id' => $payment_id,
                            'pay_token' => $pay_token,
                            'amount_paid' => $payment_data_verification['amount']
                        ]);

                        // Traitement post-paiement
                        $this->handleSuccessfulPayment($payment_data);

                        // Redirection selon la plateforme (mobile ou web)
                        return $this->payment_response($payment_data, 'success');
                    } else {
                        Log::error('Orange Money: Montant de paiement invalide', [
                            'payment_id' => $payment_id,
                            'expected_amount' => $payment_data->payment_amount,
                            'received_amount' => $payment_data_verification['amount']
                        ]);
                        
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
                        
                        // Redirection selon la plateforme (mobile ou web)
                        return $this->payment_response($payment_data, 'fail');
                    }
                } else {
                    Log::error('Orange Money: Échec de vérification du paiement', [
                        'payment_id' => $payment_id,
                        'pay_token' => $pay_token,
                        'error' => $verification_response['error'] ?? 'Erreur inconnue'
                    ]);
                    
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
                    
                    // Redirection selon la plateforme (mobile ou web)
                    return $this->payment_response($payment_data, 'fail');
                }
            } else {
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

                // Récupération des données de paiement pour la redirection
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

                // Redirection selon la plateforme (mobile ou web)
                return $this->payment_response($payment_data, 'fail');
            }

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors du callback', [
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
                            Log::error('Orange Money: Erreur lors de l\'exécution du hook d\'échec', [
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
     * Webhook Orange Money pour les notifications de paiement
     */
    public function webhook(Request $request)
    {
        try {
            // Vérification de la signature du webhook (si Orange Money l'implémente)
            $payload = $request->all();
            
            Log::info('Orange Money Webhook Received: ' . json_encode($payload));
            
            // Traitement du webhook selon le type d'événement
            if (isset($payload['pay_token']) && isset($payload['status'])) {
                $this->processWebhookPayment($payload);
            }

            return response()->json(['status' => 'success'], 200);

        } catch (Exception $e) {
            Log::error('Orange Money Webhook Error: ' . $e->getMessage());
            return response()->json(['status' => 'error'], 500);
        }
    }

    /**
     * Obtient un token d'accès OAuth2 pour l'API Orange Money
     */
    private function getAccessToken()
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->post($this->base_url . '/oauth/v2/token', [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->config_values->client_id,
                    'client_secret' => $this->config_values->client_secret
                ]);

            if ($response->successful()) {
                $data = $response->json();
                return $data['access_token'] ?? null;
            }

            Log::error('Orange Money: Erreur lors de l\'obtention du token', [
                'status' => $response->status(),
                'response' => $response->body()
            ]);

            return null;

        } catch (Exception $e) {
            Log::error('Orange Money: Erreur lors de l\'obtention du token', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Vérifie le statut d'un paiement Orange Money
     */
    public function verifyPayment($pay_token)
    {
        try {
            $access_token = $this->getAccessToken();
            if (!$access_token) {
                return [
                    'success' => false,
                    'error' => 'Impossible d\'obtenir le token d\'accès'
                ];
            }

            $response = Http::withHeaders(array_merge($this->headers, [
                'Authorization' => 'Bearer ' . $access_token
            ]))
                ->timeout(30)
                ->get($this->base_url . '/orange-money-webpay/v1/payment/' . $pay_token);

            if ($response->successful()) {
                $payment_data = $response->json();
                
                // Vérification selon la documentation Orange Money
                if ($payment_data['status'] === 'SUCCESS') {
                    return [
                        'success' => true,
                        'payment' => $payment_data
                    ];
                } else {
                    // Gestion des erreurs de paiement selon la documentation
                    $error_message = 'Paiement échoué';
                    if (isset($payment_data['error_code'])) {
                        $error_message = $this->getOrangeMoneyErrorMessage($payment_data['error_code']);
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
                    $error_message = $this->getOrangeMoneyErrorMessage($error_data['error_code']);
                }
                
                return [
                    'success' => false,
                    'error' => $error_message
                ];
            }

        } catch (Exception $e) {
            Log::error('Orange Money Verify Payment Error: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => 'Erreur lors de la vérification du paiement'
            ];
        }
    }

    /**
     * Traitement du webhook de paiement
     */
    private function processWebhookPayment($payload)
    {
        try {
            $pay_token = $payload['pay_token'];
            $status = $payload['status'];
            
            // Recherche du paiement par pay_token
            $payment_data = $this->payment::where('transaction_id', $pay_token)->first();
            
            if ($payment_data && $status === 'SUCCESS') {
                $this->payment::where(['id' => $payment_data->id])->update([
                    'payment_method' => 'orange_money',
                    'is_paid' => 1,
                    'updated_at' => now()
                ]);

                $this->handleSuccessfulPayment($payment_data);
            }

        } catch (Exception $e) {
            Log::error('Orange Money Webhook Processing Error: ' . $e->getMessage());
        }
    }

    /**
     * Valide le montant du paiement
     */
    private function validatePaymentAmount($payment_data, $verification_data)
    {
        $currency = $payment_data->currency_code ?? 'XOF';
        
        if ($currency === 'XOF') {
            $expected_amount = (int) ($payment_data->payment_amount * 100);
            $received_amount = (int) $verification_data['amount'];
        } else {
            $expected_amount = (float) $payment_data->payment_amount;
            $received_amount = (float) $verification_data['amount'];
        }
        
        return $expected_amount === $received_amount;
    }

    /**
     * Valide le format des montants selon les règles strictes d'Orange Money
     */
    private function validateOrangeMoneyAmount($amount, $currency)
    {
        // Règles Orange Money pour les montants :
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
     * Retourne le message d'erreur Orange Money selon le code d'erreur
     */
    private function getOrangeMoneyErrorMessage($error_code)
    {
        $error_messages = [
            'INVALID_CREDENTIALS' => 'Identifiants Orange Money invalides',
            'INSUFFICIENT_FUNDS' => 'Fonds insuffisants sur le compte Orange Money',
            'INVALID_AMOUNT' => 'Montant invalide',
            'INVALID_CURRENCY' => 'Devise non supportée',
            'PAYMENT_FAILED' => 'Échec du paiement',
            'PAYMENT_CANCELLED' => 'Paiement annulé par l\'utilisateur',
            'PAYMENT_EXPIRED' => 'Paiement expiré',
            'INVALID_PHONE' => 'Numéro de téléphone invalide',
            'ACCOUNT_BLOCKED' => 'Compte Orange Money bloqué',
            'SERVICE_UNAVAILABLE' => 'Service Orange Money temporairement indisponible',
            'INVALID_MERCHANT' => 'Marchand invalide',
            'DUPLICATE_TRANSACTION' => 'Transaction en double',
            'INVALID_TOKEN' => 'Token de paiement invalide',
            'TIMEOUT' => 'Délai d\'attente dépassé',
            'NETWORK_ERROR' => 'Erreur de réseau'
        ];

        return $error_messages[$error_code] ?? 'Erreur Orange Money: ' . $error_code;
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
            Log::error('Orange Money Handle Successful Payment Error: ' . $e->getMessage());
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
            Log::warning("Orange Money: Impossible de récupérer la configuration {$gateway}", [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }
}