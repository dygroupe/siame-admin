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

class PayDunyaController extends Controller
{
    use Processor;

    private $config_values;
    private PaymentRequest $payment;
    private $user;
    private $base_url;
    private $headers;

    public function __construct(PaymentRequest $payment, User $user)
    {
        $config = $this->payment_config('paydunya', 'payment_config');
        
        if (!is_null($config) && $config->mode == 'live') {
            $this->config_values = json_decode($config->live_values);
            $this->base_url = 'https://app.paydunya.com/api'; // CORRECT pour le mode LIVE
        } elseif (!is_null($config) && $config->mode == 'test') {
            $this->config_values = json_decode($config->test_values);
            $this->base_url = 'https://app.paydunya.com/sandbox-api'; // CORRECT pour le mode TEST
        } else {
            throw new Exception('Configuration PayDunya non trouvée ou invalide');
        }

        // Vérification des clés API requises
        if (empty($this->config_values->master_key) || 
            empty($this->config_values->public_key) || 
            empty($this->config_values->private_key) || 
            empty($this->config_values->token)) {
            throw new Exception('Clés API PayDunya manquantes ou invalides');
        }

        $this->payment = $payment;
        $this->user = $user;

        // Configuration des en-têtes HTTP selon la documentation officielle PayDunya
        $this->headers = [
            'PAYDUNYA-MASTER-KEY' => $this->config_values->master_key,
            'PAYDUNYA-PUBLIC-KEY' => $this->config_values->public_key,
            'PAYDUNYA-PRIVATE-KEY' => $this->config_values->private_key,
            'PAYDUNYA-TOKEN' => $this->config_values->token,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];

        // Log de la configuration pour débogage
        Log::info('PayDunya: Configuration initialisée', [
            'mode' => $config->mode,
            'base_url' => $this->base_url,
            'endpoint_create' => $this->base_url . '/v1/checkout-invoice/create',
            'endpoint_confirm' => $this->base_url . '/v1/checkout-invoice/confirm/[token]'
        ]);
    }

    /**
     * Initialise le processus de paiement PayDunya
     * Crée une facture de paiement et redirige vers la page de paiement
     */
    public function initialize(Request $request)
    {
        try {
            // Validation des données d'entrée
            $validator = Validator::make($request->all(), [
                'payment_id' => 'required|uuid'
            ]);

            if ($validator->fails()) {
                Log::error('PayDunya: Validation échouée', [
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
                Log::warning('PayDunya: Données de paiement non trouvées', [
                    'payment_id' => $request['payment_id']
                ]);
                
                return response()->json($this->response_formatter(GATEWAYS_DEFAULT_204), 200);
            }

            // Extraction des informations métier
            $business_name = $this->extractBusinessName($payment_data);
            $payer_info = json_decode($payment_data->payer_information, true);

            // Préparation de la requête PayDunya selon la documentation officielle
            $paydunya_request = [
                'invoice' => [
                    'items' => [
                        [
                            'name' => 'Paiement - ' . $business_name,
                            'quantity' => 1,
                            'unit_price' => (float) $payment_data->payment_amount,
                            'total_price' => (float) $payment_data->payment_amount,
                            'description' => 'Paiement ID: ' . $payment_data->id
                        ]
                    ],
                    'total_amount' => (float) $payment_data->payment_amount,
                    'description' => 'Paiement pour ' . $business_name,
                    'currency' => 'XOF' // Devise par défaut pour l'Afrique de l'Ouest
                ],
                'store' => [
                    'name' => $business_name
                ],
                'custom_data' => [
                    'payment_id' => $payment_data->id,
                    'payer_id' => $payment_data->payer_id ?? null,
                    'business_id' => $payment_data->business_id ?? null
                ],
                'actions' => [
                    'callback_url' => route('paydunya.callback', ['payment_id' => $payment_data->id]),
                    'cancel_url' => route('paydunya.callback', ['payment_id' => $payment_data->id, 'status' => 'cancelled']),
                    'return_url' => route('paydunya.callback', ['payment_id' => $payment_data->id, 'status' => 'return'])
                ]
            ];

            Log::info('PayDunya: Création de facture', [
                'payment_id' => $payment_data->id,
                'amount' => $payment_data->payment_amount,
                'business' => $business_name
            ]);

            // Appel à l'API PayDunya pour créer la facture
            $endpoint = '/v1/checkout-invoice/create';
            $full_url = $this->base_url . $endpoint;
            
            Log::info('PayDunya: Appel API', [
                'endpoint' => $endpoint,
                'full_url' => $full_url,
                'mode' => $config->mode ?? 'non défini',
                'headers' => $this->headers,
                'request_data' => $paydunya_request
            ]);
            
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->post($full_url, $paydunya_request);

            // Log de la réponse pour débogage
            Log::info('PayDunya: Réponse reçue', [
                'status_code' => $response->status(),
                'response_body' => $response->body(),
                'response_headers' => $response->headers()
            ]);

            if (!$response->successful()) {
                Log::error('PayDunya: Erreur API lors de la création de facture', [
                    'status_code' => $response->status(),
                    'response' => $response->body(),
                    'payment_id' => $payment_data->id
                ]);
                
                throw new Exception('Erreur lors de la création de la facture PayDunya: ' . $response->status());
            }

            $response_data = $response->json();
            
            // Vérification de la réponse PayDunya selon la documentation
            // PayDunya retourne response_code = "00" pour le succès
            if (!isset($response_data['response_code']) || $response_data['response_code'] !== '00') {
                Log::error('PayDunya: Échec de création de facture', [
                    'response' => $response_data,
                    'payment_id' => $payment_data->id
                ]);
                
                throw new Exception('Échec de création de facture PayDunya: ' . ($response_data['response_text'] ?? 'Erreur inconnue'));
            }

            // Mise à jour du paiement avec le token PayDunya
            $this->payment::where(['id' => $payment_data->id])->update([
                'transaction_id' => $response_data['token'],
                'payment_method' => 'paydunya'
            ]);

            Log::info('PayDunya: Facture créée avec succès', [
                'payment_id' => $payment_data->id,
                'token' => $response_data['token']
            ]);

            // Redirection vers la page de paiement PayDunya
            // PayDunya retourne l'URL complète dans response_text
            $checkout_url = $response_data['response_text'];
            
            Log::info('PayDunya: Redirection vers la page de paiement', [
                'payment_id' => $payment_data->id,
                'token' => $response_data['token'],
                'checkout_url' => $checkout_url
            ]);
            
            return redirect()->away($checkout_url);

        } catch (Exception $e) {
            Log::error('PayDunya: Erreur lors de l\'initialisation', [
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
     * Gère le callback de PayDunya après le paiement
     * Vérifie le statut du paiement et met à jour la base de données
     */
    public function callback(Request $request)
    {
        try {
            $payment_id = $request->get('payment_id');
            $status = $request->get('status', 'successful');
            $token = $request->get('token');

            Log::info('PayDunya: Callback reçu', [
                'payment_id' => $payment_id,
                'status' => $status,
                'token' => $token,
                'all_params' => $request->all()
            ]);

            if (empty($payment_id)) {
                Log::error('PayDunya: Callback sans payment_id');
                return response()->json(['success' => false, 'message' => 'Payment ID manquant'], 400);
            }

            // Récupération des données de paiement
            $payment_data = $this->payment::where(['id' => $payment_id])->first();
            
            if (!isset($payment_data)) {
                Log::error('PayDunya: Données de paiement non trouvées pour le callback', [
                    'payment_id' => $payment_id
                ]);
                return response()->json(['success' => false, 'message' => 'Paiement non trouvé'], 404);
            }

            if ($status === 'successful' && $token) {
                // Vérification du paiement avec l'API PayDunya
                $verification_response = $this->verifyPayment($token);
                
                if ($verification_response['success']) {
                    $invoice_data = $verification_response['invoice'];
                    
                    // Vérification du montant et du statut
                    if ($this->validatePaymentAmount($payment_data, $invoice_data)) {
                        // Mise à jour du statut de paiement
                        $this->payment::where(['id' => $payment_id])->update([
                            'payment_method' => 'paydunya',
                            'is_paid' => 1,
                            'transaction_id' => $token,
                            'updated_at' => now()
                        ]);

                        Log::info('PayDunya: Paiement confirmé avec succès', [
                            'payment_id' => $payment_id,
                            'token' => $token,
                            'amount_paid' => $invoice_data['total_amount']
                        ]);

                        // Exécution du hook de succès si disponible
                        if (isset($payment_data->success_hook) && function_exists($payment_data->success_hook)) {
                            try {
                                call_user_func($payment_data->success_hook, $payment_data);
                            } catch (Exception $hook_error) {
                                Log::error('PayDunya: Erreur lors de l\'exécution du hook de succès', [
                                    'error' => $hook_error->getMessage(),
                                    'payment_id' => $payment_id
                                ]);
                            }
                        }

                        return $this->payment_response($payment_data, 'success');
                    } else {
                        Log::warning('PayDunya: Montant du paiement invalide', [
                            'payment_id' => $payment_id,
                            'expected_amount' => $payment_data->payment_amount,
                            'paid_amount' => $invoice_data['total_amount'] ?? 'N/A'
                        ]);
                    }
                } else {
                    Log::error('PayDunya: Échec de vérification du paiement', [
                        'payment_id' => $payment_id,
                        'token' => $token,
                        'verification_response' => $verification_response
                    ]);
                }
            } else {
                Log::info('PayDunya: Paiement annulé ou échoué', [
                    'payment_id' => $payment_id,
                    'status' => $status
                ]);
            }

            // Exécution du hook d'échec si disponible
            if (isset($payment_data->failure_hook) && function_exists($payment_data->failure_hook)) {
                try {
                    call_user_func($payment_data->failure_hook, $payment_data);
                } catch (Exception $hook_error) {
                    Log::error('PayDunya: Erreur lors de l\'exécution du hook d\'échec', [
                        'error' => $hook_error->getMessage(),
                        'payment_id' => $payment_id
                    ]);
                }
            }

            return $this->payment_response($payment_data, 'fail');

        } catch (Exception $e) {
            Log::error('PayDunya: Erreur lors du callback', [
                'error' => $e->getMessage(),
                'payment_id' => $request->get('payment_id'),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors du traitement du callback: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Vérifie le statut d'un paiement avec l'API PayDunya
     */
    private function verifyPayment($token)
    {
        try {
            $response = Http::withHeaders($this->headers)
                ->timeout(30)
                ->get($this->base_url . '/v1/checkout-invoice/confirm/' . $token);

            if (!$response->successful()) {
                Log::error('PayDunya: Erreur lors de la vérification du paiement', [
                    'status_code' => $response->status(),
                    'response' => $response->body(),
                    'token' => $token
                ]);
                
                return ['success' => false, 'message' => 'Erreur API: ' . $response->status()];
            }

            $response_data = $response->json();
            
            if (isset($response_data['success']) && $response_data['success']) {
                return [
                    'success' => true,
                    'invoice' => $response_data['invoice'] ?? []
                ];
            }

            return [
                'success' => false,
                'message' => $response_data['message'] ?? 'Vérification échouée'
            ];

        } catch (Exception $e) {
            Log::error('PayDunya: Exception lors de la vérification du paiement', [
                'error' => $e->getMessage(),
                'token' => $token
            ]);
            
            return ['success' => false, 'message' => 'Exception: ' . $e->getMessage()];
        }
    }

    /**
     * Valide que le montant payé correspond au montant attendu
     */
    private function validatePaymentAmount($payment_data, $invoice_data)
    {
        $expected_amount = (float) $payment_data->payment_amount;
        $paid_amount = (float) ($invoice_data['total_amount'] ?? 0);
        
        // Tolérance de 1 centime pour les arrondis
        $tolerance = 0.01;
        
        return abs($paid_amount - $expected_amount) <= $tolerance;
    }

    /**
     * Extrait le nom de l'entreprise depuis les données de paiement
     */
    private function extractBusinessName($payment_data)
    {
        if ($payment_data->additional_data) {
            $business = json_decode($payment_data->additional_data, true);
            return $business['business_name'] ?? 'Mon Entreprise';
        }
        
        return 'Mon Entreprise';
    }

    /**
     * Méthode de test simple pour vérifier la configuration
     */
    public function testConfig()
    {
        try {
            $config_info = [
                'base_url' => $this->base_url,
                'mode' => 'configuré',
                'config_keys' => array_keys((array) $this->config_values),
                'headers_count' => count($this->headers),
                'endpoint_test' => $this->base_url . '/v1/checkout-invoice/create'
            ];

            return response()->json([
                'success' => true,
                'message' => 'Configuration PayDunya OK',
                'data' => $config_info
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Erreur lors du test: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Méthode de test de connexion API
     */
    public function testApi()
    {
        try {
            // Test simple de connexion
            $response = Http::withHeaders($this->headers)
                ->timeout(10)
                ->get($this->base_url . '/v1/status');

            return response()->json([
                'success' => true,
                'message' => 'Test API réussi',
                'data' => [
                    'status_code' => $response->status(),
                    'response' => $response->body(),
                    'endpoint' => $this->base_url . '/v1/status'
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Test API échoué: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Gère les webhooks IPN (Instant Payment Notification) de PayDunya
     * Cette méthode est appelée automatiquement par PayDunya pour confirmer les paiements
     */
    public function webhook(Request $request)
    {
        try {
            Log::info('PayDunya: Webhook IPN reçu', [
                'headers' => $request->headers->all(),
                'body' => $request->all()
            ]);

            // Vérification de l'authenticité du webhook (à implémenter selon la documentation PayDunya)
            if (!$this->verifyWebhookSignature($request)) {
                Log::warning('PayDunya: Signature webhook invalide');
                return response()->json(['success' => false, 'message' => 'Signature invalide'], 400);
            }

            $webhook_data = $request->all();
            
            // Traitement du webhook selon le type d'événement
            if (isset($webhook_data['event_type'])) {
                switch ($webhook_data['event_type']) {
                    case 'invoice.completed':
                        return $this->handleInvoiceCompleted($webhook_data);
                    
                    case 'invoice.cancelled':
                        return $this->handleInvoiceCancelled($webhook_data);
                    
                    case 'invoice.failed':
                        return $this->handleInvoiceFailed($webhook_data);
                    
                    default:
                        Log::info('PayDunya: Type d\'événement webhook non géré', [
                            'event_type' => $webhook_data['event_type']
                        ]);
                        return response()->json(['success' => true, 'message' => 'Événement ignoré']);
                }
            }

            return response()->json(['success' => true, 'message' => 'Webhook traité']);

        } catch (Exception $e) {
            Log::error('PayDunya: Erreur lors du traitement du webhook', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Vérifie la signature du webhook pour s'assurer de son authenticité
     */
    private function verifyWebhookSignature(Request $request)
    {
        // Implémentation de la vérification de signature selon la documentation PayDunya
        // Cette méthode doit être adaptée selon les spécifications exactes de PayDunya
        
        $signature = $request->header('X-PayDunya-Signature');
        $payload = $request->getContent();
        
        if (empty($signature) || empty($payload)) {
            return false;
        }

        // Calcul de la signature attendue
        $expected_signature = hash_hmac('sha256', $payload, $this->config_values->token);
        
        return hash_equals($expected_signature, $signature);
    }

    /**
     * Gère l'événement de facture complétée
     */
    private function handleInvoiceCompleted($webhook_data)
    {
        $token = $webhook_data['invoice']['token'] ?? null;
        
        if ($token) {
            // Mise à jour du statut de paiement
            $payment_data = $this->payment::where(['transaction_id' => $token])->first();
            
            if ($payment_data && !$payment_data->is_paid) {
                $this->payment::where(['id' => $payment_data->id])->update([
                    'is_paid' => 1,
                    'updated_at' => now()
                ]);

                Log::info('PayDunya: Paiement confirmé via webhook', [
                    'payment_id' => $payment_data->id,
                    'token' => $token
                ]);

                // Exécution du hook de succès
                if (isset($payment_data->success_hook) && function_exists($payment_data->success_hook)) {
                    call_user_func($payment_data->success_hook, $payment_data);
                }
            }
        }

        return response()->json(['success' => true, 'message' => 'Facture complétée traitée']);
    }

    /**
     * Gère l'événement de facture annulée
     */
    private function handleInvoiceCancelled($webhook_data)
    {
        $token = $webhook_data['invoice']['token'] ?? null;
        
        if ($token) {
            $payment_data = $this->payment::where(['transaction_id' => $token])->first();
            
            if ($payment_data) {
                Log::info('PayDunya: Paiement annulé via webhook', [
                    'payment_id' => $payment_data->id,
                    'token' => $token
                ]);
            }
        }

        return response()->json(['success' => true, 'message' => 'Facture annulée traitée']);
    }

    /**
     * Gère l'événement de facture échouée
     */
    private function handleInvoiceFailed($webhook_data)
    {
        $token = $webhook_data['invoice']['token'] ?? null;
        
        if ($token) {
            $payment_data = $this->payment::where(['transaction_id' => $token])->first();
            
            if ($payment_data) {
                Log::info('PayDunya: Paiement échoué via webhook', [
                    'payment_id' => $payment_data->id,
                    'token' => $token
                ]);
            }
        }

        return response()->json(['success' => true, 'message' => 'Facture échouée traitée']);
    }
}
