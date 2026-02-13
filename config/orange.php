<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Orange Money Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration pour l'intégration Orange Money
    | Support des paiements en XOF, EUR, USD, GBP
    |
    */

    'mode' => env('ORANGE_MODE', 'test'), // test ou live

    'client_id' => env('ORANGE_CLIENT_ID', ''),

    'client_secret' => env('ORANGE_CLIENT_SECRET', ''),

    'merchant_id' => env('ORANGE_MERCHANT_ID', ''),

    'business_name' => env('ORANGE_BUSINESS_NAME', 'SIAME'),

    // URL de base de l'API (paiements).
    // Pour Sonatel Sénégal, la doc officielle indique :
    //  - Sandbox : https://api.sandbox.orange-sonatel.com
    //  - Live    : https://api.orange-sonatel.com
    //
    // On laisse la valeur par défaut vide pour que le contrôleur applique automatiquement
    // ces URLs Sonatel. Si vous souhaitez surcharger, définissez ORANGE_BASE_URL dans .env.
    'base_url' => env('ORANGE_BASE_URL', ''),

    'webhook_secret' => env('ORANGE_WEBHOOK_SECRET', ''),

    /*
    |--------------------------------------------------------------------------
    | URLs de Callback
    |--------------------------------------------------------------------------
    */
    'success_url' => env('ORANGE_SUCCESS_URL', ''),
    'error_url' => env('ORANGE_ERROR_URL', ''),
    'webhook_url' => env('ORANGE_WEBHOOK_URL', ''),

    /*
    |--------------------------------------------------------------------------
    | Configuration des Devises
    |--------------------------------------------------------------------------
    */
    'supported_currencies' => [
        'XOF' => [
            'name' => 'Franc CFA Ouest-Africain',
            'symbol' => 'FCFA',
            'decimal_places' => 0
        ],
        'EUR' => [
            'name' => 'Euro',
            'symbol' => '€',
            'decimal_places' => 2
        ],
        'USD' => [
            'name' => 'Dollar Américain',
            'symbol' => '$',
            'decimal_places' => 2
        ],
        'GBP' => [
            'name' => 'Livre Sterling',
            'symbol' => '£',
            'decimal_places' => 2
        ]
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration des Montants
    |--------------------------------------------------------------------------
    */
    'minimum_amount' => 100, // 1 XOF en centimes (selon documentation Orange Money)
    'maximum_amount' => 10000000, // 100,000 XOF en centimes

    /*
    |--------------------------------------------------------------------------
    | Timeout et Retry
    |--------------------------------------------------------------------------
    */
    'timeout' => 30, // secondes
    'retry_attempts' => 3,
    'retry_delay' => 1000, // millisecondes

    /*
    |--------------------------------------------------------------------------
    | Configuration des Sessions
    |--------------------------------------------------------------------------
    */
    'session_expiry' => 30, // minutes
    'auto_expire' => true,

    /*
    |--------------------------------------------------------------------------
    | Configuration des Logs
    |--------------------------------------------------------------------------
    */
    'log_channel' => 'daily',
    'log_level' => 'info',

    /*
    |--------------------------------------------------------------------------
    | Configuration OAuth2
    |--------------------------------------------------------------------------
    */
    'oauth' => [
        // Base URL pour le token (si vide, on utilise base_url ci-dessus). Sonatel peut avoir un FQDN différent.
        'base_url' => env('ORANGE_OAUTH_BASE_URL', ''),
        // Orange global: /oauth/v3/token. Sonatel utilise parfois /oauth/v2/token (voir doc ou contrat).
        'token_endpoint' => env('ORANGE_OAUTH_TOKEN_ENDPOINT', '/oauth/v3/token'),
        // Endpoint à essayer en secours si "Resource not found" (ex: Sonatel /oauth/v2/token)
        'token_endpoint_fallback' => env('ORANGE_OAUTH_TOKEN_ENDPOINT_FALLBACK', '/oauth/v2/token'),
        'grant_type' => 'client_credentials',
        'scope' => 'payment'
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration des Endpoints API
    |--------------------------------------------------------------------------
    */
    'endpoints' => [
        'payment' => '/orange-money-webpay/v1/payment',
        'verify' => '/orange-money-webpay/v1/payment/{pay_token}',
        'refund' => '/orange-money-webpay/v1/payment/{pay_token}/refund',
        'status' => '/orange-money-webpay/v1/payment/{pay_token}/status',
        // API Sonatel createPaymentQRCode (équivalent @sonatel-os/juf) — retourne deepLinks.MAXIT et deepLinks.OM
        'payment_qrcode' => env('ORANGE_PAYMENT_QRCODE_ENDPOINT', '/api/eWallet/v1/payments/qrcode'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration des Pays Supportés
    |--------------------------------------------------------------------------
    */
    'supported_countries' => [
        'SN' => 'Sénégal',
        'CI' => 'Côte d\'Ivoire',
        'ML' => 'Mali',
        'BF' => 'Burkina Faso',
        'NE' => 'Niger',
        'GN' => 'Guinée',
        'CM' => 'Cameroun',
        'CF' => 'République Centrafricaine',
        'JO' => 'Jordanie',
        'IQ' => 'Irak'
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration des Erreurs
    |--------------------------------------------------------------------------
    */
    'error_codes' => [
        'INVALID_CREDENTIALS' => 'Identifiants invalides',
        'INSUFFICIENT_FUNDS' => 'Fonds insuffisants',
        'INVALID_AMOUNT' => 'Montant invalide',
        'INVALID_CURRENCY' => 'Devise non supportée',
        'PAYMENT_FAILED' => 'Échec du paiement',
        'PAYMENT_CANCELLED' => 'Paiement annulé',
        'PAYMENT_EXPIRED' => 'Paiement expiré',
        'INVALID_PHONE' => 'Numéro de téléphone invalide',
        'ACCOUNT_BLOCKED' => 'Compte bloqué',
        'SERVICE_UNAVAILABLE' => 'Service indisponible',
        'INVALID_MERCHANT' => 'Marchand invalide',
        'DUPLICATE_TRANSACTION' => 'Transaction en double',
        'INVALID_TOKEN' => 'Token invalide',
        'TIMEOUT' => 'Délai dépassé',
        'NETWORK_ERROR' => 'Erreur de réseau'
    ]
];