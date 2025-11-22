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

    'base_url' => env('ORANGE_BASE_URL', 'https://api.orange.com'),

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
        'token_endpoint' => '/oauth/v2/token',
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
        'status' => '/orange-money-webpay/v1/payment/{pay_token}/status'
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