<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Wave Mobile Money Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration pour l'intégration Wave Mobile Money
    | Support des paiements en XOF, EUR, USD, GBP
    |
    */

    'mode' => env('WAVE_MODE', 'test'), // test ou live

    'api_key' => env('WAVE_API_KEY', ''),

    'business_name' => env('WAVE_BUSINESS_NAME', 'SIAME'),

    'base_url' => env('WAVE_BASE_URL', 'https://api.wave.com'),

    'webhook_secret' => env('WAVE_WEBHOOK_SECRET', ''),

    /*
    |--------------------------------------------------------------------------
    | URLs de Callback
    |--------------------------------------------------------------------------
    */
    'success_url' => env('WAVE_SUCCESS_URL', ''),
    'error_url' => env('WAVE_ERROR_URL', ''),
    'webhook_url' => env('WAVE_WEBHOOK_URL', ''),

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
    'minimum_amount' => 100, // 1 XOF en centimes (selon documentation Wave)
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
    | Logging
    |--------------------------------------------------------------------------
    */
    'log_requests' => env('WAVE_LOG_REQUESTS', true),
    'log_responses' => env('WAVE_LOG_RESPONSES', true),
    'log_webhooks' => env('WAVE_LOG_WEBHOOKS', true),

    /*
    |--------------------------------------------------------------------------
    | Configuration des Webhooks
    |--------------------------------------------------------------------------
    */
    'webhook_events' => [
        'checkout.session.completed',
        'checkout.session.expired',
        'checkout.payment.succeeded',
        'checkout.payment.failed'
    ],

    /*
    |--------------------------------------------------------------------------
    | Configuration des Erreurs
    |--------------------------------------------------------------------------
    */
    'error_messages' => [
        'authorization-error' => 'Clé API manquante ou invalide',
        'missing-auth-header' => 'En-tête d\'autorisation manquant',
        'checkout-session-not-found' => 'Session de checkout non trouvée',
        'request-validation-error' => 'Erreur de validation de la requête',
        'service-unavailable' => 'Service temporairement indisponible',
        'unauthorized-wallet' => 'Portefeuille non autorisé',
        'insufficient-funds' => 'Fonds insuffisants',
        'blocked-account' => 'Compte bloqué',
        'payment-failure' => 'Échec du paiement'
    ]
];