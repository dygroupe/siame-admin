<?php

/*
 * Configuration PayDunya pour SIAME.SOURCE.3.3
 *
 * PayDunya - Payment Gateway for West Africa
 * Documentation: https://developers.paydunya.com/doc/FR/introduction
 */

return [

    /**
     * Master Key: Votre clé maître PayDunya
     * Obtenez-la sur https://app.paydunya.com dans votre dashboard
     */
    'master_key' => env('PAYDUNYA_MASTER_KEY'),

    /**
     * Public Key: Votre clé publique PayDunya
     * Obtenez-la sur https://app.paydunya.com dans votre dashboard
     */
    'public_key' => env('PAYDUNYA_PUBLIC_KEY'),

    /**
     * Private Key: Votre clé privée PayDunya
     * Obtenez-la sur https://app.paydunya.com dans votre dashboard
     */
    'private_key' => env('PAYDUNYA_PRIVATE_KEY'),

    /**
     * Token: Votre token PayDunya pour la vérification des webhooks
     * Obtenez-le sur https://app.paydunya.com dans votre dashboard
     */
    'token' => env('PAYDUNYA_TOKEN', ''),

    /**
     * Mode: Test ou Live environment
     * - 'test' : Mode de test (développement)
     * - 'live' : Mode production (IMPORTANT: changer pour la production)
     */
    'mode' => env('PAYDUNYA_MODE', 'test'),

    /**
     * Base URL: URL de base de l'API PayDunya
     * Note: PayDunya utilise la même URL pour test et production
     */
    'base_url' => 'https://app.paydunya.com',

    /**
     * Timeout: Délai d'attente pour les requêtes API (en secondes)
     */
    'timeout' => env('PAYDUNYA_TIMEOUT', 30),

    /**
     * Devise par défaut pour l'Afrique de l'Ouest
     */
    'currency' => env('PAYDUNYA_CURRENCY', 'XOF'),

    /**
     * Webhook URL: URL de votre webhook (configurée automatiquement)
     */
    'webhook_url' => env('PAYDUNYA_WEBHOOK_URL', null),

    /**
     * Callback URL: URL de retour après paiement (configurée automatiquement)
     */
    'callback_url' => env('PAYDUNYA_CALLBACK_URL', null),

    /**
     * Logging: Activer/désactiver le logging détaillé
     */
    'logging' => env('PAYDUNYA_LOGGING', true),

    /**
     * Debug: Mode debug pour le développement
     */
    'debug' => env('PAYDUNYA_DEBUG', false),
];
