<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="1;url={{ e($deep_link) }}">
    <title>Retour à Siame</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700&display=swap" rel="stylesheet">
    <style>
        :root {
            --success-bg: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 50%, #a7f3d0 100%);
            --success-accent: #059669;
            --success-accent-hover: #047857;
            --success-glow: rgba(5, 150, 105, 0.25);
            --failed-bg: linear-gradient(135deg, #fef2f2 0%, #fee2e2 50%, #fecaca 100%);
            --failed-accent: #dc2626;
            --failed-accent-hover: #b91c1c;
            --failed-glow: rgba(220, 38, 38, 0.2);
            --cancel-bg: linear-gradient(135deg, #fffbeb 0%, #fef3c7 50%, #fde68a 100%);
            --cancel-accent: #d97706;
            --cancel-accent-hover: #b45309;
            --cancel-glow: rgba(217, 119, 6, 0.2);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            transition: background 0.5s ease;
        }
        body.success { background: var(--success-bg); }
        body.failed, body.cancel { background: var(--failed-bg); }
        body.cancel { background: var(--cancel-bg); }

        .page {
            width: 100%;
            max-width: 420px;
            animation: fadeUp 0.6s ease-out;
        }
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(24px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 2.5rem 2rem;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 10px 40px -10px rgba(0, 0, 0, 0.12), 0 0 0 1px rgba(0, 0, 0, 0.03);
        }
        .card.success { box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 10px 40px -10px var(--success-glow), 0 0 0 1px rgba(0, 0, 0, 0.03); }
        .card.failed { box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 10px 40px -10px var(--failed-glow), 0 0 0 1px rgba(0, 0, 0, 0.03); }
        .card.cancel { box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 10px 40px -10px var(--cancel-glow), 0 0 0 1px rgba(0, 0, 0, 0.03); }

        .icon-wrap {
            width: 88px;
            height: 88px;
            margin: 0 auto 1.5rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .icon-wrap::before {
            content: '';
            position: absolute;
            inset: -4px;
            border-radius: 50%;
            opacity: 0.4;
        }
        .icon-wrap.success { background: linear-gradient(135deg, #d1fae5, #a7f3d0); }
        .icon-wrap.success::before { background: var(--success-accent); filter: blur(12px); }
        .icon-wrap.failed { background: linear-gradient(135deg, #fee2e2, #fecaca); }
        .icon-wrap.failed::before { background: var(--failed-accent); filter: blur(12px); }
        .icon-wrap.cancel { background: linear-gradient(135deg, #fef3c7, #fde68a); }
        .icon-wrap.cancel::before { background: var(--cancel-accent); filter: blur(12px); }

        .icon-wrap svg {
            position: relative;
            z-index: 1;
            width: 44px;
            height: 44px;
        }
        .icon-wrap svg path {
            stroke-dasharray: 100;
            stroke-dashoffset: 100;
            animation: drawIcon 0.8s ease-out 0.3s forwards;
        }
        .icon-wrap.failed svg path, .icon-wrap.cancel svg path {
            stroke-dasharray: 80;
            stroke-dashoffset: 80;
        }
        @keyframes drawIcon {
            to { stroke-dashoffset: 0; }
        }

        .title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }
        .description {
            font-size: 1rem;
            color: #6b7280;
            line-height: 1.6;
            margin-bottom: 1.75rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 1rem 2rem;
            font-family: inherit;
            font-size: 1rem;
            font-weight: 600;
            color: #fff !important;
            text-decoration: none;
            border: none;
            border-radius: 14px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        .btn:active { transform: translateY(0); }
        .btn.success { background: linear-gradient(135deg, #059669, #047857); }
        .btn.success:hover { background: linear-gradient(135deg, #047857, #065f46); }
        .btn.failed, .btn.cancel { background: linear-gradient(135deg, #2563eb, #1d4ed8); }
        .btn.failed:hover, .btn.cancel:hover { background: linear-gradient(135deg, #1d4ed8, #1e40af); }

        .btn svg {
            width: 20px;
            height: 20px;
        }
        .countdown {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid rgba(0, 0, 0, 0.06);
        }
        .countdown-bar {
            height: 4px;
            background: #e5e7eb;
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 0.75rem;
        }
        .countdown-fill {
            height: 100%;
            border-radius: 2px;
            animation: shrink 1s linear forwards;
        }
        .countdown-fill.success { background: var(--success-accent); }
        .countdown-fill.failed, .countdown-fill.cancel { background: #6366f1; }
        @keyframes shrink {
            from { width: 100%; }
            to { width: 0%; }
        }
        .countdown-text {
            font-size: 0.8125rem;
            color: #9ca3af;
        }
        .countdown-fallback {
            font-size: 0.8rem;
            color: #9ca3af;
            margin-top: 0.5rem;
            line-height: 1.4;
        }

        .brand {
            margin-top: 2rem;
            font-size: 0.75rem;
            color: #9ca3af;
            font-weight: 500;
        }
    </style>
</head>
@php
    $statusKey = strtolower($status ?? 'failed');
    if ($statusKey === 'fail') $statusKey = 'failed';
    $messages = [
            'success' => [
                'title' => 'Paiement réussi',
                'description' => 'Votre paiement a été effectué avec succès. Retournez à l\'application Siame pour voir votre commande.',
            ],
            'failed' => [
                'title' => 'Paiement échoué',
                'description' => 'Votre paiement n\'a pas abouti. Retournez à l\'application Siame pour réessayer ou choisir une autre méthode de paiement.',
            ],
            'cancel' => [
                'title' => 'Paiement annulé',
                'description' => 'Le paiement a été annulé. Retournez à l\'application Siame pour réessayer si vous le souhaitez.',
            ],
    ];
    $msg = $messages[$statusKey] ?? $messages['failed'];
    $cardClass = $statusKey === 'success' ? 'success' : ($statusKey === 'cancel' ? 'cancel' : 'failed');
@endphp
<body class="{{ $cardClass }}">
    <div class="page">
        <div class="card {{ $cardClass }}">
            <div class="icon-wrap {{ $cardClass }}">
                @if($cardClass === 'success')
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20 6L9 17l-5-5"/>
                    </svg>
                @else
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 6L6 18M6 6l12 12"/>
                    </svg>
                @endif
            </div>
            <h1 class="title">{{ $msg['title'] }}</h1>
            <p class="description">{{ $msg['description'] }}</p>
            <a id="open-app" href="{{ $deep_link }}" class="btn {{ $cardClass }}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                    <polyline points="15 3 21 3 21 9"/>
                    <line x1="10" y1="14" x2="21" y2="3"/>
                </svg>
                Ouvrir l'application Siame
            </a>
            <div class="countdown">
                <div class="countdown-bar">
                    <div class="countdown-fill {{ $cardClass }}"></div>
                </div>
                <p class="countdown-text">Redirection automatique dans quelques secondes…</p>
                <p class="countdown-fallback">Si l'application ne s'ouvre pas, rouvrez-la manuellement pour voir le résultat du paiement.</p>
            </div>
        </div>
        <p class="brand">Siame · Paiement sécurisé</p>
    </div>

    <script>
        (function() {
            var params = new URLSearchParams(window.location.search);
            var orderId = params.get('order_id') || '';
            var status = params.get('status') || 'success';
            var contactNumber = params.get('contact_number') || '';
            var guestId = params.get('guest_id') || '';
            var createAccount = params.get('create_account') || '';

            var query = 'order_id=' + encodeURIComponent(orderId || '0') + '&status=' + encodeURIComponent(status);
            if (contactNumber) query += '&contact_number=' + encodeURIComponent(contactNumber);
            if (guestId) query += '&guest_id=' + encodeURIComponent(guestId);
            if (createAccount) query += '&create_account=' + encodeURIComponent(createAccount);

            var base;
            var siamePackage = {{ json_encode($siame_app_package ?? '') }};
            var isAndroid = /Android/i.test(navigator.userAgent);

            if (isAndroid && siamePackage) {
                var fallbackUrl = window.location.href;
                base = 'intent://payment?' + query + '#Intent;scheme=siame;package=' + encodeURIComponent(siamePackage) + ';S.browser_fallback_url=' + encodeURIComponent(fallbackUrl) + ';end';
            } else {
                base = 'siame://payment?' + query;
            }

            var openAppLink = document.getElementById('open-app');
            if (openAppLink) openAppLink.href = base;

            // Redirection automatique vers l'app dès l'arrivée sur la page (après clic "Retourner" dans Wave).
            // Évite un second clic sur notre page ; si le schéma est bloqué (WebView), le meta refresh 1s ou le bouton restent disponibles.
            setTimeout(function() {
                try { window.location.href = base; } catch (e) {}
            }, 350);
        })();
    </script>
</body>
</html>
