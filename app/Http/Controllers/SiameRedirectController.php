<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

/**
 * Page intermédiaire pour ramener l'utilisateur vers l'app Siame après paiement
 * (Wave, Orange Money). Utilisée quand Wave/OM redirigent vers notre callback :
 * on affiche une page avec bouton cliquable car les WebViews de Wave/OM
 * bloquent souvent les redirections automatiques vers siame://
 */
class SiameRedirectController extends Controller
{
    public function payment(Request $request)
    {
        $status = $request->query('status', 'failed');
        $orderId = $request->query('order_id', '');
        $contactNumber = $request->query('contact_number', '');
        $guestId = $request->query('guest_id', '');
        $createAccount = $request->query('create_account', 'false');

        // order_id et status sont OBLIGATOIRES pour que l'app Flutter traite le deep link
        $params = [
            'order_id' => $orderId !== '' && $orderId !== null ? $orderId : '0',
            'status' => in_array($status, ['success', 'failed', 'cancel', 'fail'], true) ? $status : 'failed',
        ];
        if ($contactNumber !== '' && $contactNumber !== null) {
            $params['contact_number'] = $contactNumber;
        }
        if ($guestId !== '' && $guestId !== null) {
            $params['guest_id'] = $guestId;
        }
        if ($createAccount !== '' && $createAccount !== null && $createAccount !== 'false') {
            $params['create_account'] = $createAccount;
        }

        $deepLink = 'siame://payment?' . http_build_query($params);

        $siamePackage = env('SIAME_APP_PACKAGE', '');

        return response()->view('payment-views.siame-open-app', [
            'deep_link' => $deepLink,
            'status' => $status,
            'siame_app_package' => $siamePackage,
        ])->header('Cache-Control', 'no-cache, no-store');
    }
}
