<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Validator;
use App\Models\PaymentRequest;
use App\Traits\Processor;

class PaytechController extends Controller
{
    use Processor;

    private $config_values;

    private PaymentRequest $payment;
    private $user;

    public function __construct(PaymentRequest $payment, User $user)
    {
        $config = $this->payment_config('paytech', 'payment_config');
        if (!is_null($config) && $config->mode == 'live') {
            $this->config_values = json_decode($config->live_values);
        } elseif (!is_null($config) && $config->mode == 'test') {
            $this->config_values = json_decode($config->test_values);
        }

        $this->payment = $payment;
        $this->user = $user;
    }

    public function initialize(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'payment_id' => 'required|uuid'
        ]);

        if ($validator->fails()) {
            return response()->json($this->response_formatter(GATEWAYS_DEFAULT_400, null, $this->error_processor($validator)), 400);
        }

        $data = $this->payment::where(['id' => $request['payment_id']])->where(['is_paid' => 0])->first();
        if (!isset($data)) {
            return response()->json($this->response_formatter(GATEWAYS_DEFAULT_204), 200);
        }

        if ($data['additional_data'] != null) {
            $business = json_decode($data['additional_data']);
            $business_name = $business->business_name ?? "my_business";
        } else {
            $business_name = "my_business";
        }
        $payer = json_decode($data['payer_information']);

        $requestPayload = [
            'payment_id' => (string) $data->id,
            'item_name' => $business_name,
            'item_price' => $data->payment_amount,
            'ref_command' => $data->id,
            'command_name' => "Paiement de " . $business_name,
            'currency' => $data->currency_code ?? 'XOF',
            'env' => $this->config_values->env ?? 'test',
            'custom_field' => json_encode([
                'payer_email' => $payer->email ?? null,
                'payer_name' => $payer->name ?? null,
            ]),
            'ipn_url' => route('paytech.ipn'),
            'success_url' => route('paytech.callback', ['payment_id' => $data->id]),
            'cancel_url' => route('paytech.cancel', ['payment_id' => $data->id])
        ];

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://paytech.sn/api/payment/request-payment",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($requestPayload),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'API_KEY: ' . $this->config_values->api_key,
                'API_SECRET: ' . $this->config_values->api_secret,
            ],
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        $res = json_decode($response);

        if (isset($res->success) && $res->success && isset($res->redirect_url)) {
            return redirect()->away($res->redirect_url);
        }

        return 'Impossible de traiter votre paiement avec PayTech';
    }

    public function callback(Request $request){
        
    $payment = $this->payment::where('id', $request['payment_id'])->first();

    if (!$payment) {
        return $this->payment_response(null, 'fail');
    }

    if ($request['status'] === 'success') {
        $this->payment::where('id', $request['payment_id'])->update([
            'payment_method' => 'paytech',
            'is_paid' => 1,
            'transaction_id' => $request['token'] ?? null,
        ]);

        $payment = $this->payment::find($payment->id);

        if (isset($payment) && function_exists($payment->success_hook)) {
            call_user_func($payment->success_hook, $payment);
        }

        //Préparation des données de redirection comme PayDunya
        $payerInfo = json_decode($payment->payer_information ?? '{}');
        $orderId = $payment->order_id ?? null;
        $phone = $payerInfo->phone ?? '';
        $guestId = $payerInfo->guest_id ?? '';
        $createAccount = $payerInfo->create_account ?? false;

        $redirectUrl = url('https://siame.shop/order-successful') . '?' . http_build_query([
            'id' => $orderId,
            'contact_number' => $phone,
            'create_account' => $createAccount ? 'true' : 'false',
            'guest_id' => $guestId,
        ]);

        return redirect()->away($redirectUrl);
    }

    if (isset($payment) && function_exists($payment->failure_hook)) {
        call_user_func($payment->failure_hook, $payment);
    }

    return $this->payment_response($payment, 'fail');
}


    public function cancel(Request $request)
    {
        $payment = $this->payment::where('id', $request['payment_id'])->first();

        if (isset($payment) && function_exists($payment->failure_hook)) {
            call_user_func($payment->failure_hook, $payment);
        }

        return 'Paiement annulé par l’utilisateur';
    }

    public function ipn(Request $request)
    {
        // Traitement IPN éventuel (notification de paiement)
        return response()->json(['message' => 'IPN reçue'], 200);
    }
}
