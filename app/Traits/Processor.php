<?php

namespace App\Traits;

use Exception;
use App\Models\Setting;
use App\Models\PaymentRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\App;
use Illuminate\Http\RedirectResponse;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Storage;

trait  Processor
{
    public function response_formatter($constant, $content = null, $errors = []): array
    {
        $constant = (array)$constant;
        $constant['content'] = $content;
        $constant['errors'] = $errors;
        return $constant;
    }

    public function error_processor($validator): array
    {
        $errors = [];
        foreach ($validator->errors()->getMessages() as $index => $error) {
            $errors[] = ['error_code' => $index, 'message' => self::translate($error[0])];
        }
        return $errors;
    }

    public function translate($key)
    {
        try {
            App::setLocale('en');
            $lang_array = include(base_path('resources/lang/' . 'en' . '/lang.php'));
            $processed_key = ucfirst(str_replace('_', ' ', str_ireplace(['\'', '"', ',', ';', '<', '>', '?'], ' ', $key)));
            if (!array_key_exists($key, $lang_array)) {
                $lang_array[$key] = $processed_key;
                $str = "<?php return " . var_export($lang_array, true) . ";";
                file_put_contents(base_path('resources/lang/' . 'en' . '/lang.php'), $str);
                $result = $processed_key;
            } else {
                $result = __('lang.' . $key);
            }
            return $result;
        } catch (\Exception $exception) {
            return $key;
        }
    }

    public function payment_config($key, $settings_type): object|null
    {
        try {
            $config = DB::table('addon_settings')->where('key_name', $key)
                ->where('settings_type', $settings_type)->first();
        } catch (Exception $exception) {
            return new Setting();
        }

        return (isset($config)) ? $config : null;
    }
    public static function getDisk()
    {
        $config=\App\CentralLogics\Helpers::get_business_settings('local_storage');

        return isset($config)?($config==0?'s3':'public'):'public';
    }
    public function file_uploader(string $dir, string $format, $image = null, $old_image = null)
    {
        if ($image == null) return $old_image ?? 'def.png';

        if (isset($old_image)) Storage::disk(self::getDisk())->delete($dir . $old_image);

        $imageName = \Carbon\Carbon::now()->toDateString() . "-" . uniqid() . "." . $format;
        if (!Storage::disk(self::getDisk())->exists($dir)) {
            Storage::disk(self::getDisk())->makeDirectory($dir);
        }
        Storage::disk(self::getDisk())->put($dir . $imageName, file_get_contents($image));

        return $imageName;
    }

    public function payment_response($payment_info, $payment_flag): Application|JsonResponse|Redirector|RedirectResponse|\Illuminate\Contracts\Foundation\Application
    {
        $payment_info = PaymentRequest::find($payment_info->id);
        $token_string = 'payment_method=' . $payment_info->payment_method . '&&attribute_id=' . $payment_info->attribute_id . '&&transaction_reference=' . $payment_info->transaction_id;

        // App mobile (Siame) : redirection vers le deep link siame://payment
        if ($payment_info->payment_platform === 'app') {
            $deepLink = $this->buildSiamePaymentDeepLink($payment_info, $payment_flag);
            if ($deepLink !== null) {
                return redirect()->away($deepLink);
            }
            // Fallback : si pas de deep link (ex. attribute_id manquant), utiliser external_redirect_link ou page web
        }

        if (in_array($payment_info->payment_platform, ['web', 'app']) && $payment_info['external_redirect_link'] != null) {
            return redirect($payment_info['external_redirect_link'] . '?flag=' . $payment_flag . '&&token=' . base64_encode($token_string));
        }
        return redirect()->route('payment-' . $payment_flag, ['token' => base64_encode($token_string)]);
    }

    /**
     * Construit l'URL de deep link pour l'app Siame après paiement (Wave, Orange Money, etc.).
     * Format : siame://payment?status=STATUS&order_id=ORDER_ID&contact_number=NUMBER&guest_id=GUEST_ID&create_account=BOOLEAN
     */
    protected function buildSiamePaymentDeepLink(PaymentRequest $payment_info, string $payment_flag): ?string
    {
        $status = match ($payment_flag) {
            'success' => 'success',
            'fail' => 'failed',
            'cancel' => 'cancel',
            default => 'failed',
        };

        $order_id = $payment_info->attribute_id ?? '';
        if ($order_id === '' || $order_id === null) {
            return null;
        }

        $payer = is_string($payment_info->payer_information)
            ? json_decode($payment_info->payer_information, true)
            : (array) $payment_info->payer_information;
        $additional = is_string($payment_info->additional_data)
            ? json_decode($payment_info->additional_data, true)
            : (array) ($payment_info->additional_data ?? []);
        // contact_number : priorité à la valeur envoyée par l'app, sinon payer.phone
        $contact_number = $additional['contact_number'] ?? $payer['phone'] ?? '';
        $guest_id = $additional['guest_id'] ?? '';
        $create_account = isset($additional['create_account'])
            ? ($additional['create_account'] ? 'true' : 'false')
            : 'false';

        $params = [
            'status' => $status,
            'order_id' => $order_id,
            'contact_number' => $contact_number,
            'guest_id' => $guest_id,
            'create_account' => $create_account,
        ];

        return 'siame://payment?' . http_build_query($params);
    }
}
