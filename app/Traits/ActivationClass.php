<?php

namespace App\Traits;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
// use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

trait ActivationClass
{
    public function is_local(): bool
    {
        $whitelist = array(
            '127.0.0.1',
            '::1'
        );

        if (!in_array(request()->ip(), $whitelist)) {
            return false;
        }

        return true;
    }

    public function getDomain(): string
    {
        return str_replace(["http://", "https://", "www."], "", url('/'));
    }

    public function getSystemAddonCacheKey(string|null $app = 'default'): string
    {
        $appName = env('APP_NAME').'_cache';
        return str_replace('-', '_', Str::slug($appName.'cache_system_addons_for_' . $app . '_' . $this->getDomain()));
    }

    public function getAddonsConfig(): array
    {
        if (file_exists(base_path('config/system-addons.php'))) {
            return include(base_path('config/system-addons.php'));
        }

        $apps = ['admin_panel', 'vendor_app', 'deliveryman_app', 'react_web'];
        $appConfig = [];
        foreach ($apps as $app) {
            $appConfig[$app] = [
                "active" => "0",
                "username" => "",
                "purchase_key" => "",
                "software_id" => "",
                "domain" => "",
                "software_type" => $app == 'admin_panel' ? "product" : 'addon',
            ];
        }
        return $appConfig;
    }

    public function getCacheTimeoutByDays(int $days = 3): int
    {
        return 60 * 60 * 24 * $days;
    }

    public function getRequestConfig(string|null $username = null, string|null $purchaseKey = null, string|null $softwareId = null, string|null $softwareType = null): array
    {
        $activeStatus = base64_encode(1);

        return [
            "active" => base64_decode($activeStatus),
            "username" => trim($username),
            "purchase_key" => $purchaseKey,
            "software_id" => $softwareId ?? SOFTWARE_ID,
            "domain" => $this->getDomain(),
            "software_type" => $softwareType,
        ];
    }

    public function checkActivationCache(string|null $app)
    {
        return true;
    }

    public function updateActivationConfig($app, $response): void
    {
        if('admin.business-settings.addon-activation.index' === \Illuminate\Support\Facades\Route::currentRouteName() ){
            return;
        }
        $config = $this->getAddonsConfig();
        $config[$app] = $response;
        $configContents = "<?php return " . var_export($config, true) . ";";
        file_put_contents(base_path('config/system-addons.php'), $configContents);
        $cacheKey = $this->getSystemAddonCacheKey(app: $app);
        Cache::forget($cacheKey);
    }
}
