<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AdminRentalModuleCheckMiddleware
{

    /**
     * @param Request $request
     * @param Closure $next
     * @return mixed|never
     */
    public function handle(Request $request, Closure $next)
    {
        if ((addon_published_status('Rental') && config('module.current_module_type') == 'rental' )||   $request->is('admin/rental/trip/details/*') ||  $request->is('admin/rental/provider/details/*')){
            return $next($request);
        }

        return abort(404);
    }
}
