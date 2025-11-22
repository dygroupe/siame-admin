<?php


use Illuminate\Support\Facades\Route;
use Modules\AI\app\Http\Controllers\AIController;
use Modules\AI\app\Factory\AIEngineFactory;
use Modules\AI\app\Constants\AIEngine;
use Illuminate\Http\Request;
use Modules\AI\app\Services\ProductAutoFillService;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::group([], function () {
    Route::resource('ai', AIController::class)->names('ai');
});

Route::get('/test-ai', function (Request $request) {
$imageUrl = "https://assets.aboutamazon.com/dims4/default/e62894c/2147483647/strip/true/crop/1279x720+0+0/resize/2480x1396!/format/webp/quality/90/?url=https%3A%2F%2Famazon-blogs-brightspot.s3.amazonaws.com%2Ff9%2F25%2Fe4aa62e5408ca8764934782e7010%2Fcombo-1280x720.jpg";

        $service = new ProductAutoFillService();
        $result = $service->askQuestion("Hello");

        return response()->json([
            'success' => true,
            'data' => $result
        ]);

});
