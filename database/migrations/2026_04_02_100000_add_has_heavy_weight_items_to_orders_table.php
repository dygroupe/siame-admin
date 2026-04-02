<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('orders') && ! Schema::hasColumn('orders', 'has_heavy_weight_items')) {
            Schema::table('orders', function (Blueprint $table) {
                $table->boolean('has_heavy_weight_items')->default(false)->after('dm_vehicle_id');
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('orders') && Schema::hasColumn('orders', 'has_heavy_weight_items')) {
            Schema::table('orders', function (Blueprint $table) {
                $table->dropColumn('has_heavy_weight_items');
            });
        }
    }
};
