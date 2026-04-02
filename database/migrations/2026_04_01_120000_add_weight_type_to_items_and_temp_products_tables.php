<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     * 0 = light weight, 1 = heavy weight (aligned with vendor app weight_type).
     */
    public function up(): void
    {
        if (Schema::hasTable('items') && ! Schema::hasColumn('items', 'weight_type')) {
            Schema::table('items', function (Blueprint $table) {
                $table->unsignedTinyInteger('weight_type')->default(0)->after('unit_id');
            });
        }

        if (Schema::hasTable('temp_products') && ! Schema::hasColumn('temp_products', 'weight_type')) {
            Schema::table('temp_products', function (Blueprint $table) {
                $table->unsignedTinyInteger('weight_type')->default(0)->after('unit_id');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasTable('items') && Schema::hasColumn('items', 'weight_type')) {
            Schema::table('items', function (Blueprint $table) {
                $table->dropColumn('weight_type');
            });
        }

        if (Schema::hasTable('temp_products') && Schema::hasColumn('temp_products', 'weight_type')) {
            Schema::table('temp_products', function (Blueprint $table) {
                $table->dropColumn('weight_type');
            });
        }
    }
};
