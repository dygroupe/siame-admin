<?php

namespace App\CentralLogics;

use App\Models\DeliveryMan;
use App\Models\DMVehicle;
use App\Models\Item;
use App\Models\Order;
use App\Scopes\StoreScope;

/**
 * Rules: orders containing heavy-weight items (item.weight_type = 1)
 * must use the Fourgon DM vehicle category; only those delivery men may take them.
 * Fourgon delivery men may take any order (heavy or light).
 */
class HeavyDeliveryLogic
{
    /** Stored value in d_m_vehicles.type (default label, not translated). */
    public const FOURGON_VEHICLE_TYPE = 'Fourgon';

    public static function fourgonVehicleId(): ?int
    {
        $id = DMVehicle::withoutGlobalScopes()
            ->where('status', 1)
            ->where('type', self::FOURGON_VEHICLE_TYPE)
            ->value('id');

        return $id !== null ? (int) $id : null;
    }

    public static function deliveryManIsFourgon(?DeliveryMan $dm): bool
    {
        if (! $dm || ! $dm->vehicle_id) {
            return false;
        }

        $vehicle = DMVehicle::withoutGlobalScopes()->find($dm->vehicle_id);
        if (! $vehicle) {
            return false;
        }

        $raw = $vehicle->getRawOriginal('type');

        return $raw !== null && strcasecmp((string) $raw, self::FOURGON_VEHICLE_TYPE) === 0;
    }

    public static function orderRequiresHeavyVehicle(Order $order): bool
    {
        return (int) ($order->has_heavy_weight_items ?? 0) === 1;
    }

    /**
     * @param  array<int, array<string, mixed>>  $cartLines  POS session cart lines (must contain 'id' => item id)
     */
    public static function posCartContainsHeavyItem(array $cartLines): bool
    {
        foreach ($cartLines as $line) {
            if (! is_array($line) || empty($line['id'])) {
                continue;
            }
            $wt = Item::withoutGlobalScope(StoreScope::class)->whereKey($line['id'])->value('weight_type');
            if ((int) $wt === 1) {
                return true;
            }
        }

        return false;
    }

    public static function vehicleExtraChargeForVehicleId(float $distance, int $vehicleId): array
    {
        $data = DMVehicle::active()->where('id', $vehicleId)
            ->where(function ($query) use ($distance) {
                $query->where(function ($q) use ($distance) {
                    $q->where('starting_coverage_area', '<=', $distance)
                        ->where('maximum_coverage_area', '>=', $distance);
                })->orWhere(function ($q) use ($distance) {
                    $q->where('starting_coverage_area', '>=', $distance);
                });
            })
            ->orderBy('starting_coverage_area')
            ->first();

        if (! $data) {
            $data = DMVehicle::active()->where('id', $vehicleId)->first();
        }

        return [
            'extraCharge' => (float) ($data->extra_charges ?? 0),
            'vehicle_id' => $vehicleId,
        ];
    }

    /**
     * Firebase: notify the order's vehicle topic; if the order is light-only, also notify Fourgon riders.
     */
    public static function pushOrderRequestToDeliveryVehicleTopics(Order $order, array $data, string $notificationType = 'order_request'): void
    {
        if (! $order->zone_id || ! $order->dm_vehicle_id) {
            return;
        }

        $topic = 'delivery_man_'.$order->zone_id.'_'.$order->dm_vehicle_id;
        Helpers::send_push_notif_to_topic($data, $topic, $notificationType);

        $fourgonId = self::fourgonVehicleId();
        if ($fourgonId && (int) $order->dm_vehicle_id !== (int) $fourgonId && ! self::orderRequiresHeavyVehicle($order)) {
            $topicVan = 'delivery_man_'.$order->zone_id.'_'.$fourgonId;
            Helpers::send_push_notif_to_topic($data, $topicVan, $notificationType);
        }
    }
}
