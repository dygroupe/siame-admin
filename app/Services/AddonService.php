<?php

namespace App\Services;

use App\Traits\ActivationClass;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Rap2hpoutre\FastExcel\FastExcel;

class AddonService
{
    use ActivationClass;

    public function getAddData(Object $request): array
    {
        return [
            'name' => $request->name[array_search('default', $request->lang)],
            'price' => $request->price,
            'store_id' => $request->store_id,
            'addon_category_id' => $request->category_id,
        ];
    }

    public function getImportData(Request $request, bool $toAdd = true): array
    {
        try {
            $collections = (new FastExcel)->import($request->file('products_file'));
        } catch (Exception) {
            return ['flag' => 'wrong_format'];
        }

        $data = [];
        foreach ($collections as $collection) {
            if ($collection['Name'] === "" || !is_numeric($collection['StoreId'])) {
                return ['flag' => 'required_fields'];
            }
            if(isset($collection['Price']) && ($collection['Price'] < 0  )  ) {
                return ['flag' => 'price_range'];
            }
            $array = [
                'name' => $collection['Name'],
                'price' => $collection['Price'],
                'store_id' => $collection['StoreId'],
                'status' => $collection['Status'] == 'active' ? 1 : 0,
                'created_at'=>now(),
                'updated_at'=>now()
            ];

            if(!$toAdd){
                $array['id'] = $collection['Id'];
            }

            $data[] = $array;
        }

        return $data;
    }

    public function getBulkExportData(object $collection): array
    {
        $data = [];
        foreach($collection as $key=>$item){
            $data[] = [
                'Id'=>$item->id,
                'Name'=>$item->name,
                'Price'=>$item->price,
                'StoreId'=>$item->store_id,
                'Status'=>$item->status == 1 ? 'active' : 'inactive'
            ];
        }
        return $data;
    }

    public function getCurrentDomain(): string
    {
        return str_replace(["http://", "https://", "www."], "", url('/'));
    }

    public function addonActivationProcess(object $request): array
    {
        return [
            'status' => 1,
            'activation_status' => 1,
            'username' => $request['username'],
            'purchase_code' => $request['purchase_code'],
        ];
    }

}
