<?php

namespace App\Repositories;

use App\Contracts\Repositories\OrderTransactionRepositoryInterface;
use App\Models\OrderTransaction;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;

class OrderTransactionRepository implements OrderTransactionRepositoryInterface
{
    public function __construct(protected OrderTransaction $transaction)
    {
    }

    public function add(array $data): string|object
    {
        $transaction = $this->transaction->newInstance();
        foreach ($data as $key => $column) {
            $transaction[$key] = $column;
        }
        $transaction->save();
        return $transaction;
    }

    public function getFirstWhere(array $params, array $relations = []): ?Model
    {
        return $this->transaction->where($params)->first();
    }

    public function getList(array $orderBy = [], array $relations = [], int|string $dataLimit = DEFAULT_DATA_LIMIT, int $offset = null): Collection|LengthAwarePaginator
    {
        return $this->transaction->paginate($dataLimit);
    }

    public function getListWhere(string $searchValue = null, array $filters = [], array $relations = [], int|string $dataLimit = DEFAULT_DATA_LIMIT, int $offset = null): Collection|LengthAwarePaginator
    {
        $key = explode(' ', $searchValue);
        return $this->transaction->where(function ($query) use ($key) {
            foreach ($key as $value) {
                $query->orWhere('name', 'like', "%{$value}%");
            }
        })->limit($dataLimit)->get();
    }

    public function update(string $id, array $data): bool|string|object
    {
        $transaction = $this->transaction->find($id);
        foreach ($data as $key => $column) {
            $transaction[$key] = $column;
        }
        $transaction->save();
        return $transaction;
    }

    public function delete(string $id): bool
    {
        $transaction = $this->transaction->find($id);
        $transaction->translations()->delete();
        $transaction->delete();

        return true;
    }

    public function getDmEarningList(Request $request): Collection
    {
        $date = $request->date;
        return $this->transaction->where('delivery_man_id', $request->id)
            ->when($date, function($query)use($date){
                return $query->whereDate('created_at', $date);
            })->get();
    }
}
