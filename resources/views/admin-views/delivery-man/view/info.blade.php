@extends('layouts.admin.app')

@section('title', translate('Delivery Man Preview'))

@section('content')
    <div class="content container-fluid pb-0">
        <!-- Page Header -->
        <div class="page-header">
            <div class="d-flex flex-wrap justify-content-between align-items-start gap-2">
                <div class="d-flex gap-2">
                    <div class="page-header-icon">
                        <img src="{{ asset('public/assets/admin/img/delivery-man.png') }}" class="w--26" alt="">
                    </div>
                    <div>
                        <h1 class="page-header-title text-break mb-1">
                            <span>
                                {{ translate('messages.deliveryman_preview') }}
                                @if ($deliveryMan->application_status == 'approved')
                                    <span class="badge badge-soft-dark ml-2" id="itemCount">{{ $reviews->total() }}</span>
                                @endif
                            </span>
                        </h1>

                        <p class="mb-0 fs-12">{{ translate('messages.Requested_to_join_at') }} {{ \App\CentralLogics\Helpers::time_date_format($deliveryMan->created_at) }}
                        </p>
                    </div>
                </div>

                @if ($deliveryMan->application_status != 'approved')
                    <div class="btn-container">
                        <a class="btn btn-primary text-capitalize font-weight-medium fs-12" data-toggle="tooltip"
                            data-placement="top" data-original-title="{{ translate('messages.edit') }}"
                            href="{{ route('admin.users.delivery-man.edit', [$deliveryMan['id']]) }}">
                            <i class="tio-edit"></i>
                            {{ translate('messages.edit-information') }}
                        </a>

                        @if ($deliveryMan->application_status != 'denied')
                            <a class="btn btn-danger text-capitalize font-weight-medium request-alert fs-12"
                                data-url="{{ route('admin.users.delivery-man.application', [$deliveryMan['id'], 'denied']) }}"
                                data-message="{{ translate('messages.you_want_to_deny_this_application') }}"
                                href="javascript:">
                                {{ translate('messages.reject') }}
                            </a>
                        @endif

                        <a class="btn btn-success text-capitalize font-weight-medium request-alert fs-12"
                            data-url="{{ route('admin.users.delivery-man.application', [$deliveryMan['id'], 'approved']) }}"
                            data-message="{{ translate('messages.you_want_to_approve_this_application') }}"
                            href="javascript:">
                            {{ translate('messages.approve') }}
                        </a>
                    </div>
                @endif
            </div>

            <div class="">
                @include('admin-views.delivery-man.partials._tab_menu')
            </div>
        </div>
        <!-- End Page Header -->

        @if ($deliveryMan->application_status == 'approved')
            <div class="row mb-3 gy-2 row-3">
                <!-- Earnings (Monthly) Card Example -->
                <div class="col-sm-6 mb-2 col-lg-4">
                    <div class="color-card">
                        <div class="img-box">
                            <img class="resturant-icon w--30"
                                src="{{ asset('public/assets/admin/img/icons/color-icon-1.png') }}" alt="img">
                        </div>
                        <div>
                            <h2 class="title">
                                {{count($deliveryMan['order_transaction'])}}
                            </h2>
                            <div class="subtitle">
                                {{ translate('messages.total_delivered_orders') }}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Collected Cash Card Example -->
                <div class="col-sm-6 mb-2 col-lg-4">
                    <div class="color-card color-2">
                        <div class="img-box">
                            <img class="resturant-icon w--30"
                                src="{{ asset('/public/assets/admin/img/icons/color-icon-2.png') }}" alt="transactions">
                        </div>
                        <div>
                            <h2 class="title">
                                {{ \App\CentralLogics\Helpers::format_currency($deliveryMan->wallet ? $deliveryMan->wallet->collected_cash : 0.0) }}
                            </h2>
                            <div class="subtitle">
                                {{ translate('messages.cash_in_hand') }}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Total Earning Card Example -->
                <div class="col-sm-6 mb-2 col-lg-4">
                    <div class="color-card color-3">
                        <div class="img-box">
                            <img class="resturant-icon w--30"
                                src="{{ asset('/public/assets/admin/img/icons/color-icon-3.png') }}" alt="transactions">
                        </div>
                        <div>
                            <h2 class="title">
                                {{ \App\CentralLogics\Helpers::format_currency($deliveryMan->wallet ? $deliveryMan->wallet->total_earning : 0.0) }}
                            </h2>
                            <div class="subtitle">
                                {{ translate('messages.total_earning') }}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Total Earning Card Example -->

                <?php
                $balance = 0;
                if ($deliveryMan->wallet) {
                    $balance = $deliveryMan->wallet->total_earning - ($deliveryMan->wallet->total_withdrawn + $deliveryMan->wallet->pending_withdraw + $deliveryMan->wallet->collected_cash);
                }

                ?>
                @if ($deliveryMan->earning)
                    @if ($balance > 0)
                        <div class="col-sm-6 mb-2 col-lg-4">
                            <div class="color-card color-4">
                                <div class="img-box">
                                    <img class="resturant-icon w--30"
                                        src="{{ asset('/public/assets/admin/img/icons/group.png') }}"
                                        alt="transactions">
                                </div>
                                <div>
                                    <h2 class="title">
                                        {{ \App\CentralLogics\Helpers::format_currency(abs($balance)) }}
                                    </h2>
                                    <div class="subtitle">
                                        {{ translate('messages.Withdraw_Able_Balance') }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    @elseif($balance < 0)
                        <div class="col-sm-6 mb-2 col-lg-4">
                            <div class="color-card color-4">
                                <div class="img-box">
                                    <img class="resturant-icon w--30"
                                        src="{{ asset('/public/assets/admin/img/icons/color-icon-4.png') }}"
                                        alt="transactions">
                                </div>
                                <div>
                                    <h2 class="title">
                                        {{ \App\CentralLogics\Helpers::format_currency(abs($deliveryMan->wallet->collected_cash)) }}
                                    </h2>
                                    <div class="subtitle">
                                        {{ translate('messages.Payable_Balance') }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    @else
                        <div class="col-sm-6 mb-2 col-lg-4">
                            <div class="color-card color-4">
                                <div class="img-box">
                                    <img class="resturant-icon w--30"
                                        src="{{ asset('/public/assets/admin/img/icons/group.png') }}"
                                        alt="transactions">
                                </div>
                                <div>
                                    <h2 class="title">
                                        {{ \App\CentralLogics\Helpers::format_currency(0) }}
                                    </h2>
                                    <div class="subtitle">
                                        {{ translate('messages.Balance') }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    @endif


                    <div class="col-sm-6 mb-2 col-lg-4">
                        <div class="color-card color-5">
                            <div class="img-box">
                                <img class="resturant-icon w--30"
                                    src="{{ asset('/public/assets/admin/img/icons/color-icon-5.png') }}"
                                    alt="transactions">
                            </div>
                            <div>
                                <h2 class="title">
                                    {{ \App\CentralLogics\Helpers::format_currency($deliveryMan->wallet ? $deliveryMan->wallet->total_withdrawn : 0.0) }}
                                </h2>
                                <div class="subtitle">
                                    {{ translate('messages.Total_withdrawn') }}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-sm-6 mb-2 col-lg-4">
                        <div class="color-card color-6">
                            <div class="img-box">
                                <img class="resturant-icon w--30"
                                    src="{{ asset('/public/assets/admin/img/icons/color-icon-6.png') }}"
                                    alt="transactions">
                            </div>
                            <div>
                                <h2 class="title">
                                    {{ \App\CentralLogics\Helpers::format_currency($deliveryMan->wallet ? $deliveryMan->wallet->pending_withdraw : 0.0) }}
                                </h2>
                                <div class="subtitle">
                                    {{ translate('messages.Pending_withdraw') }}
                                </div>
                            </div>
                        </div>
                    </div>
                @endif
            </div>
    </div>
    </div>
    </div>
    @endif

    <div class="content container-fluid pt-0">
        <div class="card my-3">
            <div class="card-body pb-5">
                @if ($deliveryMan->application_status == 'approved')
                <div
                    class="d-flex mb-3 justify-content-between align-items-center gap-2 flex-wrap position-relative z-index-2">
                    <h4 class="card-title align-items-center flex-wrap gap-2">
                        {{ $deliveryMan['f_name'] . ' ' . $deliveryMan['l_name'] }}
                            {{ $deliveryMan?->zone?->name  ??  translate('messages.zone_deleted')}}
                        @if ($deliveryMan->application_status == 'approved')
                            @if ($deliveryMan['status'])
                                @if ($deliveryMan['active'])
                                    <label
                                        class=" mb-0 badge badge-soft-primary">{{ translate('messages.online') }}</label>
                                @else
                                    <label
                                        class=" mb-0 badge badge-soft-danger">{{ translate('messages.offline') }}</label>
                                @endif
                            @else
                                <label class=" mb-0 badge badge-danger">{{ translate('messages.suspended') }}</label>
                            @endif
                        @else
                            <label
                                class=" mb-0 badge badge-soft-{{ $deliveryMan->application_status == 'pending' ? 'info' : 'danger' }}">{{ translate('messages.' . $deliveryMan->application_status) }}</label>
                        @endif
                    </h4>

                    <div class="d-flex flex-wrap gap-2">

                            <a  href="{{route('admin.users.delivery-man.edit',[$deliveryMan->id])}}"
                                class="btn py-2 btn-primary align-items-center d-flex">
                                {{translate('Edit Information')}}
                            </a>

                            <a href="javascript:"
                                class="btn request-alert py-2 {{ $deliveryMan->status ? 'btn--danger' : 'btn-success' }} align-items-center d-flex"
                                data-url="{{ route('admin.users.delivery-man.status', [$deliveryMan['id'], $deliveryMan->status ? 0 : 1]) }}"
                                data-message="{{ $deliveryMan->status ? translate('messages.you_want_to_suspend_this_deliveryman') : translate('messages.you_want_to_unsuspend_this_deliveryman') }}">
                                {{ $deliveryMan->status ? translate('messages.suspend_this_delivery_man') : translate('messages.unsuspend_this_delivery_man') }}
                            </a>
                        <div class="hs-unfold">
                            <div class="dropdown">
                                <button class="btn btn--primary dropdown-toggle" type="button" id="dropdownMenuButton"
                                    data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                    {{ translate('messages.type') }}
                                    ({{ $deliveryMan->earning ? translate('messages.freelancer') : translate('messages.salary_based') }})
                                </button>
                                <div class="dropdown-menu text-capitalize" aria-labelledby="dropdownMenuButton">
                                    <a class="dropdown-item {{ $deliveryMan->earning ? 'active' : '' }} request-alert"
                                        data-url="{{ route('admin.users.delivery-man.earning', [$deliveryMan['id'], 1]) }}"
                                        data-message="{{ translate('messages.want_to_enable_earnings') }}"
                                        href="javascript:">{{ translate('messages.freelancer') }}</a>
                                    <a class="dropdown-item {{ $deliveryMan->earning ? '' : 'active' }} request-alert"
                                        data-url="{{ route('admin.users.delivery-man.earning', [$deliveryMan['id'], 0]) }}"
                                        data-message="{{ translate('messages.want_to_disable_earnings') }}"
                                        href="javascript:">{{ translate('messages.salary_based') }}</a>
                                </div>
                            </div>
                        </div>
                    </div>


                </div>
@endif
                <div class="d-flex flex-column flex-md-row align-items-center gap-3 border rounded p-3">
                    <div class="d-flex gap-3">
                        <img class="rounded" data-onerror-image="{{ asset('public/assets/admin/img/160x160/img1.jpg') }}"
                            src="{{ $deliveryMan['image_full_url']}}"
                            width="115" height="115" alt="Delivery man image">
                    </div>

                    <div class="flex-grow-1">
                        <div class="row g-2">
                            <div class="col-12">
                                <h4 title="{{$deliveryMan['f_name'] . ' ' . $deliveryMan['l_name']}}" class="d-flex justify-content-center justify-content-md-start mb-0">
                                    {{ $deliveryMan['f_name'] . ' ' . $deliveryMan['l_name'] }}</h4>
                                <div class="fs-12 text-muted d-flex justify-content-center justify-content-md-start">
                                    @if ($deliveryMan->application_status == 'approved')
                                        <a href="mailto:{{ $deliveryMan['email'] }}"> {{ $deliveryMan['email'] }}</a>
                                        <span class="d-block mx-3">|</span>
                                        <a href="tel:{{ $deliveryMan['phone'] }}"> {{ $deliveryMan['phone'] }}</a>
                                    @endif
                                </div>
                            </div>

                            <div class="col-md-6 col-xl-4 col-xxl-3">
                                <div class="d-flex justify-content-center justify-content-md-start gap-3">
                                    <img class="rounded-circle"
                                        src="{{ asset('public/assets/admin/img/icons/job-type.png') }}" width="35"
                                        height="35" alt="">
                                    <div class="">
                                        <h6 class="mb-1">{{ translate('messages.Job_Type') }} </h6>
                                        <p class="mb-0 font-weight-normal">
                                            {{ $deliveryMan->earning ? translate('messages.freelancer') : translate('messages.salary_based') }}
                                        </p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 col-xl-4 col-xxl-3">
                                <div class="d-flex justify-content-center justify-content-md-start gap-3">
                                    <img class="rounded-circle"
                                        src="{{ asset('public/assets/admin/img/icons/vehicle-type.png') }}"
                                        width="35" height="35" alt="">
                                    <div class="">
                                        <h6 class="mb-1">{{ translate('messages.Vehicle_Type') }}</h6>
                                        <p class="mb-0 font-weight-normal">{{ $deliveryMan?->vehicle?->type }}</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 col-xl-4 col-xxl-3">
                                <div class="d-flex justify-content-center justify-content-md-start gap-3">
                                    <img class="rounded-circle"
                                        src="{{ asset('public/assets/admin/img/icons/zone.png') }}" width="35"
                                        height="35" alt="">
                                    <div class="">
                                        <h6 class="mb-1">{{ translate('messages.Zone') }}</h6>
                                        <p class="mb-0 font-weight-normal">{{ isset($deliveryMan->zone)?$deliveryMan->zone->name:translate('zone_deleted') }}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    @if ($deliveryMan->application_status == 'approved')
                        @php($total = $deliveryMan->reviews->count())


                            <div class="d-flex flex-column flex-lg-row gap-3 flex-grow-1 border-lg-left">
                                @if ($total > 0)
                                <div class="d-flex flex-column align-items-center justify-content-center px-4">
                                    <img class="" width="80" height="80"
                                        src="{{ asset('public/assets/admin/img/icons/rating-stars.png') }}"
                                        alt="">

                                    <div class="d-block">
                                        <div class="rating--review">
                                            <h3 class="title mb-0">
                                                {{ count($deliveryMan->rating) > 0 ? number_format($deliveryMan->rating[0]->average, 1) : 0 }}<span
                                                    class="out-of">/5</span></h3>
                                            <div class="info">
                                                <span>{{ $deliveryMan->reviews->count() }}
                                                    {{ translate('messages.reviews') }}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <ul
                                    class="list-unstyled list-unstyled-py-2 mb-0 rating--review-right py-3 flex-grow-1 review-color-progress">

                                    <!-- Review Ratings -->
                                    <li class="d-flex align-items-center font-size-sm">
                                        @php($five = \App\CentralLogics\Helpers::dm_rating_count($deliveryMan['id'], 5))
                                        <span class="progress-name mr-3">{{ translate('excellent') }}</span>
                                        <div class="progress flex-grow-1">
                                            <div class="progress-bar" role="progressbar"
                                                style="width: {{ $total == 0 ? 0 : ($five / $total) * 100 }}%;"
                                                aria-valuenow="{{ $total == 0 ? 0 : ($five / $total) * 100 }}"
                                                aria-valuemin="0" aria-valuemax="100"></div>
                                        </div>
                                        <span class="ml-3">{{ $five }}</span>
                                    </li>
                                    <!-- End Review Ratings -->

                                    <!-- Review Ratings -->
                                    <li class="d-flex align-items-center font-size-sm">
                                        @php($four = \App\CentralLogics\Helpers::dm_rating_count($deliveryMan['id'], 4))
                                        <span class="progress-name mr-3">{{ translate('good') }}</span>
                                        <div class="progress flex-grow-1">
                                            <div class="progress-bar" role="progressbar"
                                                style="width: {{ $total == 0 ? 0 : ($four / $total) * 100 }}%;"
                                                aria-valuenow="{{ $total == 0 ? 0 : ($four / $total) * 100 }}"
                                                aria-valuemin="0" aria-valuemax="100"></div>
                                        </div>
                                        <span class="ml-3">{{ $four }}</span>
                                    </li>
                                    <!-- End Review Ratings -->

                                    <!-- Review Ratings -->
                                    <li class="d-flex align-items-center font-size-sm">
                                        @php($three = \App\CentralLogics\Helpers::dm_rating_count($deliveryMan['id'], 3))
                                        <span class="progress-name mr-3">{{ translate('average') }}</span>
                                        <div class="progress flex-grow-1">
                                            <div class="progress-bar" role="progressbar"
                                                style="width: {{ $total == 0 ? 0 : ($three / $total) * 100 }}%;"
                                                aria-valuenow="{{ $total == 0 ? 0 : ($three / $total) * 100 }}"
                                                aria-valuemin="0" aria-valuemax="100"></div>
                                        </div>
                                        <span class="ml-3">{{ $three }}</span>
                                    </li>
                                    <!-- End Review Ratings -->

                                    <!-- Review Ratings -->
                                    <li class="d-flex align-items-center font-size-sm">
                                        @php($two = \App\CentralLogics\Helpers::dm_rating_count($deliveryMan['id'], 2))
                                        <span class="progress-name mr-3">{{ translate('below_average') }}</span>
                                        <div class="progress flex-grow-1">
                                            <div class="progress-bar" role="progressbar"
                                                style="width: {{ $total == 0 ? 0 : ($two / $total) * 100 }}%;"
                                                aria-valuenow="{{ $total == 0 ? 0 : ($two / $total) * 100 }}"
                                                aria-valuemin="0" aria-valuemax="100"></div>
                                        </div>
                                        <span class="ml-3">{{ $two }}</span>
                                    </li>
                                    <!-- End Review Ratings -->

                                    <!-- Review Ratings -->
                                    <li class="d-flex align-items-center font-size-sm">
                                        @php($one = \App\CentralLogics\Helpers::dm_rating_count($deliveryMan['id'], 1))
                                        <span class="progress-name mr-3">{{ translate('poor') }}</span>
                                        <div class="progress flex-grow-1">
                                            <div class="progress-bar" role="progressbar"
                                                style="width: {{ $total == 0 ? 0 : ($one / $total) * 100 }}%;"
                                                aria-valuenow="{{ $total == 0 ? 0 : ($one / $total) * 100 }}"
                                                aria-valuemin="0" aria-valuemax="100"></div>
                                        </div>
                                        <span class="ml-3">{{ $one }}</span>
                                    </li>
                                    <!-- End Review Ratings -->
                                </ul>

                                @else

                                <div class="d-flex flex-column align-items-center justify-content-center px-4 m-auto">
                                    <img class=" w-100"
                                        src="{{ asset('public/assets/admin/img/icons/no_rating.png') }}"
                                        alt="">
                                    <p class="mb-0 font-weight-normal">
                                        {{ translate('messages.no_review/rating_given_yet') }}
                                    </p>
                                </div>
                                @endif
                            </div>


                    @endif
                </div>

                <div class="d-flex gap-2 align-items-center mt-5">
                    <img src="{{ asset('public/assets/admin/img/entypo_image-inverted.png') }}" width="20" height="20"
                        alt="">
                        @if ($deliveryMan->application_status == 'approved')
                        <h5 class="mb-0">{{ translate('Identity_Documents') }}</h5>
                        @else
                        <h5 class="mb-0">{{ translate('Registration_Information') }}</h5>
                        @endif


                </div>

                <hr class="mt-2 hr-light">


                <div class="row g-3 mt-3">
                    @if ($deliveryMan->application_status == 'pending')
                        <div class="col-sm-6 col-lg-4">
                            <h5 class="mb-3">{{ translate('messages.General_Information') }}</h5>

                            <div class="key-val-list-item d-flex gap-3">
                                <div> {{ translate('messages.First_Name') }} </div>:
                                <div>{{ $deliveryMan['f_name'] }}</div>
                            </div>
                            <div class="key-val-list-item d-flex gap-3">
                                <div>{{ translate('messages.Last_Name') }}</div>:
                                <div>{{ $deliveryMan['l_name'] }}</div>
                            </div>
                            <div class="key-val-list-item d-flex gap-3">
                                <div>{{ translate('messages.email') }}</div>:
                                <div>{{ $deliveryMan['email'] }}</div>
                            </div>
                        </div>
                    @endif
                    <div class="col-sm-6 col-lg-4">
                        <h5 class="mb-3">{{ translate('messages.Identity_Information') }}</h5>

                        <div class="key-val-list-item d-flex gap-3">
                            <div>{{ translate('Identity_Type') }}</div>:
                            <div>{{ translate($deliveryMan->identity_type) }}</div>
                        </div>
                        <div class="key-val-list-item d-flex gap-3">
                            <div>{{ translate('messages.identification_number') }}</div>:
                            <div>{{ $deliveryMan->identity_number }}</div>
                        </div>
                    </div>
                    @if ($deliveryMan->application_status == 'pending')
                        <div class="col-sm-6 col-lg-4">
                            <h5 class="mb-3">{{ translate('messages.Login_Information') }}</h5>

                            <div class="key-val-list-item d-flex gap-3">
                                <div>{{ translate('messages.Phone') }}</div>:
                                <div>{{ $deliveryMan->phone }}</div>
                            </div>
                            <div class="key-val-list-item d-flex gap-3">
                                <div>{{ translate('messages.Password') }}</div>:
                                <div>**********</div>
                            </div>
                        </div>
                    @endif
                    <div class=" {{ $deliveryMan->application_status == 'pending' ? 'col-12' : 'col-6' }} ">
                        @if ($deliveryMan->application_status == 'pending')
                            <h5 class="mb-3 mt-5">{{ translate('messages.Identity_Image') }}</h5>
                        @endif
                        <div class="d-flex flex-wrap gap-3">
                            @foreach ($deliveryMan->identity_image_full_url as $key => $img)
                                <button class="btn" data-toggle="modal" data-target="#image-{{ $key }}">
                                    <div class="gallary-card">
                                        <img class="rounded mx-h150 mx-w-100"
                                            data-onerror-image="{{ asset('/public/assets/admin/img/900x400/img1.jpg') }}"
                                            src="{{ $img }}"
                                            width="275" height="150" alt="">
                                    </div>
                                </button>
                                <div class="modal fade" id="image-{{ $key }}" tabindex="-1" role="dialog"
                                    aria-labelledby="myModlabel" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h4 class="modal-title" id="myModlabel">
                                                    {{ translate('messages.Identity_Image') }}</h4>
                                                <button type="button" class="close" data-dismiss="modal"><span
                                                        aria-hidden="true">&times;</span><span
                                                        class="sr-only">{{ translate('messages.Close') }}</span></button>
                                            </div>
                                            <div class="modal-body">
                                                <img data-onerror-image="{{ asset('/public/assets/admin/img/900x400/img1.jpg') }}"
                                                src="{{ $img }}"
                                                    class="w-100 onerror-image">
                                            </div>
                                            <div class="modal-footer">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            @endforeach

                        </div>
                    </div>
                </div>


            </div>
        </div>
    </div>




    @if ($deliveryMan->application_status == 'approved')
    <div class="content container-fluid pt-0">
        <div class="card">
            <!-- Header -->
            <div class="card-header py-2 border-0">
                <h5 class="card-header-title">
                    {{ translate('messages.review_list') }}
                    <span class="badge badge-soft-dark ml-2" id="itemCount">
                            {{$reviews->total()}}
                        </span>
                </h5>
                <div class="search--button-wrapper justify-content-end">
                    <!-- Unfold -->
                    <div class="hs-unfold mr-2">
                        <a class="js-hs-unfold-invoker btn btn-sm btn-white dropdown-toggle min-height-40"
                            href="javascript:;"
                            data-hs-unfold-options='{
                                    "target": "#usersExportDropdown",
                                    "type": "css-animation"
                                }'>
                            <i class="tio-download-to mr-1"></i> {{ translate('messages.export') }}
                        </a>

                        <div id="usersExportDropdown"
                            class="hs-unfold-content dropdown-unfold dropdown-menu dropdown-menu-sm-right">
                            <span class="dropdown-header">{{ translate('messages.download_options') }}</span>
                            <a id="export-excel" class="dropdown-item"
                                href="{{ route('admin.users.delivery-man.review-export', ['type' => 'excel', 'id' => $deliveryMan->id, request()->getQueryString()]) }}">
                                <img class="avatar avatar-xss avatar-4by3 mr-2"
                                    src="{{ asset('public/assets/admin') }}/svg/components/excel.svg"
                                    alt="Image Description">
                                {{ translate('messages.excel') }}
                            </a>
                            <a id="export-csv" class="dropdown-item"
                                href="{{ route('admin.users.delivery-man.review-export', ['type' => 'csv', 'id' => $deliveryMan->id, request()->getQueryString()]) }}">
                                <img class="avatar avatar-xss avatar-4by3 mr-2"
                                    src="{{ asset('public/assets/admin') }}/svg/components/placeholder-csv-format.svg"
                                    alt="Image Description">
                                .{{ translate('messages.csv') }}
                            </a>
                        </div>
                    </div>
                    <!-- End Unfold -->
                </div>
            </div>
            <!-- End Header -->

            <!-- New Table -->
            <div class="card-body p-0">
                <div class="table-responsive datatable-custom">
                    <table id="datatable" class="table table-borderless table-thead-bordered table-nowrap card-table"
                        data-hs-datatables-options='{
                        "columnDefs": [{
                            "targets": [0, 3, 6],
                            "orderable": false
                        }],
                        "order": [],
                        "info": {
                        "totalQty": "#datatableWithPaginationInfoTotalQty"
                        },
                        "search": "#datatableSearch",
                        "entries": "#datatableEntries",
                        "pageLength": 25,
                        "isResponsive": false,
                        "isShowPaging": false,
                        "pagination": "datatablePagination"
                    }'>
                        <thead class="thead-light">
                            <tr>
                                <th class="border-0">{{ translate('messages.SL') }}</th>
                                <th class="border-0">{{ translate('messages.order_ID') }}</th>
                                <th class="border-0">{{ translate('messages.customer') }}</th>
                                <th class="border-0">{{ translate('messages.Rating') }}</th>
                                <th class="border-0">{{ translate('messages.review') }}</th>
                            </tr>
                        </thead>

                        <tbody>

                            @foreach ($reviews as $k => $review)
                                <tr>
                                    <td scope="row">{{$k+$reviews->firstItem()}}</td>
                                    <td>
                                        <a
                                            href="{{ route('admin.order.all-details', ['id' => $review->order_id]) }}">{{ $review->order_id }}</a>
                                    </td>
                                    <td>
                                        @if ($review->customer)
                                            <a class="d-flex align-items-center"
                                                href="{{ route('admin.customer.view', [$review['user_id']]) }}">
                                                <span class="d-block text-dark">
                                                    {{ $review->customer ? $review->customer['f_name'] . ' ' . $review->customer['l_name'] : '' }}
                                                </span>
                                            </a>
                                        @else
                                            {{ translate('messages.customer_not_found') }}
                                        @endif
                                    </td>
                                    <td>
                                        <div class="">
                                            <div class="d-flex">
                                                <label
                                                    class="badge badge-soft-warning mb-0 d-flex align-items-center gap-1 justify-content-center">
                                                    <span class="d-inline-block mt-half">{{ $review->rating }}</span>
                                                    <i class="tio-star"></i>
                                                </label>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="text-wrap">
                                            {{ $review['comment'] }}
                                        </div>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                <!-- End Table -->
                @if (count($reviews) !== 0)
                    <hr>
                @endif
                <div class="page-area">
                    {!! $reviews->links() !!}
                </div>
                @if (count($reviews) === 0)
                    <div class="empty--data">
                        <img src="{{ asset('/public/assets/admin/svg/illustrations/sorry.svg') }}" alt="public">
                        <h5>
                            {{ translate('no_data_found') }}
                        </h5>
                    </div>
                @endif
            </div>

            <!-- previous Table -->
            <div class="card-body p-0 d-none">
                <div class="table-responsive datatable-custom">
                    <table id="datatable" class="table table-borderless table-thead-bordered table-nowrap card-table"
                        data-hs-datatables-options='{
                        "columnDefs": [{
                            "targets": [0, 3, 6],
                            "orderable": false
                        }],
                        "order": [],
                        "info": {
                        "totalQty": "#datatableWithPaginationInfoTotalQty"
                        },
                        "search": "#datatableSearch",
                        "entries": "#datatableEntries",
                        "pageLength": 25,
                        "isResponsive": false,
                        "isShowPaging": false,
                        "pagination": "datatablePagination"
                    }'>
                        <thead class="thead-light">
                            <tr>
                                <th class="border-0">{{ translate('messages.reviewer') }}</th>
                                <th class="border-0">{{ translate('messages.order_id') }}</th>
                                <th class="border-0">{{ translate('messages.reviews') }}</th>
                                <th class="border-0">{{ translate('messages.date') }}</th>
                            </tr>
                        </thead>

                        <tbody>

                            @foreach ($reviews as $review)
                                <tr>
                                    <td>
                                        @if ($review->customer)
                                            <a class="d-flex align-items-center"
                                                href="{{ route('admin.customer.view', [$review['user_id']]) }}">
                                                <div class="avatar avatar-circle">
                                                    <img class="avatar-img" width="75" height="75"
                                                        src="{{ asset('storage/app/public/profile/') }}/{{ $review->customer ? $review->customer->image : '' }}"
                                                        alt="Image Description">
                                                </div>
                                                <div class="ml-3">
                                                    <span
                                                        class="d-block h5 text-hover-primary mb-0">{{ $review->customer ? $review->customer['f_name'] . ' ' . $review->customer['l_name'] : '' }}
                                                        <i class="tio-verified text-primary" data-toggle="tooltip"
                                                            data-placement="top" title="Verified Customer"></i></span>
                                                    <span
                                                        class="d-block font-size-sm text-body">{{ $review->customer ? $review->customer->email : '' }}</span>
                                                </div>
                                            </a>
                                        @else
                                            {{ translate('messages.customer_not_found') }}
                                        @endif
                                    </td>
                                    <td>
                                        <a
                                            href="{{ route('admin.order.all-details', ['id' => $review->order_id]) }}">{{ $review->order_id }}</a>
                                    </td>
                                    <td>
                                        <div class="text-wrap w-18rem">
                                            <div class="d-flex">
                                                <label class="badge badge-soft-info">
                                                    {{ $review->rating }} <i class="tio-star"></i>
                                                </label>
                                            </div>

                                            <p>
                                                {{ $review['comment'] }}
                                            </p>
                                        </div>
                                    </td>
                                    <td>
                                        {{ date('d M Y ' . config('timeformat'), strtotime($review['created_at'])) }}
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                <!-- End Table -->
                @if (count($reviews) !== 0)
                    <hr>
                @endif
                <div class="page-area">
                    {!! $reviews->links() !!}
                </div>
                @if (count($reviews) === 0)
                    <div class="empty--data">
                        <img src="{{ asset('/public/assets/admin/svg/illustrations/sorry.svg') }}" alt="public">
                        <h5>
                            {{ translate('no_data_found') }}
                        </h5>
                    </div>
                @endif
            </div>
        </div>
    </div>
    @endif

    </div>
@endsection

@push('script_2')
    <script>
        "use strict";
        $('.request-alert').on('click', function() {
            let url = $(this).data('url');
            let message = $(this).data('message');
            request_alert(url, message);
        })

        function request_alert(url, message) {
            Swal.fire({
                title: '{{ translate('messages.are_you_sure') }}',
                text: message,
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#FC6A57',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    location.href = url;
                }
            })
        }
    </script>
@endpush
