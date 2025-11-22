@extends('layouts.admin.app')

@section('title', translate('Order Details'))

@section('content')
    <?php
    $deliverman_tips = 0;
    $campaign_order = isset($order->details[0]->campaign) ? true : false;
    $reasons = \App\Models\OrderCancelReason::where('status', 1)->where('user_type', 'admin')->get();
    $parcel_order = $order->order_type == 'parcel' ? true : false;
    $tax_included = 0;
    $max_processing_time = $order->store ? explode('-', $order->store['delivery_time'])[0] : 0;
    ?>
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <div class="row align-items-center">
                <div class="col-sm mb-2 mb-sm-0">
                    <h1 class="page-header-title">
                        <span class="page-header-icon">
                            <img src="{{ asset('/public/assets/admin/img/car-logo.png') }}" class="w--20" alt="">
                        </span>
                        <span>
                            {{ translate('trips_details') }}
                        </span>
                    </h1>
                </div>
            </div>
        </div>
        <!-- Page Header -->

        @php
            $refund_amount = $order->order_amount - $order->delivery_charge - $order->dm_tips;
        @endphp
        <div class="row flex-xl-nowrap" id="printableArea">
            <div class="col-lg-8 order-print-area-left">
                <!-- Card -->
                <div class="card mb-3 mb-lg-5">
                    <!-- Header -->
                    <div class="card-header align-items-stretch flex-column border-0 pb-0">
                        <div class="d-flex align-items-start justify-content-between flex-wrap mb-2">
                            <div class="order-invoice-left d-flex d-sm-block justify-content-between">
                                <div>
                                    <h1 class="page-header-title d-flex align-items-center __gap-5px">
                                        Trip ID # 1000078
                                    </h1>
                                    <span class="mt-2 d-block d-flex align-items-center __gap-5px">
                                        Placed on 12 Aug, 2022, 12:45
                                        <br>
                                        Schedule At 14 Aug, 2022, 12:45
                                    </span>
                                    <div class="fs-14 text-title mt-2 pt-1 mb-2 d-flex align-items-center __gap-5px">
                                        <span>Provider</span> <span>:</span>
                                        <span class="font-bold">Auto Focus Car Service</span>
                                        <button type="button" class="btn btn--primary-light px-2 py-1 shadow-none"
                                            data-toggle="modal" data-target="#locationModal">
                                            <i class="tio-poi"></i> Map View
                                        </button>
                                    </div>
                                    <div class="fs-14 text-title mt-2 pt-1 mb-2 d-flex align-items-center __gap-5px">
                                        <span>Trip Type</span> <span>:</span>
                                        <span class="font-bold">Hourly</span>
                                        <span>(Scheduled)</span>
                                    </div>
                                    <div class="fs-14 text-title mt-2 pt-1 mb-2 d-flex align-items-center __gap-5px">
                                        <span>Total Hour</span> <span>:</span>
                                        <span class="font-bold">5 hrs</span>
                                    </div>
                                </div>
                                <div class="d-sm-none">
                                    <a class="btn btn--primary print--btn font-regular d-flex align-items-center __gap-5px"
                                        href="#">
                                        <i class="tio-print mr-sm-1"></i>
                                        <span>{{ translate('messages.print_invoice') }}</span>
                                    </a>
                                </div>
                            </div>
                            <div class="order-invoice-right mt-3 mt-sm-0">
                                <div class="btn--container ml-auto align-items-center justify-content-end">

                                    <button class="btn btn--primary btn-outline-primary font-bold" type="button"
                                        data-toggle="modal" data-target="#editTripModal">
                                        <i class="tio-edit mr-sm-1"></i> Edit Trip
                                    </button>
                                    <a class="btn btn--primary print--btn font-bold d-none d-sm-block" href="#">
                                        <i class="tio-print mr-sm-1"></i> <span>Print invoice</span>
                                    </a>
                                </div>
                                <div class="text-right mt-3 order-invoice-right-contents text-capitalize">
                                    <h6>
                                        <span>Trip Status</span> <span>:</span>
                                        <span class="badge badge--accepted ml-2 ml-sm-3 text-capitalize">
                                            Confirmed
                                        </span>
                                    </h6>
                                    <h6>
                                        <span>Payment status</span> <span>:</span>
                                        <strong class="text-danger">Unpaid</strong>

                                    </h6>
                                    <h6>
                                        <span>Payment method</span> <span>:</span>
                                        <span class="font-semibold">SSL Commerz</span>
                                    </h6>
                                    <h6>
                                        <span>Reference Code </span> <span>:</span>
                                        <span class="font-semibold">68973</span>
                                    </h6>
                                </div>
                            </div>
                        </div>
                        <div class="__bg-FAFAFA p-2 rounded">
                            <h6 class="fs-14 text-title opacity-lg">
                                Note:
                                <span class="opacity-70 font-regular">Please provide Good quality car</span>
                            </h6>
                        </div>
                    </div>
                    <!-- End Header -->

                    <!-- Body -->
                    <div class="card-body px-0">
                        <!-- item cart -->
                        <div class="table-responsive">
                            <table
                                class="table table-borderless table-thead-bordered table-nowrap table-align-middle card-table dataTable no-footer mb-0">
                                <thead class="thead-light">
                                    <tr>
                                        <th class="border-0">#</th>
                                        <th class="border-0">Vehicle Details</th>
                                        <th class="border-0">Unite Fair</th>
                                        <th class="border-0">Total Hour</th>
                                        <th class="text-right  border-0">Fare</th>
                                    </tr>
                                </thead>
                                <tbody>

                                    <tr>
                                        <td>
                                            <!-- Static Count Number -->
                                            <div>
                                                1
                                            </div>
                                            <!-- Static Count Number -->
                                        </td>
                                        <td>
                                            <div class="media media--sm">
                                                <a class="avatar avatar-xl mr-3" href="#">
                                                    <img class="img-fluid rounded aspect-ratio-1 onerror-image"
                                                        src="{{ asset('public/assets/admin/img/160x160/img2.jpg') }}"
                                                        data-onerror-image="{{ asset('public/assets/admin/img/160x160/img2.jpg') }}"
                                                        alt="Image Description">
                                                </a>
                                                <div class="media-body">
                                                    <div class="fs-12 text--title">
                                                        <div class="fz-12 font-semibold line--limit-1">
                                                            F Premio 2006</div>
                                                        <div><span class="font-semibold mr-2">License No. :</span>Nator Kha
                                                            21-3214</div>
                                                        <div><span class="font-semibold mr-2">Category :</span>SUV</div>
                                                        <div><span class="font-semibold mr-2">Brand :</span>Toyota</div>

                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="fs-14 text--title">
                                                $ 45.24 hourly
                                            </div>
                                        </td>
                                        <td>
                                            <div class="fs-14 text--title">
                                                5
                                            </div>
                                        </td>
                                        <td class="text-right">
                                            <div class="fs-14 text--title">
                                                $ 1,350.25
                                            </div>
                                        </td>
                                    </tr>

                                    <!-- End Media -->
                                </tbody>
                            </table>
                        </div>
                        <div class="mx-3">
                            <hr>
                        </div>
                        <div class="row justify-content-md-end mb-3 mt-4 mx-0">
                            <div class="col-md-9 col-lg-8">
                                <dl class="row text-right text-title">
                                    <dt class="col-6 font-regular">Trip Fare</dt>
                                    <dd class="col-6">
                                        $ 1,350.25</dd>

                                    <dt class="col-6">Subtotal</dt>
                                    <dd class="col-6 font-semibold">
                                        $ 1,350.25
                                    </dd>

                                    <dt class="col-6 font-regular">Coupon discount</dt>
                                    <dd class="col-6">
                                        -$ 350.25
                                    </dd>

                                    <dt class="col-6 font-regular text-uppercase">Vat/tax:</dt>
                                    <dd class="col-6 text-right">
                                        +$ 10
                                    </dd>

                                    <dt class="col-6 font-bold">Total:</dt>
                                    <dd class="col-6 font-bold">$ 1,010.00</dd>
                                </dl>
                                <!-- End Row -->
                            </div>
                        </div>
                        <!-- End Row -->
                    </div>
                    <!-- End Body -->
                </div>
                <!-- End Card -->
            </div>

            <div class="col-lg-4 order-print-area-right">
                @if (
                    !in_array($order->order_status, [
                        'refund_requested',
                        'refunded',
                        'refund_request_canceled',
                        'delivered',
                        'canceled',
                    ]))
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title">{{ translate('trip_setup') }}</h5>
                        </div>
                        <div class="card-body">
                            <div class="hs-unfold w-100 mb-20">
                                <label for="" class="font-semibold text-title">Trip Status</label>
                                <div class="dropdown">
                                    <button
                                        class="form-control h--45px dropdown-toggle d-flex justify-content-between align-items-center w-100"
                                        type="button" id="dropdownMenuButton" data-toggle="dropdown"
                                        aria-haspopup="true" aria-expanded="false">
                                        Confirmed
                                    </button>
                                    <div class="dropdown-menu text-capitalize" aria-labelledby="dropdownMenuButton">
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to pending ?" href="javascript:">Pending</a>
                                        <a class="dropdown-item active route-alert" data-url="#"
                                            data-message="Change status to confirmed ?" href="javascript:">Confirmed</a>
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to processing ?" href="javascript:">Processing</a>
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to handover ?" href="javascript:">Handover</a>
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to out for delivery ?" href="javascript:">Out for
                                            delivery</a>
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to delivered (payment status will be paid if not)"
                                            href="javascript:">Delivered</a>
                                        <a class="dropdown-item  canceled-status">Canceled</a>
                                    </div>
                                </div>
                            </div>

                            <div class="hs-unfold w-100 mb-20">
                                <label for="" class="font-semibold text-title">Payment Status</label>
                                <div class="dropdown">
                                    <button
                                        class="form-control h--45px dropdown-toggle d-flex justify-content-between align-items-center w-100"
                                        type="button" id="dropdownMenuButton" data-toggle="dropdown"
                                        aria-haspopup="true" aria-expanded="false">
                                        Unpaid
                                    </button>
                                    <div class="dropdown-menu text-capitalize" aria-labelledby="dropdownMenuButton">
                                        <a class="dropdown-item  route-alert" data-url="#"
                                            data-message="Change status to Paid ?" href="javascript:">Paid</a>
                                        <a class="dropdown-item active route-alert" data-url="#"
                                            data-message="Change status to Unpaid ?" href="javascript:">Unpaid</a>
                                    </div>

                                </div>
                            </div>
                            <button type="button" class="btn btn--primary w-100"><i class="tio-bike"></i> <span
                                    class="ml-2">Assign Driver</span>
                            </button>
                        </div>
                    </div>
                @endif
                <div class="card mt-2">
                    <div class="card-body">
                        <div class="position-relative">
                            <div class="map-fullscreen-btn_wrapper">
                                <button type="button" data-toggle="modal" data-target="#pickupDesModal"
                                    class="btn border-0 shadow--card-2">
                                    <i class="tio-fullscreen-1-1"></i>
                                </button>
                            </div>
                            <img class="aspect-2-1 object--cover w-100 max-h-160px rounded"
                                src="{{ asset('public/assets/admin/img/map-road.png') }}" alt="Map road">
                        </div>
                        <hr>
                        <ul class="trip-details-address text--title px-0 pt-2">
                            <li>
                                <span class="svg">
                                    <span class="text--title bg--F6F6F6 p-10px rounded"><i class="tio-poi"></i></span>
                                </span>
                                <span class="w-0 flex-grow-1">
                                    <span class="font-medium">Home:</span>
                                    <span class="opacity-70">Road 9/a, house - 666, Dhaka</span>
                                </span>
                            </li>
                            <li>
                                <span class="svg">
                                    <span class="text--title bg--F6F6F6 p-10px rounded"><i
                                            class="tio-navigate-outlined rotate-45 d-inline-block"></i></span>
                                </span>
                                <span class="w-0 flex-grow-1 font-medium">
                                    50 lake circus, kolabagan, Dhanmondi
                                </span>
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="card mt-2">
                    <div class="card-body">
                        <h5 class="card-title mb-3 d-flex flex-wrap align-items-center">
                            <span>{{ translate('messages.Customer_Info') }}</span>


                            @if ($order?->store?->sub_self_delivery)
                                &nbsp; ({{ translate('messages.store') }})
                            @endif

                            @if (!isset($order->delivered) && !$order?->store?->sub_self_delivery)
                                <a type="button" href="#myModal" class="text--base cursor-pointer ml-auto"
                                    data-toggle="modal" data-target="#myModal">
                                    {{ translate('messages.change') }}
                                </a>
                            @endif
                        </h5>
                        <a class="media align-items-center deco-none customer--information-single"
                            href="{{ !$order?->store?->sub_self_delivery ? route('admin.users.delivery-man.preview', [$order->delivery_man['id']]) : '#' }}">
                            <div class="avatar avatar-circle">
                                <img class="avatar-img onerror-image"
                                    data-onerror-image="{{ asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                    src="{{ $order->delivery_man?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                    alt="Image Description">
                            </div>
                            <div class="media-body">
                                {{-- <span class="text--title fs-14 font-semibold d-block text-hover-primary mb-1">{{ $order->delivery_man['f_name'] . ' ' . $order->delivery_man['l_name'] }}</span> --}}
                                <span class="text--title fs-14 font-semibold d-block text-hover-primary mb-1">Jhone
                                    Die</span>

                                <div class="text--title d-flex align-items-center gap-1">
                                    <span>
                                        <span class="font-bold">12</span>
                                        {{ translate('messages.order') }},
                                    </span>
                                    <span>
                                        <span class="font-bold">5</span>
                                        {{ translate('messages.trip') }}
                                    </span>
                                </div>

                                <div class="text--title">
                                    +90-495-303235
                                </div>

                                <div class="text--title">
                                    doe@gmail,com
                                </div>

                            </div>
                        </a>
                    </div>
                </div>
                <div class="card mt-2">
                    <div class="card-body">
                        <h5 class="card-title mb-3 d-flex flex-wrap align-items-center">
                            <span>{{ translate('messages.Provider_Info') }}</span>
                        </h5>
                        <a class="media align-items-center deco-none resturant--information-single" href="#">
                            <div class="avatar avatar-circle">
                                <img class="avatar-img w-75px border-000-01 onerror-image"
                                    data-onerror-image="{{ asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                    src="{{ $order->delivery_man?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                    alt="Image Description">
                            </div>
                            <div class="media-body">
                                <div class="text--title fs-14 font-semibold d-block text-hover-primary mb-1">
                                    Auto Focus Car Service
                                </div>

                                <div class="text--title">
                                    <span class="font-bold">205</span>
                                    {{ translate('messages.Trip_served') }}
                                </div>

                                <div class="text--title d-flex align-items-center">
                                    +90-495-303235
                                </div>

                                <div class="text--title d-flex align-items-baseline">
                                    <i class="tio-poi mr-2"></i>
                                    Șoseaua Gheorghe Ionescu Sisești nr
                                    236, ‘București, Romania
                                </div>

                            </div>
                        </a>
                    </div>
                </div>
            </div>
        </div>
        <!-- End Row -->
    </div>

    <!--Dm assign Modal -->
    <div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title" id="myModalLabel">{{ translate('messages.assign_deliveryman') }}</h4>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span
                            aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-5 my-2">
                            <ul class="list-group overflow-auto initial--23">
                                @foreach ($deliveryMen as $dm)
                                    <li class="list-group-item">
                                        <span class="dm_list" role='button' data-id="{{ $dm['id'] }}">
                                            <img class="avatar avatar-sm avatar-circle mr-1 onerror-image"
                                                data-onerror-image="{{ asset('public/assets/admin/img/160x160/img1.jpg') }}"
                                                src="{{ $dm['image_full_url'] }}" alt="{{ $dm['name'] }}">
                                            {{ $dm['name'] }}
                                        </span>

                                        <a class="btn btn-primary btn-xs float-right add-delivery-man"
                                            data-id="{{ $dm['id'] }}">{{ translate('messages.assign') }}</a>
                                    </li>
                                @endforeach
                            </ul>
                        </div>
                        <div class="col-md-7 modal_body_map">
                            <div class="location-map" id="dmassign-map">
                                <div class="initial--24" id="map_canvas"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- End Modal -->

    <!--Show locations on map Modal -->
    <div class="modal fade" id="locationModal" tabindex="-1" role="dialog" aria-labelledby="locationModalLabel">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header pt-4 px-4">
                    <h4 class="modal-title" id="locationModalLabel">{{ translate('messages.location_data') }}</h4>
                    <button type="button" class="close p-0 m-0" data-dismiss="modal" aria-label="Close"><span
                            aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body p-4">
                    <div class="row">
                        <div class="col-md-12 modal_body_map">
                            <div class="location-map" id="location-map">
                                <div class="initial--25 rounded-8" id="location_map_canvas"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- End Modal -->

    <!--Show Pickup/Destinaton route on map Modal -->
    <div class="modal fade" id="pickupDesModal" tabindex="-1" role="dialog" aria-labelledby="pickupDesModalLabel">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header pt-4 px-4">
                    <h4 class="modal-title" id="pickupDesModalLabel">{{ translate('messages.Trip ID # 1000078') }}</h4>
                    <button type="button" class="close p-0 m-0" data-dismiss="modal" aria-label="Close"><span
                            aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body p-4">
                    <div class="row">
                        <div class="col-md-12 modal_body_map">
                            <div class="location-map" id="pickup_location_map">
                                <div class="initial--25 rounded-8 custom_map_canvas" id="custom_route_line_map_canvas">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- End Modal -->

    <!--Show Edit trip Modal -->
    <div class="modal fade" id="editTripModal" tabindex="-1" role="dialog" aria-labelledby="editTripModalLabel">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header pt-4 px-4">
                    <h4 class="modal-title" id="editTripModalLabel">{{ translate('messages.Trip ID # 1000078') }}</h4>
                    <button type="button" class="close p-0 m-0" data-dismiss="modal" aria-label="Close"><span
                            aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body p-4">
                    <form action="">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group text-title">
                                    <label class="input-label font-semibold" for="">Pickup Location</label>
                                    <div class="position-relative w-100 d-flex align-items-center">
                                        <input type="text" name="" id="" class="form-control pr-2"
                                            placeholder="Enter your pickup location"
                                            value="Home: Road 9/a, house - 666, Dhaka">
                                        <div class="input-icon fs-20 opacity-60">
                                            <i class="tio-poi"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group text-title">
                                    <label class="input-label font-semibold" for="">Destination</label>
                                    <div class="position-relative w-100 d-flex align-items-center">
                                        <input type="text" name="" id="" class="form-control pr-2"
                                            placeholder="Enter your destination location"
                                            value="50 lake circus, kolabagan, Dhanmondi">
                                        <div class="input-icon fs-20 opacity-60">
                                            <i class="tio-navigate-outlined rotate-45 d-block"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group text-title">
                                    <label class="input-label font-semibold" for="">Trip Type</label>
                                    <select name="" id="" class="form-control custom-select-arrow">
                                        <option value="hourly" selected>Hourly</option>
                                        <option value="day">Day</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group text-title">
                                    <label class="input-label font-semibold" for="trip-schedule">Trip Schedule</label>
                                    <div class="position-relative w-100 d-flex align-items-center">
                                        <input type="datetime-local" name="trip_schedule" id="trip-schedule"
                                            value="2022-08-14T12:45" class="form-control pr-2 opacity-lg"
                                            placeholder="Enter your destination location">
                                    </div>
                                </div>

                            </div>
                        </div>
                        <div class="card p-0">
                            <div class="card-body p-0 bg--F6F6F6">
                                <!-- item cart -->
                                <div class="table-responsive">
                                    <table
                                        class="table table-borderless table-thead-bordered table-nowrap table-align-middle card-table dataTable no-footer mb-0">
                                        <thead class="bg--EDEDED text--title">
                                            <tr>
                                                <th class="border-0">#</th>
                                                <th class="border-0">Vehicle Details</th>
                                                <th class="border-0">Unite Fair</th>
                                                <th class="border-0">Total Hour</th>
                                                <th class="text-right  border-0">Fare</th>
                                            </tr>
                                        </thead>
                                        <tbody>

                                            <tr>
                                                <td>
                                                    <!-- Static Count Number -->
                                                    <div>
                                                        1
                                                    </div>
                                                    <!-- Static Count Number -->
                                                </td>
                                                <td>
                                                    <div class="media media--sm">
                                                        <a class="avatar avatar-xl mr-3" href="#">
                                                            <img class="img-fluid rounded aspect-ratio-1 onerror-image"
                                                                src="{{ asset('public/assets/admin/img/160x160/img2.jpg') }}"
                                                                data-onerror-image="{{ asset('public/assets/admin/img/160x160/img2.jpg') }}"
                                                                alt="Image Description">
                                                        </a>
                                                        <div class="media-body">
                                                            <div class="fs-12 text--title">
                                                                <div class="fz-12 font-semibold line--limit-1">
                                                                    F Premio 2006</div>
                                                                <div><span class="font-semibold mr-2">License No.
                                                                        :</span>Nator Kha
                                                                    21-3214</div>
                                                                <div><span class="font-semibold mr-2">Category :</span>SUV
                                                                </div>
                                                                <div><span class="font-semibold mr-2">Brand :</span>Toyota
                                                                </div>

                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td>
                                                    <div class="fs-14 text--title">
                                                        $ 45.24 hourly
                                                    </div>
                                                </td>
                                                <td>
                                                    <input type="number" class="form-control fs-14 text--title w--60px"
                                                        value="5" placeholder="EX:5">
                                                </td>
                                                <td class="text-right">
                                                    <input type="text"
                                                        class="form-control w--120px text-right fs-14 text--title"
                                                        value="$ 1,350.25" placeholder="fare">
                                                </td>
                                            </tr>

                                            <!-- End Media -->
                                        </tbody>
                                    </table>
                                </div>
                                <div class="mx-3">
                                    <hr>
                                </div>
                                <div class="row justify-content-md-end mb-3 mt-4 mx-0">
                                    <div class="col-md-9 col-lg-8">
                                        <dl class="row text-right text-title">
                                            <dt class="col-6 font-regular">Trip Fare</dt>
                                            <dd class="col-6">
                                                $ 1,350.25</dd>

                                            <dt class="col-6">Subtotal</dt>
                                            <dd class="col-6 font-semibold">
                                                $ 1,350.25
                                            </dd>

                                            <dt class="col-6 font-regular">Coupon discount</dt>
                                            <dd class="col-6">
                                                -$ 350.25
                                            </dd>

                                            <dt class="col-6 font-regular text-uppercase">Vat/tax:</dt>
                                            <dd class="col-6 text-right">
                                                +$ 10
                                            </dd>

                                            <dt class="col-6 font-bold">Total:</dt>
                                            <dd class="col-6 font-bold">$ 1,010.00</dd>
                                        </dl>
                                        <!-- End Row -->
                                    </div>
                                </div>
                                <!-- End Row -->
                            </div>
                        </div>
                        <div class="btn--container justify-content-end mt-4">
                            <button type="reset" id="reset_btn"
                                class="btn btn--warning-light min-w-120px">{{ translate('messages.cancel') }}</button>
                            <button type="submit"
                                class="btn btn--primary min-w-120px">{{ translate('messages.update') }}</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <!-- End Modal -->

@endsection

@push('script_2')
    <script>
        $('#search-form').on('submit', function(e) {
            e.preventDefault();
            var keyword = $('#datatableSearch').val();
            var nurl = new URL('{!! url()->full() !!}');
            nurl.searchParams.set('keyword', keyword);
            location.href = nurl;
        });

        $('.set-category-filter').on('change', function() {
            let id = $(this).val();
            var nurl = new URL('{!! url()->full() !!}');
            nurl.searchParams.set('category_id', id);
            location.href = nurl;
        })

        $('.addon_quantity_input_toggle').on('change', function(event) {
            addon_quantity_input_toggle(event);
        })

        function addon_quantity_input_toggle(e) {
            var cb = $(e.target);
            if (cb.is(":checked")) {
                cb.siblings('.addon-quantity-input').css({
                    'visibility': 'visible'
                });
            } else {
                cb.siblings('.addon-quantity-input').css({
                    'visibility': 'hidden'
                });
            }
        }

        $('.quick-view-cart-item').on('click', function() {
            let key = $(this).data('key');
            $.get({
                url: '{{ route('admin.order.quick-view-cart-item') }}',
                dataType: 'json',
                data: {
                    key: key,
                    order_id: '{{ $order->id }}',
                },
                beforeSend: function() {
                    $('#loading').show();
                },
                success: function(data) {
                    $('#quick-view').modal('show');
                    $('#quick-view-modal').empty().html(data.view);
                },
                complete: function() {
                    $('#loading').hide();
                },
            });
        })

        $('.quick-view').on('click', function() {
            let product_id = $(this).data('product-id');
            quickView(product_id);
        })

        function quickView(product_id) {
            $.get({
                url: '{{ route('admin.order.quick-view') }}',
                dataType: 'json',
                data: {
                    product_id: product_id,
                    order_id: '{{ $order->id }}',
                },
                beforeSend: function() {
                    $('#loading').show();
                },
                success: function(data) {
                    console.log("success...")
                    $('#quick-view').modal('show');
                    $('#quick-view-modal').empty().html(data.view);
                },
                complete: function() {
                    $('#loading').hide();
                },
            });
        }

        function cartQuantityInitialize() {
            $('.btn-number').click(function(e) {
                e.preventDefault();

                var fieldName = $(this).attr('data-field');
                var type = $(this).attr('data-type');
                var input = $("input[name='" + fieldName + "']");
                var currentVal = parseInt(input.val());

                if (!isNaN(currentVal)) {
                    if (type == 'minus') {

                        if (currentVal > input.attr('min')) {
                            input.val(currentVal - 1).change();
                        }
                        if (parseInt(input.val()) == input.attr('min')) {
                            $(this).attr('disabled', true);
                        }

                    } else if (type == 'plus') {

                        if (currentVal < input.attr('max')) {
                            input.val(currentVal + 1).change();
                        }
                        if (parseInt(input.val()) == input.attr('max')) {
                            $(this).attr('disabled', true);
                        }

                    }
                } else {
                    input.val(0);
                }
            });

            $('.input-number').focusin(function() {
                $(this).data('oldValue', $(this).val());
            });

            $('.input-number').change(function() {

                minValue = parseInt($(this).attr('min'));
                maxValue = parseInt($(this).attr('max'));
                valueCurrent = parseInt($(this).val());

                var name = $(this).attr('name');
                if (valueCurrent >= minValue) {
                    $(".btn-number[data-type='minus'][data-field='" + name + "']").removeAttr('disabled')
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Cart',
                        text: 'Sorry, the minimum value was reached'
                    });
                    $(this).val($(this).data('oldValue'));
                }
                if (valueCurrent <= maxValue) {
                    $(".btn-number[data-type='plus'][data-field='" + name + "']").removeAttr('disabled')
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Cart',
                        text: 'Sorry, stock limit exceeded.'
                    });
                    $(this).val($(this).data('oldValue'));
                }
            });
            $(".input-number").keydown(function(e) {
                // Allow: backspace, delete, tab, escape, enter and .
                if ($.inArray(e.keyCode, [46, 8, 9, 27, 13, 190]) !== -1 ||
                    // Allow: Ctrl+A
                    (e.keyCode == 65 && e.ctrlKey === true) ||
                    // Allow: home, end, left, right
                    (e.keyCode >= 35 && e.keyCode <= 39)) {
                    // let it happen, don't do anything
                    return;
                }
                // Ensure that it is a number and stop the keypress
                if ((e.shiftKey || (e.keyCode < 48 || e.keyCode > 57)) && (e.keyCode < 96 || e.keyCode > 105)) {
                    e.preventDefault();
                }
            });
        }

        function getVariantPrice() {
            if ($('#add-to-cart-form input[name=quantity]').val() > 0) {
                $.ajaxSetup({
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="_token"]').attr('content')
                    }
                });
                $.ajax({
                    type: "POST",
                    url: '{{ route('admin.item.variant-price') }}',
                    data: $('#add-to-cart-form').serializeArray(),
                    success: function(data) {
                        $('#add-to-cart-form #chosen_price_div').removeClass('d-none');
                        $('#add-to-cart-form #chosen_price_div #chosen_price').html(data.price);
                    }
                });
            }
        }


        $(document).on('click', '.update_order_item', function() {


            update_order_item();
        })

        function update_order_item(form_id = 'add-to-cart-form') {
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="_token"]').attr('content')
                }
            });
            $.post({
                url: '{{ route('admin.order.add-to-cart') }}',
                data: $('#' + form_id).serializeArray(),
                beforeSend: function() {
                    $('#loading').show();
                },
                success: function(data) {
                    if (data.data == 1) {
                        Swal.fire({
                            icon: 'info',
                            title: 'Cart',
                            text: "{{ translate('messages.product_already_added_in_cart') }}"
                        });
                        return false;
                    } else if (data.data == 0) {
                        toastr.success('{{ translate('messages.product_has_been_added_in_cart') }}', {
                            CloseButton: true,
                            ProgressBar: true
                        });
                        location.reload();
                        return false;
                    } else if (data.data == 'variation_error') {
                        Swal.fire({
                            icon: 'error',
                            title: 'Cart',
                            text: data.message
                        });
                        return false;
                    }
                    $('.call-when-done').click();

                    toastr.success('{{ translate('messages.order_updated_successfully') }}', {
                        CloseButton: true,
                        ProgressBar: true
                    });
                    location.reload();
                },
                complete: function() {
                    $('#loading').hide();
                }
            });
        }


        $(document).on('click', '.removeFromCart', function() {
            let key = $(this).data('key');
            removeFromCart(key);
        })

        function removeFromCart(key) {
            Swal.fire({
                title: '{{ translate('messages.are_you_sure') }}',
                text: '{{ translate('messages.you_want_to_remove_this_order_item') }}',
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#FC6A57',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    $.post('{{ route('admin.order.remove-from-cart') }}', {
                        _token: '{{ csrf_token() }}',
                        key: key,
                        order_id: '{{ $order->id }}'
                    }, function(data) {
                        if (data.errors) {
                            for (var i = 0; i < data.errors.length; i++) {
                                toastr.error(data.errors[i].message, {
                                    CloseButton: true,
                                    ProgressBar: true
                                });
                            }
                        } else {
                            toastr.success(
                                '{{ translate('messages.item_has_been_removed_from_cart') }}', {
                                    CloseButton: true,
                                    ProgressBar: true
                                });
                            location.reload();
                        }

                    });
                }
            })

        }

        $('.edit-order').on('click', function() {
            Swal.fire({
                title: '{{ translate('messages.are_you_sure') }}',
                text: '{{ translate('messages.you_want_to_edit_this_order') }}',
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#FC6A57',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    location.href = '{{ route('admin.order.edit', $order->id) }}';
                }
            })
        })

        $('.cancel-edit-order').on('click', function() {
            Swal.fire({
                title: '{{ translate('messages.are_you_sure') }}',
                text: '{{ translate('messages.you_want_to_cancel_editing') }}',
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#FC6A57',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    location.href = '{{ route('admin.order.edit', $order->id) }}?cancle=true';
                }
            })
        })

        $('.submit-edit-order').on('click', function() {
            Swal.fire({
                title: '{{ translate('messages.are_you_sure') }}',
                text: '{{ translate('messages.you_want_to_submit_all_changes_for_this_order') }}',
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#FC6A57',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    location.href = '{{ route('admin.order.update', $order->id) }}';
                }
            })
        })
    </script>

    <script
        src="https://maps.googleapis.com/maps/api/js?key={{ \App\Models\BusinessSetting::where('key', 'map_api_key')->first()->value }}&libraries=places&v=3.45.8">
    </script>
    <script>
        // INITIALIZATION OF SELECT2
        // =======================================================
        $('.js-select2-custom').each(function() {
            var select2 = $.HSCore.components.HSSelect2.init($(this));
        });

        $('.add-delivery-man').on('click', function() {
            id = $(this).data('id');
            $.ajax({
                type: "GET",
                url: '{{ url('/') }}/admin/order/add-delivery-man/{{ $order['id'] }}/' + id,
                success: function(data) {
                    location.reload();
                    console.log(data)
                    toastr.success('Successfully added', {
                        CloseButton: true,
                        ProgressBar: true
                    });
                },
                error: function(response) {
                    console.log(response);
                    toastr.error(response.responseJSON.message, {
                        CloseButton: true,
                        ProgressBar: true
                    });
                }
            });
        })

        $('.order_status_change_alert').on('click', function() {
            let route = $(this).data('url');
            let message = $(this).data('message');
            let processing = $(this).data('processing');
            order_status_change_alert(route, message, processing);
        })

        function order_status_change_alert(route, message, processing = false) {
            if (processing) {
                Swal.fire({
                    //text: message,
                    title: '{{ translate('messages.Are you sure ?') }}',
                    type: 'warning',
                    showCancelButton: true,
                    cancelButtonColor: 'default',
                    confirmButtonColor: '#FC6A57',
                    cancelButtonText: '{{ translate('messages.Cancel') }}',
                    confirmButtonText: '{{ translate('messages.submit') }}',
                    inputPlaceholder: "{{ translate('Enter processing time') }}",
                    input: 'text',
                    html: message + '<br/>' +
                        '<label>{{ translate('Enter Processing time in minutes') }}</label>',
                    inputValue: processing,
                    preConfirm: (processing_time) => {
                        location.href = route + '&processing_time=' + processing_time;
                    },
                    allowOutsideClick: () => !Swal.isLoading()
                })
            } else {
                Swal.fire({
                    title: '{{ translate('messages.Are you sure ?') }}',
                    text: message,
                    type: 'warning',
                    showCancelButton: true,
                    cancelButtonColor: 'default',
                    confirmButtonColor: '#FC6A57',
                    cancelButtonText: '{{ translate('messages.No') }}',
                    confirmButtonText: '{{ translate('messages.Yes') }}',
                    reverseButtons: true
                }).then((result) => {
                    if (result.value) {
                        location.href = route;
                    }
                })
            }
        }


        function last_location_view() {
            toastr.warning('Only available when order is out for delivery!', {
                CloseButton: true,
                ProgressBar: true
            });
        }
        $(document).ready(function() {
            // Event handler for 'canceled-status' click
            $('.canceled-status').on('click', function() {
                // Assuming $reasons is properly populated and contains reasons

                // Create a select dropdown with options using map()
                var selectOptions = '';
                @foreach ($reasons as $r)
                    selectOptions += `<option value="{{ $r->reason }}">{{ $r->reason }}</option>`;
                @endforeach

                // Generate the Swal modal with the select dropdown
                Swal.fire({
                    title: '{{ translate('messages.are_you_sure') }}',
                    text: '{{ translate('messages.Change status to canceled ?') }}',
                    type: 'warning',
                    html: `<select class="form-control js-select2-custom mx-1" name="reason" id="reason">${selectOptions}</select>`,
                    showCancelButton: true,
                    cancelButtonColor: 'default',
                    confirmButtonColor: '#FC6A57',
                    cancelButtonText: '{{ translate('messages.no') }}',
                    confirmButtonText: '{{ translate('messages.yes') }}',
                    reverseButtons: true,
                    onOpen: function() {
                        // Initialize select2 after the modal is opened
                        $('.js-select2-custom').select2({
                            minimumResultsForSearch: 5,
                            width: '100%',
                            placeholder: "Select Reason",
                            language: "en",
                        });
                    }
                }).then((result) => {
                    if (result.value) {
                        // On confirmation, get the selected reason and redirect
                        var reason = $('#reason').val();
                        var orderID = '{{ $order['id'] }}';
                        var statusRoute = '{{ route('admin.order.status') }}';

                        // Redirect with order ID, status, and reason
                        var redirectURL =
                            `${statusRoute}?id=${orderID}&order_status=canceled&reason=${reason}`;

                        // Redirect the user to the generated URL
                        window.location.href = redirectURL;
                    }
                });
            });
        });
    </script>
    <script>
        var deliveryMan = <?php echo json_encode($deliveryMen); ?>;
        var map = null;
        @if ($order->order_type == 'parcel')
            var myLatlng = new google.maps.LatLng({{ $address['latitude'] }}, {{ $address['longitude'] }});
        @else
            @php($default_location = App\CentralLogics\Helpers::get_business_settings('default_location'))
            var myLatlng = new google.maps.LatLng(
                {{ isset($order->store) ? $order->store->latitude : (isset($default_location) ? $default_location['lat'] : 0) }},
                {{ isset($order->store) ? $order->store->longitude : (isset($default_location['lng']) ? $default_location['lng'] : 0) }}
            );
        @endif
        var dmbounds = new google.maps.LatLngBounds(null);
        var locationbounds = new google.maps.LatLngBounds(null);
        var dmMarkers = [];
        dmbounds.extend(myLatlng);
        locationbounds.extend(myLatlng);
        var myOptions = {
            center: myLatlng,
            zoom: 13,
            mapTypeId: google.maps.MapTypeId.ROADMAP,

            panControl: true,
            mapTypeControl: false,
            panControlOptions: {
                position: google.maps.ControlPosition.RIGHT_CENTER
            },
            zoomControl: true,
            zoomControlOptions: {
                style: google.maps.ZoomControlStyle.LARGE,
                position: google.maps.ControlPosition.RIGHT_CENTER
            },
            scaleControl: false,
            streetViewControl: false,
            streetViewControlOptions: {
                position: google.maps.ControlPosition.RIGHT_CENTER
            }
        };

        function initializeGMapNew() {

            map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);

            var infowindow = new google.maps.InfoWindow();
            @if ($order->store)
                var Restaurantmarker = new google.maps.Marker({
                    @if ($parcel_order)
                        position: new google.maps.LatLng({{ $address['latitude'] }},
                            {{ $address['longitude'] }}),
                        title: "{{ Str::limit($order->customer->f_name . ' ' . $order->customer->l_name, 15, '...') }}",
                        // icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}"
                    @else
                        position: new google.maps.LatLng({{ $order->store->latitude }},
                            {{ $order->store->longitude }}),
                        title: "{{ Str::limit($order?->store?->name, 15, '...') }}",
                        icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}",
                    @endif
                    map: map,

                });

                google.maps.event.addListener(Restaurantmarker, 'click', (function(Restaurantmarker) {
                    return function() {
                        @if ($parcel_order)
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->customer?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div><div style='float:right; padding: 10px;'><b>{{ $order->customer->f_name }}{{ $order->customer->l_name }}</b><br />{{ $address['address'] }}</div>"
                            );
                        @else
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->store?->logo_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div><div class='text-break' style='float:right; padding: 10px;'><b>{{ Str::limit($order?->store?->name, 15, '...') }}</b><br /> {{ $order->store->address }}</div>"
                            );
                        @endif
                        infowindow.open(map, Restaurantmarker);
                    }
                })(Restaurantmarker));
            @endif

            map.fitBounds(dmbounds);
            for (var i = 0; i < deliveryMan.length; i++) {
                if (deliveryMan[i].lat) {
                    // var contentString = "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ asset('storage/app/public/delivery-man') }}/"+deliveryMan[i].image+"'></div><div style='float:right; padding: 10px;'><b>"+deliveryMan[i].name+"</b><br/> "+deliveryMan[i].location+"</div>";
                    var point = new google.maps.LatLng(deliveryMan[i].lat, deliveryMan[i].lng);
                    dmbounds.extend(point);
                    map.fitBounds(dmbounds);
                    var marker = new google.maps.Marker({
                        position: point,
                        map: map,
                        title: deliveryMan[i].location,
                        icon: "{{ asset('public/assets/admin/img/delivery_boy_map.png') }}"
                    });
                    dmMarkers[deliveryMan[i].id] = marker;
                    google.maps.event.addListener(marker, 'click', (function(marker, i) {
                        return function() {
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='" +
                                deliveryMan[i].image_link +
                                "'></div><div style='float:right; padding: 10px;'><b>" + deliveryMan[i]
                                .name + "</b><br/> " + deliveryMan[i].location + "</div>");
                            infowindow.open(map, marker);
                        }
                    })(marker, i));
                }

            };
        }

        function initializeGMap() {

            map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);

            var infowindow = new google.maps.InfoWindow();
            @if ($order->store)
                var Restaurantmarker = new google.maps.Marker({
                    @if ($parcel_order)
                        position: new google.maps.LatLng({{ $address['latitude'] }},
                            {{ $address['longitude'] }}),
                        title: "{{ Str::limit($order->customer->f_name . ' ' . $order->customer->l_name, 15, '...') }}",
                        // icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}"
                    @else
                        position: new google.maps.LatLng({{ $order->store->latitude }},
                            {{ $order->store->longitude }}),
                        title: "{{ Str::limit($order?->store?->name, 15, '...') }}",
                        icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}",
                    @endif
                    map: map,

                });

                google.maps.event.addListener(Restaurantmarker, 'click', (function(Restaurantmarker) {
                    return function() {
                        @if ($parcel_order)
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->customer?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div><div style='float:right; padding: 10px;'><b>{{ $order->customer->f_name }}{{ $order->customer->l_name }}</b><br />{{ $address['address'] }}</div>"
                            );
                        @else
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->store?->logo_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div><div class='text-break' style='float:right; padding: 10px;'><b>{{ Str::limit($order?->store?->name, 15, '...') }}</b><br /> {{ $order->store->address }}</div>"
                            );
                        @endif
                        infowindow.open(map, Restaurantmarker);
                    }
                })(Restaurantmarker));
            @endif

            map.fitBounds(dmbounds);
            for (var i = 0; i < deliveryMan.length; i++) {
                if (deliveryMan[i].lat) {
                    // var contentString = "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ asset('storage/app/public/delivery-man') }}/"+deliveryMan[i].image+"'></div><div style='float:right; padding: 10px;'><b>"+deliveryMan[i].name+"</b><br/> "+deliveryMan[i].location+"</div>";
                    var point = new google.maps.LatLng(deliveryMan[i].lat, deliveryMan[i].lng);
                    dmbounds.extend(point);
                    map.fitBounds(dmbounds);
                    var marker = new google.maps.Marker({
                        position: point,
                        map: map,
                        title: deliveryMan[i].location,
                        icon: "{{ asset('public/assets/admin/img/delivery_boy_map.png') }}"
                    });
                    dmMarkers[deliveryMan[i].id] = marker;
                    google.maps.event.addListener(marker, 'click', (function(marker, i) {
                        return function() {
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='" +
                                deliveryMan[i].image_link +
                                "'></div><div style='float:right; padding: 10px;'><b>" + deliveryMan[i]
                                .name + "</b><br/> " + deliveryMan[i].location + "</div>");
                            infowindow.open(map, marker);
                        }
                    })(marker, i));
                }

            };
        }

        function initMap() {
            let map = new google.maps.Map(document.getElementById("map"), {
                zoom: 13,
                center: {
                    lat: {{ isset($order->store) ? $order->store->latitude : '23.757989' }},
                    lng: {{ isset($order->store) ? $order->store->longitude : '90.360587' }}
                }
            });

            let zonePolygon = null;

            //get current location block
            let infoWindow = new google.maps.InfoWindow();
            // Try HTML5 geolocation.
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(
                    (position) => {
                        myLatlng = {
                            lat: position.coords.latitude,
                            lng: position.coords.longitude,
                        };
                        infoWindow.setPosition(myLatlng);
                        infoWindow.setContent("Location found.");
                        infoWindow.open(map);
                        map.setCenter(myLatlng);
                    },
                    () => {
                        handleLocationError(true, infoWindow, map.getCenter());
                    }
                );
            } else {
                // Browser doesn't support Geolocation
                handleLocationError(false, infoWindow, map.getCenter());
            }
            //-----end block------
            const input = document.getElementById("pac-input");
            const searchBox = new google.maps.places.SearchBox(input);
            map.controls[google.maps.ControlPosition.TOP_CENTER].push(input);
            let markers = [];
            const bounds = new google.maps.LatLngBounds();
            searchBox.addListener("places_changed", () => {
                const places = searchBox.getPlaces();

                if (places.length == 0) {
                    return;
                }
                // Clear out the old markers.
                markers.forEach((marker) => {
                    marker.setMap(null);
                });
                markers = [];
                // For each place, get the icon, name and location.
                places.forEach((place) => {
                    if (!place.geometry || !place.geometry.location) {
                        console.log("Returned place contains no geometry");
                        return;
                    }
                    console.log(place.geometry.location);
                    if (!google.maps.geometry.poly.containsLocation(
                            place.geometry.location,
                            zonePolygon
                        )) {
                        toastr.error('{{ translate('messages.out_of_coverage') }}', {
                            CloseButton: true,
                            ProgressBar: true
                        });
                        return false;
                    }

                    document.getElementById('latitude').value = place.geometry.location.lat();
                    document.getElementById('longitude').value = place.geometry.location.lng();

                    const icon = {
                        url: place.icon,
                        size: new google.maps.Size(71, 71),
                        origin: new google.maps.Point(0, 0),
                        anchor: new google.maps.Point(17, 34),
                        scaledSize: new google.maps.Size(25, 25),
                    };
                    // Create a marker for each place.
                    markers.push(
                        new google.maps.Marker({
                            map,
                            icon,
                            title: place.name,
                            position: place.geometry.location,
                        })
                    );

                    if (place.geometry.viewport) {
                        // Only geocodes have viewport.
                        bounds.union(place.geometry.viewport);
                    } else {
                        bounds.extend(place.geometry.location);
                    }
                });
                map.fitBounds(bounds);
            });
            @if ($order->store)
                $.get({
                    url: '{{ url('/') }}/admin/zone/get-coordinates/{{ $order->store->zone_id }}',
                    dataType: 'json',
                    success: function(data) {
                        zonePolygon = new google.maps.Polygon({
                            paths: data.coordinates,
                            strokeColor: "#FF0000",
                            strokeOpacity: 0.8,
                            strokeWeight: 2,
                            fillColor: 'white',
                            fillOpacity: 0,
                        });
                        zonePolygon.setMap(map);
                        zonePolygon.getPaths().forEach(function(path) {
                            path.forEach(function(latlng) {
                                bounds.extend(latlng);
                                map.fitBounds(bounds);
                            });
                        });
                        map.setCenter(data.center);
                        google.maps.event.addListener(zonePolygon, 'click', function(mapsMouseEvent) {
                            infoWindow.close();
                            // Create a new InfoWindow.
                            infoWindow = new google.maps.InfoWindow({
                                position: mapsMouseEvent.latLng,
                                content: JSON.stringify(mapsMouseEvent.latLng.toJSON(), null,
                                    2),
                            });
                            var coordinates = JSON.stringify(mapsMouseEvent.latLng.toJSON(), null, 2);
                            var coordinates = JSON.parse(coordinates);

                            document.getElementById('latitude').value = coordinates['lat'];
                            document.getElementById('longitude').value = coordinates['lng'];
                            infoWindow.open(map);
                        });
                    },
                });
            @endif

        }

        $(document).ready(function() {

            // Re-init map before show modal
            $('#myModal').on('shown.bs.modal', function(event) {
                initMap();
                var button = $(event.relatedTarget);
                $("#dmassign-map").css("width", "100%");
                $("#map_canvas").css("width", "100%");
            });

            // Trigger map resize event after modal shown
            $('#myModal').on('shown.bs.modal', function() {
                initializeGMap();
                google.maps.event.trigger(map, "resize");
                map.setCenter(myLatlng);
            });

            // Address change modal modal shown
            $('#shipping-address-modal').on('shown.bs.modal', function() {
                initMap();
                // google.maps.event.trigger(map, "resize");
                // map.setCenter(myLatlng);
            });


            function initializegLocationMap() {
                map = new google.maps.Map(document.getElementById("location_map_canvas"), myOptions);

                var infowindow = new google.maps.InfoWindow();

                @if ($order->customer && isset($address))
                    var marker = new google.maps.Marker({
                        position: new google.maps.LatLng({{ $address['latitude'] }},
                            {{ $address['longitude'] }}),
                        map: map,
                        title: "{{ $order->customer->f_name }} {{ $order->customer->l_name }}",
                        icon: "{{ asset('public/assets/admin/img/customer_location.png') }}"
                    });

                    google.maps.event.addListener(marker, 'click', (function(marker) {
                        return function() {
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->customer?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div><div style='float:right; padding: 10px;'><b>{{ $order->customer->f_name }} {{ $order->customer->l_name }}</b><br />{{ $address['address'] }}</div>"
                            );
                            infowindow.open(map, marker);
                        }
                    })(marker));
                    locationbounds.extend(marker.getPosition());
                @endif
                @if ($order->delivery_man && $order->dm_last_location)
                    var dmmarker = new google.maps.Marker({
                        position: new google.maps.LatLng({{ $order->dm_last_location['latitude'] }},
                            {{ $order->dm_last_location['longitude'] }}),
                        map: map,
                        title: "{{ $order->delivery_man->f_name }} {{ $order->delivery_man->l_name }}",
                        icon: "{{ asset('public/assets/admin/img/delivery_boy_map.png') }}"
                    });

                    google.maps.event.addListener(dmmarker, 'click', (function(dmmarker) {
                        return function() {
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->delivery_man?->image_full_url ?? asset('public/assets/admin/img/160x160/img1.jpg') }}'></div> <div style='float:right; padding: 10px;'><b>{{ $order->delivery_man->f_name }} {{ $order->delivery_man->l_name }}</b><br /> {{ $order->dm_last_location['location'] }}</div>"
                            );
                            infowindow.open(map, dmmarker);
                        }
                    })(dmmarker));
                    locationbounds.extend(dmmarker.getPosition());
                @endif

                @if ($order->store)
                    var Retaurantmarker = new google.maps.Marker({
                        position: new google.maps.LatLng({{ $order->store->latitude }},
                            {{ $order->store->longitude }}),
                        map: map,
                        title: "{{ Str::limit($order?->store?->name, 15, '...') }}",
                        // icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}".
                        icon: "{{ asset('public/assets/admin/img/icons/pickup.svg') }}",
                    });

                    google.maps.event.addListener(Retaurantmarker, 'click', (function(Retaurantmarker) {
                        return function() {
                            infowindow.setContent(
                                "<div style='float:left'><img style='max-height:40px;wide:auto;' src='{{ $order?->store?->logo_full_url ?? asset('public/assets/admin/img/100x100/1.png') }}'></div> <div style='float:right; padding: 10px;'><b>{{ Str::limit($order?->store?->name, 15, '...') }}</b><br /> {{ $order->store->address }}</div>"
                            );
                            infowindow.open(map, Retaurantmarker);
                        }
                    })(Retaurantmarker));
                    locationbounds.extend(Retaurantmarker.getPosition());
                @endif
                @if ($parcel_order && isset($receiver_details))
                    var Receivermarker = new google.maps.Marker({
                        position: new google.maps.LatLng({{ $receiver_details['latitude'] }},
                            {{ $receiver_details['longitude'] }}),
                        map: map,
                        title: "{{ Str::limit($receiver_details['contact_person_name'], 15, '...') }}",
                        // icon: "{{ asset('public/assets/admin/img/restaurant_map.png') }}"
                    });

                    google.maps.event.addListener(Receivermarker, 'click', (function(Receivermarker) {
                        return function() {
                            infowindow.open(map, Receivermarker);
                        }
                    })(Receivermarker));
                    locationbounds.extend(Receivermarker.getPosition());
                @endif

                google.maps.event.addListenerOnce(map, 'idle', function() {
                    map.fitBounds(locationbounds);
                });
            }

            // Re-init map before show modal
            $('#locationModal').on('shown.bs.modal', function(event) {
                initializegLocationMap();
            });


            // ------- pickup destinaton map with route line starts

            // drawing a route (polyline) on the map between two locations
            function addPolylineToMap(map, pickupLocation, destinationLocation) {
                const directionsService = new google.maps.DirectionsService();
                const directionsRenderer = new google.maps.DirectionsRenderer({
                    map: map,
                    suppressMarkers: true, // Suppress default markers
                    polylineOptions: {
                        strokeColor: '#4D4D4D', // Line color
                        strokeOpacity: 1.0, // Line opacity
                        strokeWeight: 3 // Line width
                    },
                });

                // Define request for the route
                const request = {
                    origin: pickupLocation,
                    destination: destinationLocation,
                    travelMode: google.maps.TravelMode.DRIVING, // Use DRIVING as travel mode.
                };

                // Calculate the route and render it
                directionsService.route(request, function(response, status) {
                    if (status === google.maps.DirectionsStatus.OK) {
                        directionsRenderer.setDirections(response);
                    } else {
                        console.error("Directions request failed due to " + status);
                    }
                });
            }


            function initializeCustomRouteLocationMap() {

                const grayStyle = [{
                        featureType: "all",
                        stylers: [{
                                saturation: -100
                            }, // Desaturate all colors
                            {
                                lightness: 20
                            }, // Increase lightness
                        ]
                    },
                    {
                        featureType: "road",
                        stylers: [{
                                visibility: "on"
                            },
                            {
                                lightness: 30
                            }
                        ]
                    },
                    {
                        featureType: "landscape",
                        stylers: [{
                                lightness: 10
                            },
                            {
                                saturation: -80
                            }
                        ]
                    }
                ];

                const map = new google.maps.Map(document.getElementById("custom_route_line_map_canvas"), {
                    center: {
                        lat: 23.766660,
                        lng: 90.424993
                    },
                    zoom: 14, // Adjusted for better overview
                    styles: grayStyle,
                });

                const infowindow = new google.maps.InfoWindow();

                // Define pickup and destination locations
                const pickupLocation = {
                    lat: 23.766660,
                    lng: 90.424993
                };
                const destinationLocation = {
                    lat: 23.837232,
                    lng: 90.373129
                };

                // get dynamic icon color
                function getDynamicMarkerSvg(dynamicColor) {
                    return `
                        <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" viewBox="0 0 30 30">
                                        <g>
                                            <g clip-path="url(#clip0_5241_7679)">
                                                <path d="M14.7577 1C9.36898 1 5 5.3684 5 10.7577C5 14.0607 8.6658 19.7298 11.5035 23.6238C13.2959 26.0826 14.7577 27.8335 14.7577 27.8335C14.7621 27.8273 24.5154 16.1557 24.5154 10.7576C24.5154 5.3684 20.147 1 14.7577 1Z" fill="${dynamicColor}"/>
                                                <path d="M14.7575 3.43945C10.8843 3.43945 7.74414 6.57961 7.74414 10.4528C7.74414 12.4299 8.56258 14.2162 9.87865 15.4908H19.6363C20.953 14.2162 21.7708 12.4299 21.7708 10.4528C21.7708 6.57955 18.6313 3.43945 14.7575 3.43945Z" fill="white"/>
                                                <path d="M19.6366 15.0263V15.4904C16.917 18.1246 12.5984 18.1246 9.87891 15.4904V15.0263C9.87891 13.0052 11.517 11.3672 13.538 11.3672H15.9775C17.9985 11.3672 19.6366 13.0052 19.6366 15.0263Z" fill="white"/>
                                                <path d="M14.7578 11.3671C16.1051 11.3671 17.1972 10.275 17.1972 8.92772C17.1972 7.58045 16.1051 6.48828 14.7578 6.48828C13.4105 6.48828 12.3184 7.58045 12.3184 8.92772C12.3184 10.275 13.4105 11.3671 14.7578 11.3671Z" fill="white"/>
                                                <g clip-path="url(#clip1_5241_7679)">
                                                    <path d="M15.0563 14.9415C14.999 14.9415 14.941 14.9362 14.8826 14.9262C14.4166 14.8445 14.0913 14.4569 14.0913 13.9839V11.6079H11.715C11.242 11.6079 10.8546 11.2822 10.773 10.8165C10.6916 10.3515 10.944 9.91486 11.3866 9.75352L18.7673 6.93652L15.9446 14.3155C15.8056 14.6992 15.4533 14.9415 15.056 14.9415H15.0563Z" fill="#1E2124" fill-opacity="0.6"/>
                                                </g>
                                            </g>
                                        </g>
                                        <defs>
                                            <clipPath id="clip0_5241_7679">
                                                <rect width="30" height="30" fill="white"/>
                                            </clipPath>
                                            <clipPath id="clip1_5241_7679">
                                                <rect width="8" height="8" fill="white" transform="translate(10.7578 6.94141)"/>
                                            </clipPath>
                                        </defs>
                                    </svg>
                    `;
                }

                function createMarkerIconFromCssVariable(variableName) {
                    const rootStyles = getComputedStyle(document.documentElement);
                    const dynamicColor = rootStyles.getPropertyValue(variableName).trim();

                    // Generate SVG with the dynamic color
                    const svg = getDynamicMarkerSvg(dynamicColor);

                    // Convert to Base64 for Google Maps marker
                    const base64Svg = `data:image/svg+xml;base64,${btoa(svg)}`;

                    return {
                        url: base64Svg,
                        scaledSize: new google.maps.Size(30, 30),
                    };
                }

                // Set icon color from a CSS variable
                const destinationMarkerIcon = createMarkerIconFromCssVariable("--primary-clr");

                // Add a marker for the pickup location
                const pickupMarker = new google.maps.Marker({
                    position: pickupLocation,
                    map: map,
                    title: "Pickup Location",
                    icon: "{{ asset('public/assets/admin/img/icons/pickup.svg') }}",
                });

                google.maps.event.addListener(pickupMarker, "click", function() {
                    infowindow.setContent('<div class="fs-12 font-medium">Pickup</div>');
                    infowindow.open(map, pickupMarker);
                });

                // Add a marker for the destination location
                const destinationMarker = new google.maps.Marker({
                    position: destinationLocation,
                    map: map,
                    title: "Destination Location",
                    icon: destinationMarkerIcon,
                });

                google.maps.event.addListener(destinationMarker, "click", function() {
                    infowindow.setContent('<div class="fs-12 font-medium">Destination</div>');
                    infowindow.open(map, destinationMarker);
                });

                // Add a routed polyline between the pickup and destination locations
                addPolylineToMap(map, pickupLocation, destinationLocation);
            }

            // Re-init map before showing modal
            $('#pickupDesModal').on('shown.bs.modal', function(event) {
                initializeCustomRouteLocationMap();
            });

            // ------- pickup destinaton map with route line ends


            $('.dm_list').on('click', function() {
                var id = $(this).data('id');
                map.panTo(dmMarkers[id].getPosition());
                map.setZoom(13);
                dmMarkers[id].setAnimation(google.maps.Animation.BOUNCE);
                window.setTimeout(() => {
                    dmMarkers[id].setAnimation(null);
                }, 3);
            });
        })
    </script>

    <script src="{{ asset('public/assets/admin/js/spartan-multi-image-picker.js') }}"></script>
    <script type="text/javascript">
        $(function() {
            $("#coba").spartanMultiImagePicker({
                fieldName: 'order_proof[]',
                maxCount: 6 -
                    {{ $order->order_proof && is_array($order->order_proof) ? count(json_decode($order->order_proof)) : 0 }},
                rowHeight: '176px !important',
                groupClassName: 'spartan_item_wrapper min-w-176px max-w-176px',
                maxFileSize: '',
                placeholderImage: {
                    image: "{{ asset('public/assets/admin/img/upload-img.png') }}",
                    width: '176px'
                },
                dropFileLabel: "Drop Here",
                onAddRow: function(index, file) {

                },
                onRenderedPreview: function(index) {

                },
                onRemoveRow: function(index) {

                },
                onExtensionErr: function(index, file) {
                    toastr.error(
                        "{{ translate('messages.please_only_input_png_or_jpg_type_file') }}", {
                            CloseButton: true,
                            ProgressBar: true
                        });
                },
                onSizeErr: function(index, file) {
                    toastr.error("{{ translate('messages.file_size_too_big') }}", {
                        CloseButton: true,
                        ProgressBar: true
                    });
                }
            });
        });
    </script>
@endpush
