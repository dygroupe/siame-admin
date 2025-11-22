@extends('layouts.admin.app')

@section('title', translate('business_setup'))


@section('content')
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-header-title mr-3">
                <span class="page-header-icon">
                    <img src="{{ asset('public/assets/admin/img/business.png') }}" class="w--26" alt="">
                </span>
                <span>
                    {{ translate('messages.business_settings') }}
                </span>
            </h1>
            @include('admin-views.business-settings.partials.nav-menu')
        </div>
        <!-- End Page Header -->
        <form action="{{ route('admin.business-settings.update-order') }}" method="post" enctype="multipart/form-data">
            @csrf
            @php($name = \App\Models\BusinessSetting::where('key', 'business_name')->first())

            <div class="row g-3">
                @php($default_location = \App\Models\BusinessSetting::where('key', 'default_location')->first())
                @php($default_location = $default_location->value ? json_decode($default_location->value, true) : 0)
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="py-2">
                                <div class="row g-3 align-items-end">
                                    <div class="col-sm-6 col-lg-4">
                                        @php($odc = \App\Models\BusinessSetting::where('key', 'order_delivery_verification')->first())
                                        @php($odc = $odc ? $odc->value : 0)
                                        <div class="form-group mb-0">

                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('messages.order_delivery_verification') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.When_a_deliveryman_arrives_for_delivery,_Customers_will_get_a_4-digit_verification_code_on_the_order_details_section_in_the_Customer_App_and_needs_to_provide_the_code_to_the_delivery_man_to_verify_the_order.') }}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.order_varification_toggle') }}">
                                                    </span>
                                                </span>
                                                <input type="checkbox"
                                                       data-id="odc1"
                                                       data-type="toggle"
                                                       data-image-on="{{ asset('/public/assets/admin/img/modal/order-delivery-verification-on.png') }}"
                                                       data-image-off="{{ asset('/public/assets/admin/img/modal/order-delivery-verification-off.png') }}"
                                                       data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.Delivery_Verification?') }}</strong>"
                                                       data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.Delivery_Verification?') }}</strong>"
                                                       data-text-on="<p>{{ translate('messages.If you enable this, the Deliveryman has to verify the order during delivery through a 4-digit verification code.') }}</p>"
                                                       data-text-off="<p>{{ translate('messages.If you disable this, the Deliveryman will deliver the order and update the status. He doesn’t need to verify the order with any code.') }}</p>"
                                                       class="status toggle-switch-input dynamic-checkbox-toggle"

                                                       value="1"
                                                    name="odc" id="odc1" {{ $odc == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($prescription_order_status = \App\Models\BusinessSetting::where('key', 'prescription_order_status')->first())

                                        @php($prescription_order_status = $prescription_order_status ? $prescription_order_status->value : 0)
                                        <div class="form-group mb-0">

                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('messages.Place_Order_by_Prescription') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.With_this_feature,_customers_can_place_an_order_by_uploading_prescription._Stores_can_enable/disable_this_feature_from_the_store_settings_if_needed.') }}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.prescription_order_status') }}"> </span>
                                                </span>
                                                <input type="checkbox"
                                                       data-id="prescription_order_status"
                                                       data-type="toggle"
                                                       data-image-on="{{ asset('/public/assets/admin/img/modal/prescription-on.png') }}"
                                                       data-image-off="{{ asset('/public/assets/admin/img/modal/prescription-off.png') }}"
                                                       data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.Place_Order_by_Prescription?') }}</strong>"
                                                       data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.Place_Order_by_Prescription?') }}</strong>"
                                                       data-text-on="<p>{{ translate('messages.If you enable this, customers can place an order by simply uploading their prescriptions in the Pharmacy module from the Customer App or Website. Stores can enable/disable this feature from store settings if needed.') }}</p>"
                                                       data-text-off="<p>{{ translate('messages.If disabled, this feature will be hidden from the Customer App, Website, and Store App & Panel.') }}</p>"
                                                       class="status toggle-switch-input dynamic-checkbox-toggle"
                                                       value="1"
                                                    name="prescription_order_status" id="prescription_order_status"
                                                    {{ $prescription_order_status == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($home_delivery_status = \App\Models\BusinessSetting::where('key', 'home_delivery_status')->first())

                                        @php($home_delivery_status = $home_delivery_status ? $home_delivery_status->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('Home Delivery') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.If_you_enable_this_feature,_customers_can_choose_‘Home_Delivery’_and_get_the_product_delivered_to_their_preferred_location.') }}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('Home Delivery') }}"></span>
                                                </span>
                                                <input type="checkbox"
                                                       data-id="home_delivery"
                                                       data-type="toggle"
                                                       data-image-on="{{ asset('/public/assets/admin/img/modal/home-delivery-on.png') }}"
                                                       data-image-off="{{ asset('/public/assets/admin/img/modal/home-delivery-off.png') }}"
                                                       data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.Home_Delivery?') }}</strong>"
                                                       data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.Home_Delivery?') }}</strong>"
                                                       data-text-on="<p>{{ translate('messages.If you enable this, customers can use the Home Delivery Option during checkout from the Customer App or Website.') }}</p>"
                                                       data-text-off="<p>{{ translate('messages.If you disable this, the Home Delivery feature will be hidden from the customer app and website.') }}</p>"
                                                       class="status toggle-switch-input dynamic-checkbox-toggle"
                                                       name ="home_delivery_status" id="home_delivery" value="1"
                                               {{ $home_delivery_status == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($takeaway_status = \App\Models\BusinessSetting::where('key', 'takeaway_status')->first())

                                        @php($takeaway_status = $takeaway_status ? $takeaway_status->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('Takeaway') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.If_you_enable_this_feature,_customers_can_place_an_order_and_request_‘Takeaways’_or_‘self-pick-up’_from_stores.') }}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('Home Delivery') }}"></span>
                                                </span>
                                                <input type="checkbox"
                                                       data-id="take_away"
                                                       data-type="toggle"
                                                       data-image-on="{{ asset('/public/assets/admin/img/modal/takeaway-on.png') }}"
                                                       data-image-off="{{ asset('/public/assets/admin/img/modal/takeaway-off.png') }}"
                                                       data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.the_Takeaway_feature?') }}</strong>"
                                                       data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.the_Takeaway_feature?') }}</strong>"
                                                       data-text-on="<p>{{ translate('messages.If you enable this, customers can use the Takeaway feature during checkout from the Customer App or Website.') }}</p>"
                                                       data-text-off="<p>{{ translate('messages.If you disable this, the Takeaway feature will be hidden from the Customer App or Website.') }}</p>"
                                                       class="status toggle-switch-input dynamic-checkbox-toggle"
                                                       name="takeaway_status" value="1" id="take_away" {{ $takeaway_status == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="col-sm-6 col-lg-4">
                                        @php($schedule_order = \App\Models\BusinessSetting::where('key', 'schedule_order')->first())
                                        @php($schedule_order = $schedule_order ? $schedule_order->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('messages.Schedule_Order') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.With_this_feature,_customers_can_choose_their_preferred_delivery_slot._Customers_can_select_a_delivery_slot_for_ASAP_or_a_specific_date_(within_2_days_from_the_order).')}}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.customer_varification_toggle') }}">
                                                    </span>
                                                </span>
                                                <input type="checkbox"
                                                       data-id="schedule_order"
                                                       data-type="toggle"
                                                       data-image-on="{{ asset('/public/assets/admin/img/modal/schedule-on.png') }}"
                                                       data-image-off="{{ asset('/public/assets/admin/img/modal/schedule-off.png') }}"
                                                       data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.Scheduled Order?') }}</strong>"
                                                       data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.Scheduled Order?') }}</strong>"
                                                       data-text-on="<p>{{ translate('messages.If you enable this, customers can choose a suitable delivery schedule during checkout.') }}</p>"
                                                       data-text-off="<p>{{ translate('messages.If you disable this, the Scheduled Order feature will be hidden.') }}</p>"
                                                       class="status toggle-switch-input dynamic-checkbox-toggle"
                                                       value="1"
                                                    name="schedule_order" id="schedule_order"
                                                    {{ $schedule_order == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="col-sm-6 col-lg-4">
                                        @php($schedule_order_slot_duration = \App\Models\BusinessSetting::where('key', 'schedule_order_slot_duration')->first())
                                        @php($schedule_order_slot_duration_time_format = \App\Models\BusinessSetting::where('key', 'schedule_order_slot_duration_time_format')->first())
                                        <div class="form-group mb-0">
                                            <label class="input-label text-capitalize d-flex alig-items-center"
                                                for="schedule_order_slot_duration">


                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('messages.Time_Interval_for_Scheduled_Delivery') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.By_activating_this_feature,_customers_can_choose_their_suitable_delivery_slot_according_to_a_30-minute_or_1-hour_interval_set_by_the_Admin.') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('Home Delivery') }}"></span>
                                                </span>
                                            </label>
                                            <div class="d-flex">
                                                <input type="number" name="schedule_order_slot_duration" class="form-control mr-3"
                                                id="schedule_order_slot_duration"
                                                value="{{ $schedule_order_slot_duration?->value ? $schedule_order_slot_duration_time_format?->value == 'hour' ? $schedule_order_slot_duration?->value /60 : $schedule_order_slot_duration?->value: 0 }}"
                                                min="0" required>
                                                <select   name="schedule_order_slot_duration_time_format" class="custom-select form-control w-90px">
                                                    <option  value="min" {{ $schedule_order_slot_duration_time_format?->value == 'min'? 'selected' : '' }}>{{ translate('Min') }}</option>
                                                    <option  value="hour" {{ $schedule_order_slot_duration_time_format?->value == 'hour'? 'selected' : ''}}>{{ translate('Hour') }}</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                    @php($extra_packaging_data = \App\Models\BusinessSetting::where('key', 'extra_packaging_data')->first()?->value ?? '')
                                    @php($extra_packaging_data =json_decode($extra_packaging_data , true))
                                    <div class="mt-4  mb-4 access_product_approval">

                                        <label class="mb-2 input-label text-capitalize d-flex alig-items-center" for=""> <img src="{{ asset('/public/assets/admin/img/icon-park_ad-product.png') }}" alt=""
                                            class="card-header-icon align-self-center mr-1">{{ translate('Enable Extra Packaging Charge') }}

                                            <span class="form-label-secondary text-danger"
                                            data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('messages.After_saving_information,_sellers_will_get_the_option_to_offer_extra_packaging_charge_to_the_customer') }}"><img
                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                alt="{{ translate('Extra_Packaging_Charge') }}"></span>

                                        </label>
                                        <div class="justify-content-between border form-control">
                                            @foreach (config('module.module_type') as $key => $value)
                                            @if ($value != 'parcel' && $value != 'rental')
                                            <div class="form-check form-check-inline mx-4  ">
                                                <input class="mx-2 form-check-input" type="checkbox" {{  data_get($extra_packaging_data,$value,null) == 1 ? 'checked' :'' }} id="inlineCheckbox{{$key}}" value="1" name="{{ $value }}">
                                                <label class=" form-check-label" for="inlineCheckbox{{$key}}">{{ translate($value) }}</label>
                                            </div>
                                            @endif
                                            @endforeach

                                        </div>
                                    </div>
                                </div>

                                    {{-- @if (addon_published_status('Rental'))
                                    @php($order_cancelation_rate_limit_status = App\CentralLogics\Helpers::get_business_settings('order_cancelation_rate_limit_status') ?? 0)

                                    <div class="__bg-FAFAFA card shadow-none">
                                        <div class="card-header bg-transparent">
                                            <div>
                                                <h5 class="text-title mb-1">
                                                    {{ translate('messages.Vendor Cancelation Rate Setup') }}
                                                </h5>
                                                <p class="fs-12 mb-0">
                                                    {{ translate('messages.This section will be applicable for vendors of car rental module') }}
                                                </p>
                                            </div>
                                            <div class="col-lg-4 col-md-6">
                                                <div class="form-group mb-0">
                                                    <label
                                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                        <span class="pr-1 d-flex align-items-center switch--label text--title">

                                                        </span>
                                                        <input type="checkbox" data-id="order_cancelation_rate_limit_status" data-type="toggle"
                                                            data-image-on="{{ asset('/public/assets/admin/img/modal/dm-tips-on.png') }}"
                                                            data-image-off="{{ asset('/public/assets/admin/img/modal/dm-tips-off.png') }}"
                                                            data-title-on="<strong>{{ translate('messages.Want_to_enable_provider_cancelation_rate?') }}</strong>"
                                                            data-title-off="<strong>{{ translate('messages.Want_to_disable_provider_cancelation_rate?') }}</strong>"
                                                            data-text-on="<p>{{ translate('messages.If_you_enable_this,_provider_cancelation_rate_will_be_enabled.') }}</p>"
                                                            data-text-off="<p>{{ translate('messages.If_you_disable_this,_provider_cancelation_rate_will_be_disabled.') }}</p>"
                                                            class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                                            name="order_cancelation_rate_limit_status" id="order_cancelation_rate_limit_status"
                                                            {{  $order_cancelation_rate_limit_status ? 'checked' : '' }}>
                                                        <span class="toggle-switch-label text">
                                                            <span class="toggle-switch-indicator"></span>
                                                        </span>
                                                    </label>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="card-body">
                                            <div class="row">
                                                <div class="col-lg-6">
                                                    @php($order_cancelation_rate_block_limit =  App\CentralLogics\Helpers::get_business_settings('order_cancelation_rate_block_limit') ?? 0)
                                                    <div class="form-group mb-0">
                                                        <label class="input-label font-medium" for="order_cancelation_rate_block_limit">
                                                            {{ translate('messages.Cancelation Rate Limit') }} (%)
                                                            <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                                                data-original-title="{{ translate('messages.Cancelation Rate Limit') }}">
                                                                <i class="tio-info-outined text--title"></i>
                                                            </span>
                                                        </label>
                                                        <input type="number" max="100" min="0" id="order_cancelation_rate_block_limit" name="order_cancelation_rate_block_limit" class="form-control"  {{  $order_cancelation_rate_limit_status ? 'required' : 'readonly' }}  placeholder="{{ translate('Ex: 25') }}" value="{{ $order_cancelation_rate_block_limit }}">
                                                    </div>
                                                </div>

                                                @php($order_cancelation_rate_warning_limit =  App\CentralLogics\Helpers::get_business_settings('order_cancelation_rate_warning_limit') ?? 0)

                                                <div class="col-lg-6">
                                                    <div class="form-group mb-0">
                                                        <label class="input-label font-medium" for="order_cancelation_rate_warning_limit">
                                                            {{ translate('messages.Cancelation Rate Warning') }} (%)
                                                            <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                                                data-original-title="{{ translate('messages.Cancelation Rate Warning') }}">
                                                                <i class="tio-info-outined text--title"></i>
                                                            </span>
                                                        </label>
                                                        <input type="number" {{  $order_cancelation_rate_limit_status ? 'required' : 'readonly' }} min="0" max="100" value="{{ $order_cancelation_rate_warning_limit }}" name="order_cancelation_rate_warning_limit" id="order_cancelation_rate_warning_limit" class="form-control" placeholder="{{ translate('Ex: 20') }}">
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    @endif --}}



                                <div class="btn--container justify-content-end mt-20">
                                    <button type="reset" class="btn btn--reset">{{ translate('messages.reset') }}</button>
                                    <button type="{{ env('APP_MODE') != 'demo' ? 'submit' : 'button' }}"
                                        class="btn btn--primary call-demo">{{ translate('save_information') }}</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </form>

            <div class="mt-4">
                <h4 class="card-title mb-3">
                    <i class="tio-document-text-outlined mr-1"></i>
                    {{translate('Order Cancellation Messages')}}
                </h4>
                <div class="card">
                    <div class="card-body">
                <form action="{{ route('admin.business-settings.order-cancel-reasons.store') }}" method="post">
                    @csrf
                        @php($language = \App\Models\BusinessSetting::where('key', 'language')->first())
                        @php($language = $language->value ?? null)
                        @php($defaultLang = str_replace('_', '-', app()->getLocale()))
                        @if ($language)
                            <ul class="nav nav-tabs nav--tabs mb-3 border-0">
                                <li class="nav-item">
                                    <a class="nav-link lang_link1 active" href="#"
                                        id="default-link1">{{ translate('Default') }}</a>
                                </li>
                                @foreach (json_decode($language) as $lang)
                                    <li class="nav-item">
                                        <a class="nav-link lang_link1" href="#"
                                            id="{{ $lang }}-link1">{{ \App\CentralLogics\Helpers::get_language_name($lang) . '(' . strtoupper($lang) . ')' }}</a>
                                    </li>
                                @endforeach
                            </ul>
                        @endif
                        <div class="row g-3">
                            <div class="col-sm-6 lang_form1 default-form1">
                                <label for="order_cancellation" class="form-label">{{ translate('Order Cancellation Reason') }}
                                    ({{ translate('messages.default') }})</label>
                                <input type="text" class="form-control h--45px" name="reason[]"
                                    id="order_cancellation" placeholder="{{ translate('Ex:_Item_is_Broken') }}">
                                <input type="hidden" name="lang[]" value="default">
                            </div>
                            @if ($language)
                                @foreach (json_decode($language) as $lang)
                                    <div class="col-sm-6 d-none lang_form1" id="{{ $lang }}-form1">
                                        <label for="order_cancellation{{$lang}}" class="form-label">{{ translate('Order Cancellation Reason') }}
                                            ({{ strtoupper($lang) }})</label>
                                        <input type="text" class="form-control h--45px" name="reason[]"
                                            id="order_cancellation{{$lang}}" placeholder="{{ translate('Ex:_Item_is_Broken') }}">
                                        <input type="hidden" name="lang[]" value="{{ $lang }}">
                                    </div>
                                @endforeach
                            @endif
                            <div class="col-sm-6">
                                <label for="user_type" class="form-label d-flex">
                                    <span class="line--limit-1">{{ translate('User Type') }} </span>
                                    <span class="form-label-secondary text-danger d-flex" data-toggle="tooltip"
                                        data-placement="right"
                                        data-original-title="{{ translate('When this field is active, user can cancel an order with proper reason.') }}"><img
                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                            alt="{{ translate('messages.prescription_order_status') }}"></span>
                                </label>
                                <select id="user_type" name="user_type" class="form-control h--45px" required>
                                    <option value="">{{ translate('messages.select_user_type') }}</option>
                                    <option value="admin">{{ translate('messages.admin') }}</option>
                                    <option value="store">{{ translate('messages.store') }}</option>
                                    <option value="customer">{{ translate('messages.customer') }}</option>
                                    <option value="deliveryman">{{ translate('messages.deliveryman') }}</option>
                                </select>
                            </div>
                        </div>
                        <div class="mt-2">
                            {{ translate('messages.*Users_cannot_cancel_an_order_if_the_Admin_does_not_specify_a_cause_for_cancellation,_even_though_they_see_the_‘Cancel_Order‘_option._So_Admin_MUST_provide_a_proper_Order_Cancellation_Reason_and_select_the_related_user.')}}
                       </div>
                        <div class="btn--container justify-content-end mt-3 mb-4">
                            <button type="reset" class="btn btn--reset">{{ translate('messages.reset') }}</button>
                            <button type="{{ env('APP_MODE') != 'demo' ? 'submit' : 'button' }}"
                                class="btn btn--primary call-demo">{{ translate('Submit') }}</button>
                        </div>
                    </form>
                        <div class="card">
                            <div class="card-body mb-3">
                                <div class="d-flex flex-wrap justify-content-between align-items-center mb-md-0 mb-3">
                                    <div class="mx-1">
                                        <h5 class="form-label mb-4">
                                            {{ translate('messages.order_cancellation_reason_list') }}
                                        </h5>
                                    </div>
                                    <div class="my-2">
                                        <select id="type" name="type" class="form-control h--45px set-filter" data-url="{{ url()->full() }}" data-filter="type">
                                            <option value="all" {{ request('type') == 'all' ? 'selected' : '' }}>{{ translate('messages.all_user') }}</option>
                                            <option value="admin" {{ request('type') == 'admin' ? 'selected' : '' }}>{{ translate('messages.admin') }}</option>
                                            <option value="store" {{ request('type') == 'store' ? 'selected' : '' }}>{{ translate('messages.store') }}</option>
                                            <option value="customer" {{ request('type') == 'customer' ? 'selected' : '' }}>{{ translate('messages.customer') }}</option>
                                            <option value="deliveryman" {{ request('type') == 'deliveryman' ? 'selected' : '' }}>{{ translate('messages.deliveryman') }}</option>
                                        </select>
                                    </div>
                                </div>
                                <!-- Table -->
                                <div class="card-body p-0">
                                    <div class="table-responsive datatable-custom">
                                        <table id="columnSearchDatatable"
                                            class="table table-borderless table-thead-bordered table-align-middle"
                                            data-hs-datatables-options='{
                                        "isResponsive": false,
                                        "isShowPaging": false,
                                        "paging":false,
                                    }'>
                                            <thead class="thead-light">
                                                <tr>
                                                    <th class="border-0">{{ translate('messages.SL') }}</th>
                                                    <th class="border-0">{{ translate('messages.Reason') }}</th>
                                                    <th class="border-0">{{ translate('messages.type') }}</th>
                                                    <th class="border-0">{{ translate('messages.status') }}</th>
                                                    <th class="border-0 text-center">{{ translate('messages.action') }}</th>
                                                </tr>
                                            </thead>

                                            <tbody id="table-div">
                                                @foreach ($reasons as $key => $reason)
                                                    <tr>
                                                        <td>{{ $key + $reasons->firstItem() }}</td>

                                                        <td>
                                                            <span class="d-block font-size-sm text-body" title="{{ $reason->reason }}">
                                                                {{ Str::limit($reason->reason, 25, '...') }}
                                                            </span>
                                                        </td>
                                                        <td>{{ Str::title($reason->user_type) }}</td>
                                                        <td>
                                                            <label class="toggle-switch toggle-switch-sm"
                                                                for="stocksCheckbox{{ $reason->id }}">
                                                                <input type="checkbox"
                                                                       data-url="{{ route('admin.business-settings.order-cancel-reasons.status', [$reason['id'], $reason->status ? 0 : 1]) }}"
                                                                    class="toggle-switch-input redirect-url"
                                                                    id="stocksCheckbox{{ $reason->id }}"
                                                                    {{ $reason->status ? 'checked' : '' }}>
                                                                <span class="toggle-switch-label">
                                                                    <span class="toggle-switch-indicator"></span>
                                                                </span>
                                                            </label>
                                                        </td>

                                                        <td>
                                                            <div class="btn--container justify-content-center">

                                                                <a class="btn btn-sm btn--primary btn-outline-primary action-btn edit-reason"
                                                    title="{{ translate('messages.edit') }}"
                                                    data-toggle="modal"
                                                    data-target="#add_update_reason_{{ $reason->id }}"><i
                                                        class="tio-edit"></i>
                                                </a>


                                                                <a class="btn btn-sm btn--danger btn-outline-danger action-btn form-alert"
                                                                    href="javascript:"
                                                                   data-id="order-cancellation-reason-{{ $reason['id'] }}"
                                                                   data-message="{{ translate('messages.If_you_want_to_delete_this_reason,_please_confirm_your_decision.') }}"
                                                                    title="{{ translate('messages.delete') }}">
                                                                    <i class="tio-delete-outlined"></i>
                                                                </a>
                                                                <form
                                                                    action="{{ route('admin.business-settings.order-cancel-reasons.destroy', $reason['id']) }}"
                                                                    method="post" id="order-cancellation-reason-{{ $reason['id'] }}">
                                                                    @csrf @method('delete')
                                                                </form>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <!-- Modal -->
                                                    <div class="modal fade" id="add_update_reason_{{$reason->id}}" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel"
                                                        aria-hidden="true">
                                                        <div class="modal-dialog" role="document">
                                                            <div class="modal-content">
                                                                <div class="modal-header">
                                                                    <h5 class="modal-title" id="exampleModalLabel">{{ translate('messages.order_cancellation_reason') }}
                                                                        {{ translate('messages.Update') }}</label></h5>
                                                                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                                        <span aria-hidden="true">&times;</span>
                                                                    </button>
                                                                </div>
                                                                    <form action="{{ route('admin.business-settings.order-cancel-reasons.update') }}" method="post">
                                                                <div class="modal-body">
                                                                        @csrf
                                                                        @method('put')

                                                                        @php($reason=  \App\Models\OrderCancelReason::withoutGlobalScope('translate')->with('translations')->find($reason->id))
                                                                        @php($language=\App\Models\BusinessSetting::where('key','language')->first())
                                                                    @php($language = $language->value ?? null)
                                                                    @php($defaultLang = str_replace('_', '-', app()->getLocale()))
                                                                    <ul class="nav nav-tabs nav--tabs mb-3 border-0">
                                                                        <li class="nav-item">
                                                                            <a class="nav-link update-lang_link add_active active"
                                                                            href="#"
                                                                            id="default-link">{{ translate('Default') }}</a>
                                                                        </li>
                                                                        @if($language)
                                                                        @foreach (json_decode($language) as $lang)
                                                                            <li class="nav-item">
                                                                                <a class="nav-link update-lang_link"
                                                                                    href="#"
                                                                                   data-reason-id="{{$reason->id}}"
                                                                                    id="{{ $lang }}-link">{{ \App\CentralLogics\Helpers::get_language_name($lang) . '(' . strtoupper($lang) . ')' }}</a>
                                                                            </li>
                                                                        @endforeach
                                                                        @endif
                                                                    </ul>
                                                                        <input type="hidden" name="reason_id"  value="{{$reason->id}}" />

                                                                        <div class="form-group mb-3 add_active_2  update-lang_form" id="default-form_{{$reason->id}}">
                                                                            <label for="reason" class="form-label">{{translate('Order Cancellation Reason')}} ({{translate('messages.default')}}) </label>
                                                                            <input id="reason" class="form-control" name='reason[]' value="{{$reason?->getRawOriginal('reason')}}" type="text">
                                                                            <input type="hidden" name="lang1[]" value="default">
                                                                        </div>
                                                                                        @if($language)
                                                                                            @forelse(json_decode($language) as $lang)
                                                                                            <?php
                                                                                                if($reason?->translations){
                                                                                                    $translate = [];
                                                                                                    foreach($reason?->translations as $t)
                                                                                                    {
                                                                                                        if($t->locale == $lang && $t->key=="reason"){
                                                                                                            $translate[$lang]['reason'] = $t->value;
                                                                                                        }
                                                                                                    }
                                                                                                }

                                                                                                ?>
                                                                                                <div class="form-group mb-3 d-none update-lang_form" id="{{$lang}}-langform_{{$reason->id}}">
                                                                                                    <label for="reason{{$lang}}" class="form-label">{{translate('Order Cancellation Reason')}} ({{strtoupper($lang)}})</label>
                                                                                                    <input id="reason{{$lang}}" class="form-control" name='reason[]' placeholder="{{ translate('Ex:_Item_is_Broken') }}" value="{{ $translate[$lang]['reason'] ?? null }}"  type="text">
                                                                                                    <input type="hidden" name="lang1[]" value="{{$lang}}">
                                                                                                </div>
                                                                                                @empty
                                                                                                @endforelse
                                                                                                @endif

                                                                        <select name="user_type"  class="form-control h--45px"
                                                                            required>
                                                                            <option value="">{{ translate('messages.select_user_type') }}</option>
                                                                            <option {{ $reason->user_type == 'admin' ? 'selected': '' }} value="admin">{{ translate('messages.admin') }}</option>
                                                                            <option {{ $reason->user_type == 'store' ? 'selected': '' }} value="store">{{ translate('messages.store') }}</option>
                                                                            <option {{ $reason->user_type == 'customer' ? 'selected': '' }} value="customer">{{ translate('messages.customer') }}</option>
                                                                            <option {{ $reason->user_type == 'deliveryman' ? 'selected': '' }} value="deliveryman">{{ translate('messages.deliveryman') }}</option>
                                                                        </select>
                                                                </div>
                                                                <div class="modal-footer">
                                                                    <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ translate('Close') }}</button>
                                                                    <button type="submit" class="btn btn-primary">{{ translate('Save_changes') }}</button>
                                                                </div>
                                                                    </form>
                                                            </div>
                                                        </div>
                                                    </div>
                                                @endforeach
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <!-- End Table -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
    </div>
    <!-- Modal -->
@endsection

@push('script_2')
    <script src="{{asset('public/assets/admin/js/view-pages/business-settings-order-page.js')}}"></script>
@endpush
