@extends('layouts.admin.app')

@section('title', translate('store_setup'))


@section('content')
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-header-title mr-3">
                <span class="page-header-icon">
                    <img src="{{ asset('public/assets/admin/img/business.png') }}" class="w--26" alt="">
                </span>
                <span>
                    {{ translate('messages.business_setup') }}
                </span>
            </h1>
            @include('admin-views.business-settings.partials.nav-menu')
        </div>
        <form action="{{ route('admin.business-settings.update-store') }}" method="post" enctype="multipart/form-data">
            @csrf
            @php($name = \App\Models\BusinessSetting::where('key', 'business_name')->first())

            <div class="row g-3">
                @php($default_location = \App\Models\BusinessSetting::where('key', 'default_location')->first())
                @php($default_location = $default_location->value ? json_decode($default_location->value, true) : 0)
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="row g-3 align-items-end">
                                <div class="col-lg-4 col-sm-6">
                                    @php($canceled_by_store = \App\Models\BusinessSetting::where('key', 'canceled_by_store')->first())
                                    @php($canceled_by_store = $canceled_by_store ? $canceled_by_store->value : 0)
                                    <div class="form-group mb-0">
                                        <label class="input-label text-capitalize d-flex alig-items-center"><span
                                                class="line--limit-1">{{ translate('messages.Can_a_Vendor_Cancel_Order?') }}
                                            </span><span class="input-label-secondary text--title" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Admin_can_enable/disable_Vendor’s_order_cancellation_option.') }}">
                                                <i class="tio-info-outined"></i>
                                            </span></label>
                                        <div class="restaurant-type-group border">
                                            <label class="form-check form--check mr-2 mr-md-4">
                                                <input class="form-check-input" type="radio" value="1"
                                                    name="canceled_by_store" id="canceled_by_store"
                                                    {{ $canceled_by_store == 1 ? 'checked' : '' }}>
                                                <span class="form-check-label">
                                                    {{ translate('yes') }}
                                                </span>
                                            </label>
                                            <label class="form-check form--check mr-2 mr-md-4">
                                                <input class="form-check-input" type="radio" value="0"
                                                    name="canceled_by_store" id="canceled_by_store2"
                                                    {{ $canceled_by_store == 0 ? 'checked' : '' }}>
                                                <span class="form-check-label">
                                                    {{ translate('no') }}
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-lg-4 col-sm-6">
                                    @php($store_self_registration = \App\Models\BusinessSetting::where('key', 'toggle_store_registration')->first())
                                    @php($store_self_registration = $store_self_registration ? $store_self_registration->value : 0)
                                    <div class="form-group mb-0">

                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{ translate('messages.Vendor_self_registration') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.A_vendor_can_send_a_registration_request_through_their_vendor_or_customer.') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.vendor_self_registration') }}"> *
                                                </span>
                                            </span>
                                            <input type="checkbox"
                                                   data-id="store_self_registration1"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/store-self-reg-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/store-self-reg-off.png') }}"
                                                   data-title-on=""
                                                   data-title-off=""
                                                   data-text-on="<p>{{ translate('messages.If_you_enable_this,_vendors_can_do_self-registration_from_the_vendor_or_customer_app_or_website.') }}</p>"
                                                   data-text-off="<p>{{ translate('messages.If_you_disable_this,_the_Vendor_Self-Registration_feature_will_be_hidden_from_the_vendor_or_customer_app,_website,_or_admin_landing_page.') }}</p>"
                                                   class="status toggle-switch-input dynamic-checkbox-toggle"
                                                   value="1"
                                                name="store_self_registration" id="store_self_registration1"
                                                {{ $store_self_registration == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>

                                <div class="col-sm-6 col-lg-4">
                                    @php($product_gallery = \App\Models\BusinessSetting::where('key', 'product_gallery')->first()?->value ?? 0)
                                    <div class="form-group mb-0">
                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{translate('messages.Product_Gallery') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.If_you_enable_this,_any_vendor_can_duplicate_product_and_create_a_new_product_by_use_this.')}}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.Product_Gallery') }}"> *
                                                </span>
                                            </span>
                                            <input type="checkbox"

                                                   data-id="product_gallery"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/store-reg-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/store-reg-off.png') }}"
                                                   data-title-on="<strong>{{translate('messages.Want_to_enable_product_gallery?')}}</strong>"
                                                   data-title-off="<strong>{{translate('messages.Want_to_disable_product_gallery?')}}</strong>"
                                                   data-text-on="<p>{{ translate('messages.If_you_enable_this,can_create_duplicate_products') }}</p>"
                                                   data-text-off="<p>{{ translate('messages.If_you_disable_this,can_not_create_duplicate_products.') }}</p>"
                                                   class="status toggle-switch-input dynamic-checkbox-toggle"
                                                   value="1"
                                                name="product_gallery" id="product_gallery"
                                                {{ $product_gallery == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-sm-6 col-lg-4 {{ $product_gallery == 1 ? ' ' : 'd-none' }}  access_all_products">
                                    @php($access_all_products = \App\Models\BusinessSetting::where('key', 'access_all_products')->first()?->value ?? 0)
                                    <div class="form-group mb-0">
                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{translate('messages.access_all_products') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.If_you_enable_this_vendors_can_access_all_products_of_other_vendors.')}}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.access_all_products') }}"> *
                                                </span>
                                            </span>
                                            <input type="checkbox"

                                                   data-id="access_all_products"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/store-reg-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/store-reg-off.png') }}"
                                                   data-title-on="<strong>{{translate('messages.Want_to_enable_access_all_products?')}}</strong>"
                                                   data-title-off="<strong>{{translate('messages.Want_to_disable_access_all_products?')}}</strong>"
                                                   data-text-on="<p>{{ translate('messages.If_you_enable_this,_vendors_can_access_all_products_of_other_available_vendors') }}</p>"
                                                   data-text-off="<p>{{ translate('messages.If_you_disable_this,_vendors_can_not_access_all_products_of_other_vendors.') }}</p>"
                                                   class="status toggle-switch-input dynamic-checkbox-toggle"
                                                   value="1"
                                                name="access_all_products" id="access_all_products"
                                                {{ $access_all_products == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-lg-4 col-sm-6">
                                    @php($product_approval = \App\Models\BusinessSetting::where('key', 'product_approval')->first()?->value ?? 0)
                                    <div class="form-group mb-0">
                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{translate('messages.Need_Approval_for_Products') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.If_enabled,_this_option_to_require_admin_approval_for_products_to_be_displayed_on_the_user_side.')}}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.customer_verification_toggle') }}"> *
                                                </span>
                                            </span>
                                            <input type="checkbox"
                                                   data-id="product_approval"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/store-reg-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/store-reg-off.png') }}"
                                                   data-title-on="<strong>{{translate('messages.Want_to_enable_product_approval?')}}</strong>"
                                                   data-title-off="<strong>{{translate('messages.Want_to_disable_product_approval?')}}</strong>"
                                                   data-text-on="<p>{{ translate('messages.If_you_enable_this,_option_to_require_admin_approval_for_products_to_be_displayed_on_the_user_side') }}</p>"
                                                   data-text-off="<p>{{ translate('messages.If_you_disable_this,products_will_to_be_displayed_on_the_user_side_without_admin_approval.') }}</p>"
                                                   class="status toggle-switch-input dynamic-checkbox-toggle"
                                                   value="1"
                                                name="product_approval" id="product_approval"
                                                {{ $product_approval == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-lg-4 col-sm-6">
                                    @php($store_review_reply = \App\Models\BusinessSetting::where('key', 'store_review_reply')->first())
                                    @php($store_review_reply = $store_review_reply ? $store_review_reply->value : 0)
                                    <div class="form-group mb-0">

                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{ translate('Vendor_Can_Reply_Review') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                      data-toggle="tooltip" data-placement="right"
                                                      data-original-title="{{ translate('If enabled, vendors can actively engage with the customers by responding to the reviews left for their orders') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.store_review_reply') }}">
                                                </span>
                                            </span>
                                            <input type="checkbox"

                                                   data-id="store_review_reply1"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/store-self-reg-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/store-self-reg-off.png') }}"
                                                   data-title-on="{{ translate('Want to enable the option vendor to reply?') }}"
                                                   data-title-off="{{ translate('Want_to_disable_the_option_vendor_to_reply?') }}"
                                                   data-text-on="<p>{{ translate('If enabled, vendors can actively engage with the customers by responding to the reviews left for their orders.') }}</p>"
                                                   data-text-off="<p>{{ translate('If_disabled,_a_vendor_can_not_reply_to_a_review') }}</p>"
                                                   class="toggle-switch-input dynamic-checkbox-toggle"

                                                   value="1"
                                                   name="store_review_reply" id="store_review_reply1"
                                                {{ $store_review_reply == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            @php($product_approval_datas = \App\Models\BusinessSetting::where('key', 'product_approval_datas')->first()?->value ?? '')
                            @php($product_approval_datas =json_decode($product_approval_datas , true))
                            <div class="mt-4  mb-4 access_product_approval">
                                <label class="mb-2 input-label text-capitalize d-flex alig-items-center" for=""> {{ translate('Need_Approval_When') }}</label>
                                <div class="justify-content-between border form-control">
                                    <div class="form-check form-check-inline mx-4  ">
                                        <input class="mx-2 form-check-input" type="checkbox" {{  data_get($product_approval_datas,'Add_new_product',null) == 1 ? 'checked' :'' }} id="inlineCheckbox1" value="1" name="Add_new_product" {{  $product_approval == 1 ? ' ' : 'disabled'}}>
                                        <label class=" form-check-label" for="inlineCheckbox1">{{ translate('Add_new_product') }}</label>
                                    </div>
                                    <div class="form-check form-check-inline mx-4  ">
                                        <input class="mx-2 form-check-input" type="checkbox"  {{  data_get($product_approval_datas,'Update_product_price',null) == 1 ? 'checked' :'' }} id="inlineCheckbox2" value="1" name="Update_product_price" {{  $product_approval == 1 ? ' ' : 'disabled'}}>
                                        <label class=" form-check-label" for="inlineCheckbox2">{{ translate('Update_product_price') }}</label>
                                    </div>
                                    <div class="form-check form-check-inline mx-4  ">
                                        <input class="mx-2 form-check-input" type="checkbox" {{  data_get($product_approval_datas,'Update_product_variation',null) == 1 ? 'checked' :'' }}  id="inlineCheckbox3" value="1" name="Update_product_variation" {{  $product_approval == 1 ? ' ' : 'disabled'}}>
                                        <label class=" form-check-label" for="inlineCheckbox3">{{ translate('Update_product_variation') }}</label>
                                    </div>
                                    <div class="form-check form-check-inline mx-4  ">
                                        <input class="mx-2 form-check-input" type="checkbox"  {{  data_get($product_approval_datas,'Update_anything_in_product_details',null) == 1 ? 'checked' :'' }} id="inlineCheckbox4" value="1" name="Update_anything_in_product_details" {{  $product_approval == 1 ? ' ' : 'disabled'}}>
                                        <label class=" form-check-label" for="inlineCheckbox4">{{ translate('Update_anything_in_product_details') }}</label>
                                    </div>
                                </div>
                            </div>



                            <div class="row g-3 align-items-end">
                            <div class="col-lg-4 col-sm-6">
                                @php($cash_in_hand_overflow = \App\Models\BusinessSetting::where('key', 'cash_in_hand_overflow_store')->first())
                                @php($cash_in_hand_overflow = $cash_in_hand_overflow ? $cash_in_hand_overflow->value : '')
                                <div class="form-group mb-0">

                                    <label
                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{ translate('messages.Cash_In_Hand_Overflow') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                      data-toggle="tooltip" data-placement="right"
                                                      data-original-title="{{ translate('If_enabled,_vendors_will_be_automatically_suspended_by_the_system_when_their_‘Cash_in_Hand’_limit_is_exceeded.') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.cash_in_hand_overflow') }}"> *
                                                </span>
                                            </span>
                                        <input type="checkbox"
                                               data-id="cash_in_hand_overflow"
                                               data-type="toggle"
                                               data-image-on="{{ asset('/public/assets/admin/img/modal/show-earning-in-apps-on.png') }}"
                                               data-image-off="{{ asset('/public/assets/admin/img/modal/show-earning-in-apps-off.png') }}"
                                               data-title-on="{{translate('Want_to_enable')}} <strong>{{translate('Cash_In_Hand_Overflow')}}</strong>"
                                               data-title-off="{{translate('Want_to_disable')}} <strong>{{translate('Cash_In_Hand_Overflow')}}</strong> "
                                               data-text-on="<p>{{ translate('If_enabled,_vendors_have_to_provide_collected_cash_by_them_self') }}</p>"
                                               data-text-off="<p>{{ translate('If_disabled,_vendors_do_not_have_to_provide_collected_cash_by_them_self') }}</p>"
                                               class="status toggle-switch-input dynamic-checkbox-toggle"
                                                value="1"
                                               name="cash_in_hand_overflow_store" id="cash_in_hand_overflow"
                                            {{ $cash_in_hand_overflow == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                    </label>
                                </div>
                            </div>





                            <div class="col-lg-4 col-sm-6">
                                @php($cash_in_hand_overflow_store_amount = \App\Models\BusinessSetting::where('key', 'cash_in_hand_overflow_store_amount')->first())
                                <div class="form-group mb-0">
                                    <label class=" input-label text-capitalize"
                                           for="cash_in_hand_overflow_store_amount">
                                            <span>
                                                {{ translate('Maximum_Amount_to_Hold_Cash_in_Hand') }} ({{ \App\CentralLogics\Helpers::currency_symbol() }})
                                            </span>

                                        <span class="form-label-secondary"
                                              data-toggle="tooltip" data-placement="right"
                                              data-original-title="{{ translate('Enter_the_maximum_cash_amount_vendors_can_hold._If_this_number_exceeds,_vendors_will_be_suspended_and_not_receive_any_orders.') }}"><img
                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                alt="{{ translate('messages.dm_cancel_order_hint') }}"></span>
                                    </label>
                                    <input type="number" name="cash_in_hand_overflow_store_amount" class="form-control"
                                           id="cash_in_hand_overflow_store_amount" min="0" step=".001"
                                           value="{{ $cash_in_hand_overflow_store_amount ? $cash_in_hand_overflow_store_amount->value : '' }}"  {{ $cash_in_hand_overflow  == 1 ? 'required' : 'readonly' }} >
                                </div>
                            </div>


                            <div class="col-lg-4 col-sm-6">
                                @php($min_amount_to_pay_store = \App\Models\BusinessSetting::where('key', 'min_amount_to_pay_store')->first())
                                <div class="form-group mb-0">
                                    <label class=" input-label text-capitalize"
                                           for="min_amount_to_pay_store">
                                            <span>
                                                {{ translate('Minimum_Amount_To_Pay') }} ({{ \App\CentralLogics\Helpers::currency_symbol() }})

                                            </span>

                                        <span class="form-label-secondary"
                                              data-toggle="tooltip" data-placement="right"
                                              data-original-title="{{ translate('Enter_the_minimum_cash_amount_vendors_can_pay') }}"><img
                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                alt="{{ translate('messages.dm_cancel_order_hint') }}"></span>
                                    </label>
                                    <input type="number" name="min_amount_to_pay_store" class="form-control"
                                           id="min_amount_to_pay_store" min="0" step=".001"
                                           value="{{ $min_amount_to_pay_store ? $min_amount_to_pay_store->value : '' }}"  {{ $cash_in_hand_overflow  == 1 ? 'required' : 'readonly' }} >
                                </div>
                            </div>
                            </div>


                            <div class="btn--container justify-content-end mt-20">
                                <button type="reset" class="btn btn--reset">{{ translate('messages.reset') }}</button>
                                <button type="{{ env('APP_MODE') != 'demo' ? 'submit' : 'button' }}"
                                    class="btn btn--primary call-demo">{{ translate('save_information') }}</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>


        </form>
    </div>

@endsection

