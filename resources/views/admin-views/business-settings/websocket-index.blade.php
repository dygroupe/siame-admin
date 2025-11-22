@extends('layouts.admin.app')

@section('title', translate('messages.websocket_settings'))

@section('content')
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-header-title mr-3">
                <span class="page-header-icon">
                    <img src="{{ asset('public/assets/admin/img/business.png') }}" class="w--26" alt="">
                </span>
                <span>
                    {{translate('business_setup')}}
                </span>
            </h1>
            @include('admin-views.business-settings.partials.nav-menu')
        </div>
        <!-- Page Header -->

        <!-- End Page Header -->
        <form action="{{ route('admin.business-settings.update-websocket') }}" method="post" enctype="multipart/form-data">
            @csrf
            <div class="row g-2">
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-6 mt-5">
                                    @php($websocket = \App\Models\BusinessSetting::where('key', 'websocket_status')->first())
                                    @php($websocket = $websocket ? $websocket->value : 0)
                                    <div class="form-group mb-0">
                                        <label
                                            class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                            <span class="pr-1 d-flex align-items-center switch--label">
                                                <span class="line--limit-1">
                                                    {{ translate('messages.websocket') }}
                                                </span>
                                                <span class="form-label-secondary text-danger d-flex"
                                                    data-toggle="tooltip" data-placement="right"
                                                    data-original-title="{{ translate('messages.If_WebSocket_is_enabled,_configure_the_server_accordingly_for_optimal_functionality.')}}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.websocket_toggle') }}"> *
                                                </span>
                                            </span>
                                            <input type="checkbox"
                                                   data-id="websocket"
                                                   data-type="toggle"
                                                   data-image-on="{{ asset('/public/assets/admin/img/modal/schedule-on.png') }}"
                                                   data-image-off="{{ asset('/public/assets/admin/img/modal/schedule-off.png') }}"
                                                   data-title-on="{{translate('messages.Want_to_enable')}} <strong>{{translate('messages.websocket_?')}}</strong>"
                                                   data-title-off="{{translate('messages.Want_to_disable')}} <strong>{{translate('messages.websocket_?')}}</strong>'"
                                                   data-text-on="<p>{{ translate('messages.If_you_enable_this,Deliveyman_last_location_will_be_recorded_by_websocket.') }}</p>"
                                                   data-text-off="<p>{{ translate('messages.If_you_disable_this,Deliveyman_last_location_will_be_recorded_by_default_method.') }}</p>"
                                                   class="status toggle-switch-input dynamic-checkbox-toggle"
                                                   value="1"
                                                name="websocket_status" id="websocket"
                                                {{ $websocket == 1 ? 'checked' : '' }}>
                                            <span class="toggle-switch-label text">
                                                <span class="toggle-switch-indicator"></span>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-6">
                                    @php($websocket_url = \App\Models\BusinessSetting::where('key', 'websocket_url')->first())
                                    <div class="form-group mb-0">
                                        <label class="form-label"
                                            for="websocket_url">{{ translate('messages.websocket_url') }}</label>
                                        <input type="text" id="websocket_url" name="websocket_url" value="{{ $websocket_url->value ?? '' }}"
                                            class="form-control" placeholder="{{ translate('messages.Ex_:_ws://178.128.117.0') }}"
                                            required>
                                    </div>
                                </div>
                                <div class="col-6">
                                @php($websocket_port = \App\Models\BusinessSetting::where('key', 'websocket_port')->first())
                                    <div class="form-group mb-0">
                                        <label class="form-label"
                                            for="websocket_port">{{ translate('messages.websocket_port') }}</label>
                                        <input id="websocket_port" type="number" value="{{ $websocket_port->value ?? '' }}" name="websocket_port"
                                            class="form-control" placeholder="{{ translate('messages.Ex_:_6001') }}" required>
                                    </div>
                                </div>
                            </div>
                            <div class="btn--container justify-content-end">
                                <button type="reset" id="reset_btn" class="btn btn--reset">{{ translate('messages.reset') }}</button>
                                <button type="submit" id="submit" class="btn btn--primary">{{ translate('messages.save_information') }}</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </form>
    </div>
@endsection
