@extends('layouts.admin.app')

@section('title', translate('messages.add_store_name'))



@section('content')
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-header-title">
                <span class="page-header-icon">
                    <img src="{{ asset('public/assets/admin/img/store.png') }}" class="w--26" alt="">
                </span>
                <span>
                    {{ translate('messages.add_new_store') }}
                </span>
            </h1>
        </div>

        @php($language = \App\CentralLogics\Helpers::get_business_settings('language'))
        <!-- End Page Header -->
        <form enctype="multipart/form-data" class="custom-validation" data-ajax="true" id="vendor_form">
            <div class="row g-2">
                <div class="col-lg-6">
                    <div class="card shadow--card-2">
                        <div class="card-body">
                            @if ($language)
                                <ul class="nav nav-tabs mb-4">
                                    <li class="nav-item">
                                        <a class="nav-link lang_link active" href="#"
                                            id="default-link">{{ translate('Default') }}</a>
                                    </li>
                                    @foreach ($language as $lang)
                                        <li class="nav-item">
                                            <a class="nav-link lang_link" href="#"
                                                id="{{ $lang }}-link">{{ \App\CentralLogics\Helpers::get_language_name($lang) . '(' . strtoupper($lang) . ')' }}</a>
                                        </li>
                                    @endforeach
                                </ul>
                            @endif
                            @if ($language)
                                <div class="lang_form" id="default-form">
                                    <div class="form-group error-wrapper">
                                        <label class="input-label" for="default_name">{{ translate('messages.name') }}
                                            ({{ translate('messages.Default') }}) <span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span>
                                        </label>
                                        <input type="text" name="name[]" id="default_name" class="form-control"
                                            placeholder="{{ translate('messages.store_name') }}" required>
                                    </div>
                                    <input type="hidden" name="lang[]" value="default">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label"
                                            for="exampleFormControlInput1">{{ translate('messages.address') }}
                                            ({{ translate('messages.default') }})<span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <textarea type="text" name="address[]" placeholder="{{ translate('messages.store') }}"
                                            class="form-control min-h-90px ckeditor"></textarea>

                                    </div>
                                </div>
                                @foreach ($language as $lang)
                                    <div class="d-none lang_form" id="{{ $lang }}-form">
                                        <div class="form-group error-wrapper">
                                            <label class="input-label"
                                                for="{{ $lang }}_name">{{ translate('messages.name') }}
                                                ({{ strtoupper($lang) }})
                                            </label>
                                            <input type="text" name="name[]" id="{{ $lang }}_name"
                                                class="form-control" placeholder="{{ translate('messages.store_name') }}">
                                        </div>
                                        <input type="hidden" name="lang[]" value="{{ $lang }}">
                                        <div class="form-group mb-0 error-wrapper">
                                            <label class="input-label"
                                                for="exampleFormControlInput1">{{ translate('messages.address') }}
                                                ({{ strtoupper($lang) }})</label>
                                            <textarea type="text" name="address[]" placeholder="{{ translate('messages.store') }}"
                                                class="form-control min-h-90px ckeditor"></textarea>
                                        </div>
                                    </div>
                                @endforeach
                            @else
                                <div id="default-form">
                                    <div class="form-group error-wrapper">
                                        <label class="input-label"
                                            for="exampleFormControlInput1">{{ translate('messages.name') }}
                                            ({{ translate('messages.default') }})</label>
                                        <input type="text" name="name[]" class="form-control"
                                            placeholder="{{ translate('messages.store_name') }}" required>

                                    </div>
                                    <input type="hidden" name="lang[]" value="default">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label"
                                            for="exampleFormControlInput1">{{ translate('messages.address') }}
                                        </label>
                                        <textarea type="text" name="address[]" placeholder="{{ translate('messages.store') }}"
                                            class="form-control min-h-90px ckeditor"></textarea>

                                    </div>
                                </div>
                            @endif
                        </div>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="card shadow--card-2">
                        <div class="card-header">
                            <h5 class="card-title">
                                <span class="card-header-icon mr-1"><i class="tio-dashboard"></i></span>
                                <span>{{ translate('Store Logo & Covers') }}</span>
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="d-flex flex-wrap flex-sm-nowrap __gap-12px gap-lg-5">
                                <div class="error-wrapper">
                                    <div class="__custom-upload-img">

                                        <label class="form-label">
                                            {{ translate('logo') }} <span class="text--primary">({{ translate('1:1') }})
                                                <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                    data-placement="right"
                                                    data-original-title="{{ translate('messages.Required.') }}"> *
                                                </span></span>
                                        </label>
                                        <label class="text-center position-relative">
                                            <img class="img--110 min-height-170px min-width-170px onerror-image image--border"
                                                id="viewer"
                                                data-onerror-image="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                src="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                alt="logo image" />
                                            <div class="icon-file-group">
                                                <div class="icon-file">
                                                    <i class="tio-edit"></i>
                                                    <input type="file" name="logo" id="customFileEg1"
                                                        class="custom-file-input" required
                                                         accept="{{ IMAGE_EXTENSION }}">
                                                </div>
                                            </div>
                                        </label>

                                    </div>
                                </div>

                                <div class="error-wrapper">
                                    <div class="__custom-upload-img">

                                        <label class="form-label">
                                            {{ translate('Store Cover') }} <span
                                                class="text--primary">({{ translate('2:1') }}) </span>
                                        </label>
                                        <label class="text-center position-relative">
                                            <img class="img--vertical min-height-170px min-width-170px onerror-image image--border"
                                                id="coverImageViewer"
                                                data-onerror-image="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                src="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                alt="Fav icon" />
                                            <div class="icon-file-group">
                                                <div class="icon-file">
                                                    <i class="tio-edit"></i>
                                                    <input type="file" name="cover_photo" id="coverImageUpload"
                                                        class="custom-file-input"
                                                        accept="{{ IMAGE_EXTENSION }}"
                                                        data-max-size="2mb">
                                                </div>
                                            </div>
                                        </label>
                                    </div>
                                </div>

                            </div>
                            <small class="d-flex fs-10 justify-content-center">
                                     <span>{{ translate(IMAGE_FORMAT.'. ' . 'Less Than 2MB') }}</span>
                                 </small>
                        </div>
                    </div>
                </div>
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="card-title m-0 d-flex align-items-center">
                                <img class="mr-2 align-self-start w--20"
                                    src="{{ asset('public/assets/admin/img/resturant.png') }}" alt="instructions">
                                <span>{{ translate('store_information') }}</span>
                            </h4>
                        </div>
                        <div class="card-body">
                            <div class="row g-3 my-0">
                                <div class="col-md-12">
                                    <div class="position-relative">
                                        <label class="input-label"
                                            for="tax">{{ translate('Estimated Delivery Time ( Min & Maximum Time)') }}
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <div class="error-wrapper">
                                            <input type="text" id="time_view" class="form-control" readonly required>
                                        </div>
                                        <a href="javascript:void(0)" class="floating-date-toggler">&nbsp;</a>
                                        <span class="offcanvas"></span>
                                        <div class="floating--date" id="floating--date">
                                            <div class="card shadow--card-2">
                                                <div class="card-body">
                                                    <div class="floating--date-inner">
                                                        <div class="item error-wrapper">
                                                            <label class="input-label"
                                                                for="minimum_delivery_time">{{ translate('Minimum Time') }}</label>
                                                            <input id="minimum_delivery_time" type="number"
                                                                name="minimum_delivery_time" class="form-control h--45px"
                                                                placeholder="{{ translate('messages.Ex :') }} 30"
                                                                pattern="^[0-9]{2}$" required
                                                                value="{{ old('minimum_delivery_time') }}">
                                                        </div>
                                                        <div class="item error-wrapper">
                                                            <label class="input-label"
                                                                for="maximum_delivery_time">{{ translate('Maximum Time') }}</label>
                                                            <input id="maximum_delivery_time" type="number"
                                                                name="maximum_delivery_time" class="form-control h--45px"
                                                                placeholder="{{ translate('messages.Ex :') }} 60"
                                                                pattern="[0-9]{2}" required
                                                                value="{{ old('maximum_delivery_time') }}">
                                                        </div>
                                                        <div class="item smaller">
                                                            <select name="delivery_time_type" id="delivery_time_type"
                                                                class="custom-select">
                                                                <option value="min">{{ translate('messages.minutes') }}
                                                                </option>
                                                                <option value="hours">{{ translate('messages.hours') }}
                                                                </option>
                                                                <option value="days">{{ translate('messages.days') }}
                                                                </option>
                                                            </select>
                                                        </div>
                                                        <div class="item smaller">
                                                            <button type="button"
                                                                class="btn btn--primary delivery-time">{{ translate('done') }}</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="row g-3 my-0">
                                <div class="col-lg-4">
                                    <div class="form-group error-wrapper">
                                        <label class="input-label"
                                            for="choice_zones">{{ translate('messages.zone') }}<span
                                                class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                                data-original-title="{{ translate('messages.select_zone_for_map') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.select_zone_for_map') }}"></span>
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span>
                                        </label>
                                        <select name="zone_id" id="choice_zones" required
                                            class="form-control js-select2-custom"
                                            data-placeholder="{{ translate('messages.select_zone') }}">
                                            <option value="" selected disabled>
                                                {{ translate('messages.select_zone') }}</option>
                                            @foreach (\App\Models\Zone::active()->get(['id', 'name']) as $zone)
                                                @if (isset(auth('admin')->user()->zone_id))
                                                    @if (auth('admin')->user()->zone_id == $zone->id)
                                                        <option value="{{ $zone->id }}">{{ $zone->name }}</option>
                                                    @endif
                                                @else
                                                    <option value="{{ $zone->id }}">{{ $zone->name }}</option>
                                                @endif
                                            @endforeach
                                        </select>
                                    </div>
                                    <div class="form-group error-wrapper">
                                        <label class="input-label" for="latitude">{{ translate('messages.latitude') }}
                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.store_lat_lng_warning') }}">
                                                <img src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.store_lat_lng_warning') }}"></span>
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span>
                                        </label>
                                        <input type="text" id="latitude" name="latitude" class="form-control"
                                            placeholder="{{ translate('messages.Ex:') }} -94.22213"
                                            value="{{ old('latitude') }}" required readonly>

                                    </div>
                                    <div class="form-group mb-5 error-wrapper">
                                        <label class="input-label" for="longitude">{{ translate('messages.longitude') }}
                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.store_lat_lng_warning') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.store_lat_lng_warning') }}">
                                            </span>
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span>
                                        </label>
                                        <input type="text" name="longitude" class="form-control"
                                            placeholder="{{ translate('messages.Ex:') }} 103.344322" id="longitude"
                                            value="{{ old('longitude') }}" required readonly>

                                    </div>
                                </div>
                                <div class="col-lg-8">
                                    <input id="pac-input" class="controls rounded" data-toggle="tooltip"
                                        data-placement="right"
                                        data-original-title="{{ translate('messages.search_your_location_here') }}"
                                        type="text" placeholder="{{ translate('messages.search_here') }}" />
                                    <div id="map"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="card-title m-0 d-flex align-items-center">
                                <span class="card-header-icon mr-2"><i class="tio-user"></i></span>
                                <span>{{ translate('messages.owner_information') }}</span>
                            </h4>
                        </div>
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-md-4 col-sm-6">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label" for="f_name">{{ translate('messages.first_name') }}
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <input type="text" name="f_name" class="form-control"
                                            placeholder="{{ translate('messages.first_name') }}"
                                            value="{{ old('f_name') }}" required>

                                    </div>
                                </div>
                                <div class="col-md-4 col-sm-6">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label"
                                            for="l_name">{{ translate('messages.last_name') }}<span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <input type="text" name="l_name" class="form-control"
                                            placeholder="{{ translate('messages.last_name') }}"
                                            value="{{ old('l_name') }}" required>

                                    </div>

                                </div>
                                <div class="col-md-4 col-sm-6">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label" for="phone">{{ translate('messages.phone') }}<span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <input type="tel" id="phone" name="phone" class="form-control"
                                            placeholder="{{ translate('messages.Ex:') }} 017********" required>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="card-title m-0 d-flex align-items-center">
                                <span class="card-header-icon mr-2"><i class="tio-user"></i></span>
                                <span>{{ translate('messages.account_information') }}</span>
                            </h4>
                        </div>
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-md-4 col-12">
                                    <div class="form-group mb-0 error-wrapper">
                                        <label class="input-label" for="email">{{ translate('messages.email') }}<span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <input type="email" name="email" class="form-control"
                                            placeholder="{{ translate('messages.Ex:') }} ex@example.com"
                                            value="{{ old('email') }}" required>
                                    </div>
                                </div>
                                <div class="col-md-4 col-12">
                                    <div class="form-group error-wrapper mb-0">
                                        <label class="input-label"
                                            for="signupSrPassword">{{ translate('messages.password') }}<span
                                                class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                                data-original-title="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"></span>
                                            <span class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>

                                        <div class="input-group input-group-merge">
                                            <input type="password" class="js-toggle-password form-control"
                                                name="password" id="signupSrPassword"
                                                pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
                                                title="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"
                                                placeholder="{{ translate('messages.password_length_placeholder', ['length' => '8+']) }}"
                                                aria-label="8+ characters required" required
                                                data-msg="Your password is invalid. Please try again."
                                                data-hs-toggle-password-options='{
                                            "target": [".js-toggle-password-target-1", ".js-toggle-password-target-2"],
                                            "defaultClass": "tio-hidden-outlined",
                                            "showClass": "tio-visible-outlined",
                                            "classChangeTarget": ".js-toggle-passowrd-show-icon-1"
                                            }'>
                                            <div class="js-toggle-password-target-1 input-group-append">
                                                <a class="input-group-text" href="javascript:">
                                                    <i class="js-toggle-passowrd-show-icon-1 tio-visible-outlined"></i>
                                                </a>
                                            </div>
                                        </div>

                                    </div>
                                </div>
                                <div class="col-md-4 col-12">
                                    <div class="form-group error-wrapper mb-0">
                                        <label class="input-label"
                                            for="signupSrConfirmPassword">{{ translate('messages.confirm_password') }}<span
                                                class="form-label-secondary text-danger" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Required.') }}"> *
                                            </span></label>
                                        <div class="input-group input-group-merge">
                                            <input type="password" class="js-toggle-password form-control"
                                                name="confirmPassword" id="signupSrConfirmPassword"
                                                pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
                                                title="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"
                                                placeholder="{{ translate('messages.password_length_placeholder', ['length' => '8+']) }}"
                                                aria-label="8+ characters required" required
                                                data-msg="Password does not match the confirm password."
                                                data-hs-toggle-password-options='{
                                                    "target": [".js-toggle-password-target-1", ".js-toggle-password-target-2"],
                                                    "defaultClass": "tio-hidden-outlined",
                                                    "showClass": "tio-visible-outlined",
                                                    "classChangeTarget": ".js-toggle-passowrd-show-icon-2"
                                                    }'>
                                            <div class="js-toggle-password-target-2 input-group-append">
                                                <a class="input-group-text" href="javascript:">
                                                    <i class="js-toggle-passowrd-show-icon-2 tio-visible-outlined"></i>
                                                </a>
                                            </div>
                                        </div>

                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-12">
                    <div>
                        <div class="card p-20">
                            <div class="mb-20">
                                <h3 class="mb-1">{{ translate('Business TIN') }}</h3>
                                {{-- <p class="fz-12px mb-0">{{translate('Lorem ipsum dolor sit amet, consectetur adipiscing elit.')}}</p> --}}
                            </div>
                            <div class="row g-3">
                                <div class="col-md-8 col-xxl-9">
                                    <div class="bg--secondary rounded p-20 h-100">
                                        <div class="form-group  error-wrapper">
                                            <label class="input-label mb-2 d-block title-clr fw-normal"
                                                for="exampleFormControlInput1">{{ translate('Taxpayer Identification Number(TIN)') }}
                                            </label>
                                            <input type="text" name="tin"
                                                placeholder="{{ translate('Type Your Taxpayer Identification Number(TIN)') }}"
                                                class="form-control">
                                        </div>
                                        <div class="form-group mb-0  error-wrapper">
                                            <label class="input-label mb-2 d-block title-clr fw-normal"
                                                for="exampleFormControlInput1">{{ translate('Expire Date') }} </label>
                                            <input type="date"  name="tin_expire_date" class="form-control">
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4 col-xxl-3">
                                    <div class="bg--secondary rounded p-20 h-100 single-document-uploaderwrap">
                                        <div class="d-flex align-items-center gap-1 justify-content-between mb-20">
                                            <div>
                                                <h4 class="mb-1 fz--14px">{{ translate('TIN Certificate') }}</h4>
                                                <p class="fz-12px mb-0">
                                                    {{ translate('pdf, doc, jpg. File size : max 2 MB') }}</p>
                                            </div>
                                            <div class="d-flex gap-3 align-items-center">
                                                <button type="button" id="doc_edit_btn"
                                                    class="w-30px h-30 rounded d-flex align-items-center justify-content-center btn--primary btn px-3 icon-btn">
                                                    <i class="tio-edit"></i>
                                                </button>
                                            </div>
                                        </div>
                                        <div class="form-group error-wrapper">
                                            <div id="file-assets"
                                                data-picture-icon="{{ asset('public/assets/admin/img/picture.svg') }}"
                                                data-document-icon="{{ asset('public/assets/admin/img/document.svg') }}"
                                                data-blank-thumbnail="{{ asset('public/assets/admin/img/picture.svg') }}">
                                            </div>
                                            <!-- Upload box -->
                                            <div class="d-flex justify-content-center mb-2" id="pdf-container">
                                                <div class="document-upload-wrapper" id="doc-upload-wrapper">
                                                    <input type="file" name="tin_certificate_image"
                                                        class="document_input" accept=".doc, .pdf, .jpg, .png, .jpeg"
                                                        data-max-size="2mb">
                                                    <div class="textbox">
                                                        <img width="40" height="40" class="svg"
                                                            src="{{ asset('public/assets/admin/img/doc-uploaded.png') }}"
                                                            alt="">
                                                        <p class="fs-12 mb-0">
                                                            {{ translate('messages.Select_a_file_or') }} <span
                                                                class="font-semibold">{{ translate('messages.Drag & Drop') }}</span>
                                                            {{ translate('messages.here') }}</p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-12">
                    <div class="btn--container justify-content-end">
                        <button type="reset" id="reset_btn"
                            class="btn btn--reset">{{ translate('messages.reset') }}</button>
                        <button type="submit" id="submitButton"
                            class="btn btn--primary">{{ translate('messages.submit') }}</button>
                    </div>
                </div>
            </div>
        </form>
    </div>

@endsection

@push('script_2')
    <script src="{{ asset('public/assets/admin/js/file-preview/pdf.min.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/file-preview/pdf-worker.min.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/file-preview/add-multiple-document-upload.js') }}"></script>

    <script src="{{ asset('public/assets/admin/js/spartan-multi-image-picker.js') }}"></script>
    <script
        src="https://maps.googleapis.com/maps/api/js?key={{ \App\CentralLogics\Helpers::get_business_settings('map_api_key') }}&libraries=places,marker&callback=initMap&v=3.61">
    </script>

    <script>
        "use strict";

        $('#vendor_form').on('submit', function(e) {
            $('#submitButton').attr('disabled', true);
            e.preventDefault();
            let $form = $(this);
            if (!$form.valid()) {
                return false;
            }

            let formData = new FormData(this);
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                }
            });
            $.post({
                url: '{{ route('admin.store.store') }}',
                data: $('#vendor_form').serialize(),
                data: formData,
                cache: false,
                contentType: false,
                processData: false,
                beforeSend: function() {
                    $('#loading').show();
                },
                success: function(data) {
                    $('#loading').hide();
                    if (data.errors) {
                        for (let i = 0; i < data.errors.length; i++) {
                            toastr.error(data.errors[i].message, {
                                CloseButton: true,
                                ProgressBar: true
                            });
                        }
                    } else {
                        toastr.success("{{ translate('store_added_successfully') }}", {
                            CloseButton: true,
                            ProgressBar: true
                        });
                        setTimeout(function() {
                            location.href =
                                "{{ route('admin.store.list') }}";
                        }, 1000);
                    }
                }
            });
        });


        $(document).on('ready', function() {
            $('.offcanvas').on('click', function() {
                $('.offcanvas, .floating--date').removeClass('active')
            })
            $('.floating-date-toggler').on('click', function() {
                $('.offcanvas, .floating--date').toggleClass('active')
            })
            @if (isset(auth('admin')->user()->zone_id))
                $('#choice_zones').trigger('change');
            @endif
        });

        function readURL(input, viewer) {
            if (input.files && input.files[0]) {
                let reader = new FileReader();

                reader.onload = function(e) {
                    $('#' + viewer).attr('src', e.target.result);
                }

                reader.readAsDataURL(input.files[0]);
            }
        }

        $("#customFileEg1").change(function() {
            readURL(this, 'viewer');
        });

        $("#coverImageUpload").change(function() {
            readURL(this, 'coverImageViewer');
        });




        @php($default_location = \App\CentralLogics\Helpers::get_business_settings('default_location'))
        let myLatlng = {
            lat: {{ $default_location ? $default_location['lat'] : '23.757989' }},
            lng: {{ $default_location ? $default_location['lng'] : '90.360587' }}
        };
        const mapId = "{{ \App\CentralLogics\Helpers::get_business_settings('map_api_key') }}"

        let map = new google.maps.Map(document.getElementById("map"), {
            zoom: 13,
            center: myLatlng,
            mapId: mapId,
        });
        let zonePolygon = null;
        let infoWindow = new google.maps.InfoWindow({
            content: "Click the map to get Lat/Lng!",
            position: myLatlng,
        });
        let bounds = new google.maps.LatLngBounds();

        function initMap() {
            // Create the initial InfoWindow.
            infoWindow.open(map);
            //get current location block
            infoWindow = new google.maps.InfoWindow();
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
                const bounds = new google.maps.LatLngBounds();
                places.forEach((place) => {
                    document.getElementById('latitude').value = place.geometry.location.lat();
                    document.getElementById('longitude').value = place.geometry.location.lng();
                    if (!place.geometry || !place.geometry.location) {
                        console.log("Returned place contains no geometry");
                        return;
                    }
                    const {
                        AdvancedMarkerElement
                    } = google.maps.marker;

                    // Create a marker for each place.
                    markers.push(
                        new AdvancedMarkerElement({
                            map,
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
        }
        initMap();

        function handleLocationError(browserHasGeolocation, infoWindow, pos) {
            infoWindow.setPosition(pos);
            infoWindow.setContent(
                browserHasGeolocation ?
                "Error: The Geolocation service failed." :
                "Error: Your browser doesn't support geolocation."
            );
            infoWindow.open(map);
        }
        $('#choice_zones').on('change', function() {
            let id = $(this).val();
            $.get({
                url: '{{ url('/') }}/admin/zone/get-coordinates/' + id,
                dataType: 'json',
                success: function(data) {
                    if (zonePolygon) {
                        zonePolygon.setMap(null);
                    }
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
                            content: JSON.stringify(mapsMouseEvent.latLng.toJSON(),
                                null, 2),
                        });
                        let coordinates = JSON.stringify(mapsMouseEvent.latLng.toJSON(), null,
                            2);
                        coordinates = JSON.parse(coordinates);
                        document.getElementById('latitude').value = coordinates['lat'];
                        document.getElementById('longitude').value = coordinates['lng'];
                        infoWindow.open(map);
                    });
                },
            });
        });

        $("#vendor_form").on('keydown', function(e) {
            if (e.keyCode === 13) {
                e.preventDefault();
            }
        })

        $('#reset_btn').click(function() {
            $('#viewer').attr('src', "{{ asset('public/assets/admin/img/upload-img.png') }}");
            $('#customFileEg1').val(null);
            $('#coverImageViewer').attr('src', "{{ asset('public/assets/admin/img/upload-img.png') }}");
            $('#coverImageUpload').val(null);
            $('#choice_zones').val(null).trigger('change');
            zonePolygon.setMap(null);
            $('#coordinates').val(null);
            $('#latitude').val(null);
            $('#longitude').val(null);
        })

        let zone_id = 0;
        $('#choice_zones').on('change', function() {
            if ($(this).val()) {
                zone_id = $(this).val();
            }
        });



        $('.delivery-time').on('click', function() {
            let min = $("#minimum_delivery_time").val();
            let max = $("#maximum_delivery_time").val();
            let type = $("#delivery_time_type").val();
            $("#floating--date").removeClass('active');
            $("#time_view").val(min + ' to ' + max + ' ' + type);

        });
    </script>
        <script>
        // ---- file upload with textbox
        $(document).ready(function () {
            function handleImageUpload(inputSelector, imgViewerSelector, textBoxSelector) {
                const inputElement = $(inputSelector);

                // Handle input change for file selection
                inputElement.on('change', function () {
                    const file = this.files[0];
                    if (file) {

                            let acceptAttr = $(this).attr('accept') || '';
                            let validTypes = [];

                            if (acceptAttr) {
                                validTypes = acceptAttr.split(',').map(type => type.trim().toLowerCase());
                            }

                            // Fallback if nothing found in accept attribute
                            if (validTypes.length === 0) {
                                validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
                            }

                            // ✅ Check file validity by MIME or extension
                            const fileType = file.type.toLowerCase();
                            const fileExt = '.' + file.name.split('.').pop().toLowerCase();

                            const isValidType = validTypes.some(type => {
                                // Wildcard MIME type (e.g. image/*)
                                if (type.endsWith('/*')) {
                                    return fileType.startsWith(type.replace('/*', ''));
                                }

                                // Exact MIME type match
                                if (type.startsWith('image/') || type.includes('/')) {
                                    return fileType === type;
                                }

                                // File extension match (e.g. .jpg, .png)
                                return fileExt === type;
                            });

                            if (!isValidType) {
                                if (typeof toastr !== 'undefined') {
                                    toastr.error("{{ translate('messages.Invalid file type. Please upload a supported image.') }}");
                                }

                                $(this).val('');
                                $(imgViewerSelector)
                                    .attr('src', '{{ asset('public/assets/admin/img/upload-img.png') }}')
                                    .hide();
                                $(textBoxSelector).show();
                                return;
                            }

                        const maxSize = 2 * 1024 * 1024; // 2 MB in bytes
                        if (file.size > maxSize) {
                            if (typeof toastr !== 'undefined') {
                                toastr.error("{{ translate('messages.Image size must be less than 2 MB') }}");
                            }

                            $(this).val('');
                            $(imgViewerSelector)
                                .attr('src', '{{ asset('public/assets/admin/img/upload-img.png') }}')
                                .hide();
                            $(textBoxSelector).show();
                            return;
                        }

                        const reader = new FileReader();
                        reader.onload = function (e) {
                            $(imgViewerSelector).attr('src', e.target.result).show();
                            $(textBoxSelector).hide();
                        };
                        reader.readAsDataURL(file);
                    } else {
                        $(imgViewerSelector)
                            .attr('src', '{{ asset('public/assets/admin/img/upload-img.png') }}')
                            .hide();
                        $(textBoxSelector).show();
                    }
                });

                // Handle drag-and-drop functionality
                const dropZone = inputElement.closest('.image--border');

                dropZone.on('dragover', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                });

                dropZone.on('dragleave', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                });

                dropZone.on('drop', function (e) {
                    e.preventDefault();
                    e.stopPropagation();

                    const file = e.originalEvent.dataTransfer.files[0];
                    if (file) {
                        const reader = new FileReader();
                        reader.onload = function (e) {
                            $(imgViewerSelector).attr('src', e.target.result).show();
                            $(textBoxSelector).hide();
                        };
                        reader.readAsDataURL(file);
                    }
                });
            }

            handleImageUpload(
                '#coverImageUpload',
            );

            handleImageUpload(
                '#customFileEg1',
            );
        });
        // ---- file upload with textbox ends
    </script>
@endpush
