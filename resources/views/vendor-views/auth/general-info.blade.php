@extends('layouts.landing.app')
@section('title', translate('messages.vendor_registration'))
@push('css_or_js')
    <link rel="stylesheet" href="{{ asset('public/assets/admin/css/toastr.css') }}">
    <link rel="stylesheet" href="{{ asset('public/assets/admin/css/view-pages/vendor-registration.css') }}">
    <link rel="stylesheet" href="{{ asset('public/assets/landing/css/select2.min.css') }}"/>

    <link rel="stylesheet" href="{{ asset('public/assets/admin/vendor/icon-set/style.css') }}">

    <style>
        .password-feedback {
            display: none;
            width: 100%;
            margin-top: .25rem;
            font-size: .875em;

        }

        .valid {
            color: green;
        }

        .invalid {
            color: red;
        }

        .pickup-zone-container {
            display: none;
        }
    </style>
@endpush
@section('content')
    <section class="m-0 py-5">
        <div class="container">
            <!-- Page Header -->
            <div class="section-header">
                <h2 class="title mb-2">{{ translate('messages.vendor') }} <span
                        class="text--base">{{ translate('application') }}</span></h2>
            </div>
            @php($language = \App\CentralLogics\Helpers::get_business_settings('language'))
            <!-- End Page Header -->

            <!-- Stepper -->
            <div class="stepper">
                <div id="show-step1" class="stepper-item active">
                    <div class="step-name">{{ translate('General Info') }}</div>
                </div>
                <div class="stepper-item" id="show-step2">
                    <div class="step-name">{{ translate('Business Plan') }}</div>
                </div>
                <div class="stepper-item">
                    <div class="step-name">{{ translate('Complete') }}</div>
                </div>
            </div>
            <!-- Stepper -->


            <form enctype="multipart/form-data" id="form-id">
                <div id="reg-form-div">
                    <div class="card __card mb-3">
                        <div class="card-header">
                            <h5 class="card-title">
                                {{ translate('messages.vendor_info') }}
                            </h5>
                        </div>
                        <div class="card-body p-4">
                            <div class="card __card bg-F8F9FC mb-3">
                                <div class="card-body p-4">
                                    @if ($language)
                                        <ul class="nav nav-tabs mb-4 store-apply-navs">
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
                                    <div class="row g-3">
                                        @if ($language)
                                            <div class="lang_form " id="default-form">
                                                <input type="hidden" name="lang[]" value="default">
                                                <div class="row g-2">
                                                    <div class="col-lg-6">
                                                        <div class="mb-4 mb-lg-0">
                                                            <div class="form-group">
                                                                <label class="input-label"
                                                                       for="default_name">{{ translate('messages.name') }}
                                                                    ({{ translate('messages.Default') }})<span
                                                                        class="text-danger">*</span>
                                                                </label>
                                                                <input type="text" name="name[]"
                                                                       value="{{ old('name.0') }}" id="default_name"
                                                                       class="form-control __form-control"
                                                                       placeholder="{{ translate('messages.vendor_name') }}"
                                                                       maxlength="250" required>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div class="col-lg-6">
                                                        <div class="mb-4 mb-lg-0">
                                                            <div class="form-group mb-0">
                                                                <label class="input-label"
                                                                       for="address">{{ translate('messages.address') }}
                                                                    ({{ translate('messages.default') }})<span
                                                                        class="text-danger">*</span></label>
                                                                <textarea type="text" id="address" name="address[]"
                                                                          placeholder="{{ translate('Ex: ABC Company') }}"
                                                                          class="form-control __form-control">{{ old('address.0') }}</textarea>

                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>



                                            @foreach ($language as $key => $lang)
                                                <div class="d-none lang_form" id="{{ $lang }}-form">
                                                    <input type="hidden" name="lang[]" value="{{ $lang }}">
                                                    <div class="row g-2">
                                                        <div class="col-lg-6">
                                                            <div class="form-group">
                                                                <label class="input-label"
                                                                       for="{{ $lang }}_name">{{ translate('messages.name') }}
                                                                    ({{ strtoupper($lang) }})
                                                                </label>
                                                                <input type="text" name="name[]"
                                                                       value="{{ old('name.' . $key + 1) }}"
                                                                       id="{{ $lang }}_name"
                                                                       class="form-control __form-control"
                                                                       placeholder="{{ translate('messages.vendor_name') }}">
                                                            </div>
                                                        </div>

                                                        <div class="col-lg-6">
                                                            <div class="form-group mb-0">
                                                                <label class="input-label"
                                                                       for="address{{ $lang }}">{{ translate('messages.address') }}
                                                                    ({{ strtoupper($lang) }})
                                                                </label>
                                                                <textarea type="text" id="address{{ $lang }}"
                                                                          name="address[]"
                                                                          placeholder="{{ translate('Ex: ABC Company') }}"
                                                                          class="form-control __form-control">{{ old('address.' . $key + 1) }}</textarea>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            @endforeach
                                        @endif

                                    </div>
                                </div>
                            </div>
                            @php($zones = \App\Models\Zone::active()->get(['id', 'name']))
                            <div class="row g-4 mb-30">
                                <div class="col-lg-6">
                                    <div class="form-group mb-4">
                                        <label class="input-label"
                                               title="{{ translate('messages.Select the zone from where the business will be operated') }}"
                                               for="choice_zones">{{ translate('messages.business_zone') }}<span
                                                class="text-danger">*</span> <span class="form-label-secondary"
                                                                                   data-toggle="tooltip"
                                                                                   data-placement="right"
                                                                                   data-original-title="{{ translate('messages.Select the zone from where the business will be operated') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.Select the zone from where the business will be operated') }}"></span></label>
                                        <select name="zone_id" id="choice_zones" required
                                                class="form-control __form-control js-select2-custom js-example-basic-single"
                                                data-placeholder="{{ translate('messages.select_zone') }}">
                                            <option value="" selected disabled>
                                                {{ translate('messages.select_zone') }}</option>
                                            @foreach ($zones as $zone)
                                                @if (isset(auth('admin')->user()->zone_id))
                                                    @if (auth('admin')->user()->zone_id == $zone->id)
                                                        <option value="{{ $zone->id }}" selected>{{ $zone->name }}
                                                        </option>
                                                    @endif
                                                @else
                                                    <option value="{{ $zone->id }}">{{ $zone->name }}</option>
                                                @endif
                                            @endforeach
                                        </select>
                                    </div>
                                    <div class="form-group mb-4">
                                        <label for="module_id"
                                               class="input-label">{{ translate('messages.business_module') }}<span
                                                class="text-danger">*</span>
                                            <small
                                                class="text-danger">({{ translate('messages.Select_zone_first') }}
                                                )</small></label>
                                        <select name="module_id" required id="module_id"
                                                class="js-data-example-ajax form-control __form-control"
                                                data-placeholder="{{ translate('messages.select_module') }}">
                                        </select>
                                    </div>
                                    <div class="form-group mb-4 pickup-zone-container pickup-zone-tag"
                                         id="pickup-zone-container">
                                        <label class="input-label"
                                               title="{{ translate('messages.Select zones from where customer can choose their pickup locations for trip booking') }}"
                                               for="choice_zones">{{ translate('messages.pickup_zone') }}<span
                                                class="text-danger">*</span> <span class="form-label-secondary"
                                                                                   data-toggle="tooltip"
                                                                                   data-placement="right"
                                                                                   data-original-title="{{ translate('messages.Select zones from where customer can choose their pickup locations for trip booking') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.Select zones from where customer can choose their pickup locations for trip booking') }}"></span></label>
                                        <select name="pickup_zone_id[]" required class="form-control multiple-select2"
                                                data-placeholder="{{ translate('messages.select_zone') }}"
                                                multiple="multiple">
                                            <option value="" disabled>
                                                {{ translate('messages.select_zone') }}</option>
                                            @foreach ($zones as $zone)
                                                @if (isset(auth('admin')->user()->zone_id))
                                                    @if (auth('admin')->user()->zone_id == $zone->id)
                                                        <option value="{{ $zone->id }}" selected>{{ $zone->name }}
                                                        </option>
                                                    @endif
                                                @else
                                                    <option value="{{ $zone->id }}">{{ $zone->name }}</option>
                                                @endif
                                            @endforeach
                                        </select>
                                    </div>
                                    <div class="form-group mb-4">
                                        <label class="input-label"
                                               for="latitude">{{ translate('messages.latitude') }}<span
                                                class="text-danger">*</span>
                                            <span class="input-label-secondary"
                                                  title="{{ translate('messages.Pin the business location on the map to auto input latitude of that location') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.Pin the business location on the map to auto input latitude of that location') }}"></span></label>
                                        <input type="text" id="latitude" name="latitude"
                                               class="form-control __form-control"
                                               placeholder="{{ translate('messages.Ex:') }} -94.22213"
                                               value="{{ old('latitude') }}" required readonly>
                                    </div>
                                    <div class="form-group mb-4">
                                        <label class="input-label"
                                               for="longitude">{{ translate('messages.longitude') }}<span
                                                class="text-danger">*</span>
                                            <span class="input-label-secondary"
                                                  title="{{ translate('messages.Pin the business location on the map to auto input longitude of that location') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.Pin the business location on the map to auto input longitude of that location') }}"></span></label>
                                        <input type="text" name="longitude" class="form-control __form-control"
                                               placeholder="{{ translate('messages.Ex:') }} 103.344322" id="longitude"
                                               value="{{ old('longitude') }}" required readonly>
                                    </div>
                                    <div class="form-group">
                                        <label class="input-label module-select-time"
                                               for="minimum_delivery_time">{{ translate('messages.approx_delivery_time') }}
                                            <span
                                                class="text-danger">*</span></label>
                                        <div class=" __form-control custom-group-btn">
                                            <div class="item flex-sm-grow-1">
                                                <div class="d-flex align-items-center gap-1">
                                                    <label class="floating-label"
                                                           for="min">{{ translate('messages.min') }}:</label>
                                                    <input type="number" id="minimum_delivery_time"
                                                           name="minimum_delivery_time"
                                                           class="form-control p-0 border-0"
                                                           placeholder="10" value="{{ old('minimum_delivery_time') }}">
                                                </div>
                                            </div>
                                            <div class="item flex-sm-grow-1">
                                                <div class="d-flex align-items-center gap-1">
                                                    <label class="floating-label"
                                                           for="max">{{ translate('messages.max') }}:</label>
                                                    <input type="number" name="maximum_delivery_time"
                                                           id="max_delivery_time" class="form-control p-0 border-0"
                                                           placeholder="20" value="{{ old('maximum_delivery_time') }}">
                                                </div>
                                            </div>
                                            <div class="item flex-shrink-0">
                                                <select name="delivery_time_type"
                                                        class="form-select custom-select border-0" required>
                                                    <option value="min">{{ translate('messages.minutes') }}
                                                    </option>
                                                    <option value="hours">{{ translate('messages.hours') }}</option>
                                                    <option value="days">{{ translate('messages.days') }}</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-lg-6">
                                    <div class="rounded mb-3">
                                        <input id="pac-input" class="controls rounded"
                                               style="height: 3em;width:fit-content;"
                                               title="{{ translate('messages.search_your_location_here') }}" type="text"
                                               placeholder="{{ translate('messages.search_here') }}"/>
                                        <div class="h-280" id="map"></div>
                                    </div>
                                    <div class="d-flex flex-column flex-sm-row gap-4">
                                        <div class="form-group flex-grow-1 d-flex flex-column justify-content-between">
                                            <label class="input-label pt-2 mb-2">
                                                <div class="lh-1">{{ translate('messages.cover') }}<span
                                                        class="text-danger">*</span></div>
                                                <div class="fs-12 opacity-70">
                                                    {{ translate(IMAGE_FORMAT.' ' . 'Less Than 2MB') }}
                                                    <strong> {{ translate('(Ratio 2:1)') }}
                                                    </strong>
                                                </div>
                                            </label>
                                            <label class="image--border position-relative h-110 min-w-220">
                                                <img class="__register-img h-110" id="coverImageViewer"
                                                     src="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                     alt="Product thumbnail" style="display: none"/>
                                                <div class="upload-file__textbox p-2 h-100">
                                                    <img width="34" height="34"
                                                         src="{{ asset('public/assets/admin/img/document-upload.png') }}"
                                                         alt="" class="svg">
                                                    <h6 class="mt-2 text-center font-semibold fs-12">
                                                        <span
                                                            class="text-info">{{ translate('messages.Click to upload') }}</span>
                                                        <br>
                                                        {{ translate('messages.or drag and drop') }}
                                                    </h6>
                                                </div>
                                                <div class="icon-file-group d-none">
                                                    <div class="icon-file">
                                                        <input type="file" name="cover_photo" id="coverImageUpload"
                                                               class="form-control __form-control"
                                                               accept="{{ IMAGE_EXTENSION }}">
                                                        <img src="{{ asset('public/assets/admin/img/pen.png') }}"
                                                             alt="">
                                                    </div>
                                                </div>
                                            </label>
                                        </div>
                                        <div class="form-group d-flex flex-column justify-content-between">
                                            <label class="input-label pt-2 mb-2">
                                                <div class="lh-1">{{ translate('messages.logo') }}<span
                                                        class="text-danger">*</span></div>
                                                <div class="fs-12 opacity-70">
                                                    {{ translate(IMAGE_FORMAT.' ' . 'Less Than 2MB') }}
                                                    <strong> {{ translate('(Ratio 1:1)') }}
                                                    </strong>
                                                </div>
                                            </label>
                                            <label
                                                class="image--border position-relative img--100px w-100 h-110 max-w-110">
                                                <img class="__register-img h-110" id="logoImageViewer"
                                                     src="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                     alt="Product thumbnail" style="display: none"/>
                                                <div class="upload-file__textbox p-2 h-100">
                                                    <img width="34" height="34"
                                                         src="{{ asset('public/assets/admin/img/document-upload.png') }}"
                                                         alt="" class="svg">
                                                    <h6 class="mt-2 text-center font-semibold fs-12">
                                                        <span
                                                            class="text-info">{{ translate('messages.Click to upload') }}</span>
                                                        <br>
                                                        {{ translate('messages.or drag and drop') }}
                                                    </h6>
                                                </div>
                                                <div class="icon-file-group d-none">
                                                    <div class="icon-file">
                                                        <input type="file" name="logo" id="customFileEg1"
                                                               class="form-control __form-control"
                                                               accept="{{ IMAGE_EXTENSION }}">
                                                        <img src="{{ asset('public/assets/admin/img/pen.png') }}"
                                                             alt="">
                                                    </div>
                                                </div>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="card __card bg-F8F9FC mb-4">
                                <div class="card-header">
                                    <div>
                                        <h5 class="card-title mb-4">
                                            {{ translate('messages.owner_information') }}
                                        </h5>
                                        <p class="fs-12 mb-0">
                                            {{ translate('messages.Insert_Owner\'s_General_Information') }}
                                        </p>
                                    </div>
                                </div>
                                <div class="card-body p-4">
                                    <div class="row g-3">
                                        <div class="col-md-4 col-lg-4 col-sm-12">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       for="f_name">{{ translate('messages.first_name') }}<span
                                                        class="text-danger">*</span></label>
                                                <input type="text" id="f_name" name="f_name"
                                                       class="form-control __form-control"
                                                       placeholder="{{ translate('messages.first_name') }}"
                                                       value="{{ old('f_name') }}" required>
                                            </div>
                                        </div>
                                        <div class="col-md-4 col-lg-4 col-sm-12">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       for="l_name">{{ translate('messages.last_name') }}<span
                                                        class="text-danger">*</span></label>
                                                <input type="text" id="l_name" name="l_name"
                                                       class="form-control __form-control"
                                                       placeholder="{{ translate('messages.last_name') }}"
                                                       value="{{ old('l_name') }}" required>
                                            </div>
                                        </div>
                                        <div class="col-md-4 col-lg-4 col-sm-12">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       for="phone">{{ translate('messages.phone') }}<span
                                                        class="text-danger">*</span></label>
                                                <input type="tel" id="phone" name="phone"
                                                       class="form-control __form-control"
                                                       placeholder="{{ translate('messages.Ex:') }} 017********"
                                                       value="{{ old('phone') }}" required>
                                            </div>


                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="p-20 mb-3">
                                <div class="card-body">
                                    <div class="mb-3">
                                        <h3 class="mb-2">{{ translate('Business TIN') }}</h3>
                                        {{-- <p class="fz-12px mb-0">{{translate('Lorem ipsum dolor sit amet, consectetur adipiscing elit.')}}</p> --}}
                                    </div>
                                    <div class="row g-3">
                                        <div class="col-md-8 col-xxl-8">
                                            <div class="card __card bg-F8F9FC rounded p-20 h-100">
                                                <div class="card-body">
                                                    <div class="form-group mb-3">
                                                        <label class="input-label mb-2 d-block title-clr fw-normal"
                                                               for="exampleFormControlInput1">{{ translate('Taxpayer Identification Number(TIN)') }}
                                                        </label>
                                                        <input type="text" name="tin"
                                                               placeholder="{{ translate('Type Your Taxpayer Identification Number(TIN)') }}"
                                                               class=" form-control __form-control">
                                                    </div>
                                                    <div class="form-group mb-0">
                                                        <label class="input-label mb-2 d-block title-clr fw-normal"
                                                               for="exampleFormControlInput1">{{ translate('Expire Date') }}
                                                        </label>
                                                        <input type="date" name="tin_expire_date"
                                                               class="form-control __form-control">
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-4 col-xxl-4">
                                            <div class="bg--secondary rounded p-20 h-100 single-document-uploaderwrap">
                                                <div
                                                    class="d-flex align-items-center gap-1 justify-content-between mb-20 mb-4">
                                                    <div>
                                                        <h4 class="mb-2 fz--14px">{{ translate('TIN Certificate') }}</h4>
                                                        <p class="fz-12px mb-0">
                                                            {{ translate('pdf, doc, jpg. File size : max 2 MB') }}</p>
                                                    </div>
                                                    <div class="d-flex gap-3 align-items-center">
                                                        <button type="button" id="doc_edit_btn"
                                                            data-default-image="{{ asset('public/assets/admin/img/doc-uploaded.png') }}"
                                                                class="w-30px h-30 min-w-30px rounded d-flex align-items-center justify-content-center action-btn btn cmn--btn px-3 icon-btn">
                                                            <i class="tio-edit"></i>
                                                        </button>
                                                    </div>
                                                </div>
                                                <div>
                                                    <div id="file-assets"
                                                         data-picture-icon="{{ asset('public/assets/admin/img/picture.svg') }}"
                                                         data-document-icon="{{ asset('public/assets/admin/img/document.svg') }}"
                                                         data-blank-thumbnail="{{ asset('public/assets/admin/img/picture.svg') }}">
                                                    </div>
                                                    <!-- Upload box -->
                                                    <div class="d-flex justify-content-center" id="pdf-container">
                                                        <div class="document-upload-wrapper" id="doc-upload-wrapper">
                                                            <input type="file" name="tin_certificate_image"
                                                                   class="document_input"
                                                                   accept=".doc, .pdf, .jpg, .png, .jpeg">
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
                            <div class="card __card bg-F8F9FC mb-3">
                                <div class="card-header">
                                    <div>
                                        <h5 class="card-title mb-2">
                                            {{ translate('messages.account_information') }}
                                        </h5>
                                        <p class="fs-12 mb-0">
                                            {{ translate('Insert_Owner\'s_account_information') }}
                                        </p>
                                    </div>
                                </div>
                                <div class="card-body p-4">
                                    <div class="row g-3">
                                        <div class="col-md-4 col-sm-12 col-lg-4">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       for="email">{{ translate('messages.email') }}<span
                                                        class="text-danger">*</span></label>
                                                <input type="email" id="email" name="email"
                                                       class="form-control __form-control"
                                                       placeholder="{{ translate('messages.Ex:') }} ex@example.com"
                                                       value="{{ old('email') }}" required>
                                            </div>
                                        </div>
                                        <div class="col-md-4 col-sm-12 col-lg-4">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       title="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"
                                                       for="exampleInputPassword">{{ translate('messages.password') }}
                                                    <span
                                                        class="text-danger">*</span>
                                                    &nbsp;
                                                    <span class="form-label-secondary" data-toggle="tooltip"
                                                          data-placement="right"
                                                          data-original-title="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.Must_contain_at_least_one_number_and_one_uppercase_and_lowercase_letter_and_symbol,_and_at_least_8_or_more_characters') }}"></span>

                                                </label>
                                                <label class="position-relative m-0 d-block">
                                                    <input type="password" name="password"
                                                           placeholder="{{ translate('messages.password_length_placeholder', ['length' => '8+']) }}"
                                                           class="form-control __form-control form-control __form-control-user"
                                                           minlength="6" id="exampleInputPassword" required
                                                           value="{{ old('password') }}">
                                                    <span class="show-password">
                                                        <span class="icon-2">
                                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none"
                                                                 viewBox="0 0 24 24" stroke-width="1.5"
                                                                 stroke="currentColor" class="size-6">
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z"/>
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
                                                            </svg>
                                                        </span>
                                                        <span class="icon-1">
                                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none"
                                                                 viewBox="0 0 24 24" stroke-width="1.5"
                                                                 stroke="currentColor" class="size-6">
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"/>
                                                            </svg>
                                                        </span>
                                                    </span>
                                                </label>
                                                <div id="password-feedback" class="pass password-feedback">
                                                    {{ translate('messages.password_not_matched') }}
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-4 col-sm-12 col-lg-4">
                                            <div class="form-group">
                                                <label class="input-label"
                                                       for="exampleRepeatPassword">{{ translate('messages.confirm_password') }}
                                                    <span
                                                        class="text-danger">*</span></label>
                                                <label class="position-relative m-0 d-block">
                                                    <input type="password" name="confirm-password"
                                                           class="form-control __form-control form-control __form-control-user"
                                                           minlength="6" id="exampleRepeatPassword"
                                                           placeholder="{{ translate('messages.password_length_placeholder', ['length' => '8+']) }}"
                                                           required value="{{ old('confirm-password') }}">
                                                    <span class="show-password">
                                                        <span class="icon-2">
                                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none"
                                                                 viewBox="0 0 24 24" stroke-width="1.5"
                                                                 stroke="currentColor" class="size-6">
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z"/>
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
                                                            </svg>
                                                        </span>
                                                        <span class="icon-1">
                                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none"
                                                                 viewBox="0 0 24 24" stroke-width="1.5"
                                                                 stroke="currentColor" class="size-6">
                                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                                      d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"/>
                                                            </svg>
                                                        </span>
                                                    </span>
                                                </label>
                                                <div class="pass invalid-feedback">
                                                    {{ translate('messages.password_not_matched') }}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row mt-5">
                                        <div class="col-md-6 col-lg-4">
                                            @php($recaptcha = \App\CentralLogics\Helpers::get_business_settings('recaptcha'))
                                            @if (isset($recaptcha) && $recaptcha['status'] == 1)
                                                <input type="hidden" name="g-recaptcha-response"
                                                       id="g-recaptcha-response">
                                            @else
                                                <div class="row g-3">
                                                    <div class="col-6">
                                                        <input type="text" class="form-control"
                                                               name="custome_recaptcha" id="custome_recaptcha" required
                                                               placeholder="{{ translate('Enter recaptcha value') }}"
                                                               autocomplete="off"
                                                               value="{{ env('APP_DEBUG') ? session('six_captcha') : '' }}">
                                                    </div>
                                                    <div class="col-6 recap-img-div">
                                                        <img src="{!! $custome_recaptcha->inline() ?? '' !!}"
                                                             alt="image"
                                                             class="recap-img"/>
                                                    </div>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="text-end pt-4 d-flex flex-wrap justify-content-end gap-3">
                                <button type="reset" id='reset-btn'
                                        class="cmn--btn btn--secondary shadow-none rounded-md border-0 outline-0">{{ translate('Reset') }}</button>
                                <button
                                    type="{{ \App\CentralLogics\Helpers::subscription_check() == 1 ? 'button' : 'submit' }}"
                                    id="show-business-plan-div"
                                    class="cmn--btn rounded-md border-0 outline-0 btn-disable">{{ \App\CentralLogics\Helpers::subscription_check() == 1 ? translate('Next') : translate('messages.submit') }}</button>
                            </div>
                        </div>
                    </div>

                </div>

                @if (\App\CentralLogics\Helpers::subscription_check())
                    <div class="d-none" id="business-plan-div">
                        <div class="card __card mb-3">
                            <div class="card-header border-0">
                                <h5 class="card-title text-center">
                                    {{ translate('Choose Your Business Plan') }}
                                </h5>
                            </div>
                            <div class="card-body p-4">
                                <div class="row">
                                    @if (\App\CentralLogics\Helpers::commission_check())
                                        <div class="col-sm-6">
                                            <label class="plan-check-item pb-3 pb-sm-0">
                                                <input type="radio" name="business_plan" value="commission-base"
                                                       class="d-none" checked>
                                                <div class="plan-check-item-inner">
                                                    <div
                                                        class="d-flex gap-3 justify-content-between align-items-center mb-10">
                                                        <h5 class="mb-0">{{ translate('Commision_Base') }}</h5>
                                                        <span class="checkmark">
                                                            <svg xmlns="http://www.w3.org/2000/svg" width="16"
                                                                 height="16" fill="currentColor" class="bi bi-check2"
                                                                 viewBox="0 0 16 16">
                                                                <path
                                                                    d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/>
                                                            </svg>
                                                        </span>
                                                    </div>
                                                    <p>
                                                        {{ translate('vendor will pay') }} {{ $admin_commission }}%
                                                        {{ translate('commission to') }} {{ $business_name }}
                                                        {{ translate('from each order. You will get access of all the features and options  in vendor panel , app and interaction with user.') }}
                                                    </p>
                                                </div>
                                            </label>
                                        </div>
                                    @endif
                                    <div class="col-sm-6">
                                        <label class="plan-check-item">
                                            <input type="radio" name="business_plan" value="subscription-base"
                                                   class="d-none">
                                            <div class="plan-check-item-inner">
                                                <div
                                                    class="d-flex gap-3 justify-content-between align-items-center mb-10">
                                                    <h5 class="mb-0">{{ translate('Subscription_Base') }}</h5>
                                                    <span class="checkmark">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="16"
                                                             height="16" fill="currentColor" class="bi bi-check2"
                                                             viewBox="0 0 16 16">
                                                            <path
                                                                d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/>
                                                        </svg>
                                                    </span>
                                                </div>
                                                <p>
                                                    {{ translate('Run vendor by puchasing subsciption packages. You will have access the features of in vendor panel , app and interaction with user according to the subscription packages.') }}
                                                </p>
                                            </div>
                                        </label>
                                    </div>
                                </div>
                                <div id="subscription-plan">
                                    <br>
                                    <div class="card-header px-0 m-0 border-0">
                                        <h5 class="card-title text-center">
                                            {{ translate('Choose Subscription Package') }}
                                        </h5>
                                    </div>
                                    <div id='show_sub_packages'>
                                        @include('vendor-views.auth._package_data', [
                                            'packages' => $packages,
                                        ])
                                    </div>


                                </div>
                            </div>
                            <div class="text-end pt-5 d-flex flex-wrap p-4 justify-content-end gap-3">
                                <button type="button" id="back-to-form"
                                        class="cmn--btn btn--secondary shadow-none rounded-md border-0 outline-0">{{ translate('Back') }}</button>
                                <button type="submit"
                                        class="cmn--btn rounded-md border-0 outline-0 btn-disable">{{ translate('Next') }}</button>
                            </div>
                        </div>
                    </div>
                @endif
            </form>
        </div>


    </section>

<div class="d-none" id="default-text-data"
     data-default-filesize="{{ translate('File size must be less than') }}"
     data-default-allowedformat="{{ translate('Invalid file type. Allowed: PDF, DOC, JPG, PNG') }}">
</div>
@endsection
@push('script_2')

    <script src="{{ asset('public/assets/admin/js/file-preview/pdf.min.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/file-preview/pdf-worker.min.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/file-preview/store-join-us.js') }}"></script>

    {{-- <script src="{{ asset('public/assets/admin/js/spartan-multi-image-picker.js') }}"></script> --}}
    <script
        src="https://maps.googleapis.com/maps/api/js?key={{ \App\CentralLogics\Helpers::get_business_settings('map_api_key') }}&libraries=drawing,places&v=3.45.8">
    </script>
    <script type="text/javascript">
        "use strict";
        let geocoder = null;

        function setAddressFromLatLng(latlng) {
            if (!geocoder) return;
            geocoder.geocode({
                location: latlng
            }, function (results, status) {
                if (status === 'OK' && results[0]) {
                    const addr = results[0].formatted_address;
                    const visibleAddress = document.querySelector(
                        '.lang_form:not(.d-none) textarea[name="address[]"]');
                    if (visibleAddress) {
                        visibleAddress.value = addr;
                    } else {
                        const addressEl = document.getElementById('address');
                        if (addressEl) addressEl.value = addr;
                    }
                    const pacInput = document.getElementById('pac-input');
                    if (pacInput) pacInput.value = addr;
                }
            });
        }


        @php($default_location = \App\CentralLogics\Helpers::get_business_settings('default_location'))

        let myLatlng = {
            lat: {{ $default_location ? $default_location['lat'] : '23.757989' }},
            lng: {{ $default_location ? $default_location['lng'] : '90.360587' }}
        };
        let map = new google.maps.Map(document.getElementById("map"), {
            zoom: 13,
            center: myLatlng,
        });
        let zonePolygon = null;
        let infoWindow = new google.maps.InfoWindow({
            content: "Click the map to get Lat/Lng!",
            position: myLatlng,
        });
        let bounds = new google.maps.LatLngBounds();

        $('#choice_zones').on('change', function () {
            let id = $(this).val();
            $.get({
                url: '{{ url('/') }}/admin/zone/get-coordinates/' + id,
                dataType: 'json',
                success: function (data) {
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
                    zonePolygon.getPaths().forEach(function (path) {
                        path.forEach(function (latlng) {
                            bounds.extend(latlng);
                            map.fitBounds(bounds);
                        });
                    });
                    map.setCenter(data.center);
                    google.maps.event.addListener(zonePolygon, 'click', function (mapsMouseEvent) {
                        infoWindow.close();
                        // Create a new InfoWindow.
                        infoWindow = new google.maps.InfoWindow({
                            position: mapsMouseEvent.latLng,
                            content: JSON.stringify(mapsMouseEvent.latLng.toJSON(),
                                null, 2),
                        });
                        let coordinates;
                        coordinates = JSON.stringify(mapsMouseEvent.latLng.toJSON(), null,
                            2);
                        coordinates = JSON.parse(coordinates);

                        document.getElementById('latitude').value = coordinates['lat'];
                        document.getElementById('longitude').value = coordinates['lng'];
                        const oldLatLng = new google.maps.LatLng(coordinates['lat'],
                            coordinates['lng']);
                        geocoder = new google.maps.Geocoder();
                        console.log(oldLatLng);
                        setAddressFromLatLng(oldLatLng);
                        infoWindow.open(map);
                    });
                },
            });
        });

        $(document).ready(function () {
            $('#module_id').select2({
                ajax: {
                    url: '{{ url('/') }}/vendor/get-all-modules/',
                    data: function (params) {
                        return {
                            q: params.term, // search term
                            page: params.page,
                            zone_id: zone_id
                        };
                    },
                    processResults: function (data) {
                        return {
                            results: data
                        };
                    },
                    __port: function (params, success, failure) {
                        let $request = $.ajax(params);

                        $request.then(success);
                        $request.fail(failure);

                        return $request;
                    }
                }
            });

            $('#module_id').on('change', function () {
                var moduleId = $(this).val();
                $.ajax({
                    url: '{{ url('/') }}/vendor/get-module-type',
                    method: 'GET',
                    data: {
                        id: moduleId
                    },
                    success: function (response) {
                        $('#show_sub_packages').empty().html(response.view);
                        if (response.module_type === 'rental') {
                            $('#pickup-zone-container').show();
                            $('.multiple-select2').prop('disabled', false);
                            $('.module-select-time').html(
                                '{{ translate('messages.Estimated_pickup_time') }} <span class="text-danger">*</span>'
                            );
                        } else {
                            $('#pickup-zone-container').hide();
                            $('.multiple-select2').prop('disabled', true);
                            $('.module-select-time').html(
                                '{{ translate('messages.approx_delivery_time') }} <span class="text-danger">*</span>'
                            );
                        }
                    },
                    error: function (xhr, status, error) {
                        console.log("Error fetching module type:", error);
                    }
                });
            });

            $('.js-multi-select2').select2({
                placeholder: '{{ translate('messages.select_zone') }}',
                allowClear: true,
                width: '100%'
            });
        });
    </script>
    <script src="{{ asset('public/assets/admin/js/view-pages/vendor-registration.js') }}"></script>
    @if (isset($recaptcha) && $recaptcha['status'] == 1)
        <script type="text/javascript">
            "use strict";
            let onloadCallback = function () {
                grecaptcha.render('recaptcha_element', {
                    'sitekey': '{{ \App\CentralLogics\Helpers::get_business_settings('recaptcha')['site_key'] }}'
                });
            };
        </script>
        <script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit" async
                defer></script>
    @endif

    @if (isset($recaptcha) && $recaptcha['status'] == 1)
        <script src="https://www.google.com/recaptcha/api.js?render={{ $recaptcha['site_key'] }}"></script>
    @endif
    <script>
        $("#form-id").on('submit', function (e) {
            e.preventDefault();
            @if (isset($recaptcha) && $recaptcha['status'] == 1)

            let response = grecaptcha.getResponse();

            if (response.length === 0) {
                e.preventDefault();
                toastr.error("{{ translate('messages.Please check the recaptcha') }}");
            }
            @endif

            const radios = document.querySelectorAll('input[name="business_plan"]');
            let selectedValue = null;


            for (const radio of radios) {
                if (radio.checked) {
                    selectedValue = radio.value;
                    break;
                }
            }


            if (selectedValue === 'subscription-base') {
                const package_radios = document.querySelectorAll('input[name="package_id"]');
                let selectedpValue = null;
                for (const pradio of package_radios) {
                    if (pradio.checked) {
                        selectedpValue = pradio.value;
                        break;
                    }
                }

                if (!selectedpValue) {
                    toastr.error("{{ translate('You_must_select_a_package') }}");
                    e.preventDefault();
                }
            }

            $('.btn-disable').attr('disabled', true);


            let formData = new FormData(this);
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': "{{ csrf_token() }}"
                }
            });
            $.post({
                url: '{{ route('restaurant.store') }}',
                data: $('#form-id').serialize(),
                data: formData,
                cache: false,
                contentType: false,
                processData: false,
                beforeSend: function () {
                    $('#loading').show();
                },
                success: function (data) {
                    $('#loading').hide();
                    if (data.errors) {
                        $('.btn-disable').attr('enable', true);
                        for (let i = 0; i < data.errors.length; i++) {
                            toastr.error(data.errors[i].message, {
                                CloseButton: true,
                                ProgressBar: true
                            });
                        }
                    } else {
                        toastr.success("{{ translate('your_store_registration_is_successful') }}", {
                            CloseButton: true,
                            ProgressBar: true
                        });
                        setTimeout(function () {
                            location.href = data.redirect_url;
                        }, 1000);
                    }
                }
            });

        });
        $(document).on('keyup', 'input[name="password"]', function () {
            const password = $(this).val();
            const feedback = $('#password-feedback');

            const minLength = password.length >= 8;
            const hasLowerCase = /[a-z]/.test(password);
            const hasUpperCase = /[A-Z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);

            if (minLength && hasLowerCase && hasUpperCase && hasNumber && hasSymbol) {
                feedback.text("{{ translate('Password is valid') }}");
                feedback.removeClass('invalid').addClass('valid');
            } else {
                feedback.text("{{ translate('Password format is invalid') }}");
                feedback.removeClass('valid').addClass('invalid');
            }
        });



        $('#show-business-plan-div').on('click', function (e) {
            const logo = $('input[name="logo"]')[0];
            const cover = $('input[name="cover_photo"]')[0];
            const tin_certificate_image = $('input[name="tin_certificate_image"]')[0];

            const maxFileSize = 2 * 1024 * 1024; // 2MB in bytes

            if (!$('#default_name').val()) {
                toastr.error("{{ translate('Vendor_name_is_required') }}");
                e.preventDefault();
            } else if (!$('#address').val()) {
                toastr.error("{{ translate('Vendor_address_is_required') }}");
                e.preventDefault();
            } else if (!logo.files.length) {
                toastr.error("{{ translate('Vendor_logo_required') }}");
                e.preventDefault();
            } else if (!cover.files.length) {
                toastr.error("{{ translate('Vendor_cover_photo_required') }}");
                e.preventDefault();
            } else if (logo.files[0].size > maxFileSize) {
                toastr.error("{{ translate('Vendor_logo_must_be_less_than_2MB') }}");
                e.preventDefault();
            } else if (tin_certificate_image.files.length && tin_certificate_image.files[0].size > maxFileSize) {
                toastr.error("{{ translate('Tin_certificate_must_be_less_than_2MB') }}");
                e.preventDefault();
            } else if (cover.files[0].size > maxFileSize) {
                toastr.error("{{ translate('Vendor_cover_photo_must_be_less_than_2MB') }}");
                e.preventDefault();
            } else if (!$('#choice_zones').val()) {
                toastr.error("{{ translate('You_must_select_a_zone') }}");
                e.preventDefault();
            } else if (!$('#module_id').val()) {
                toastr.error("{{ translate('You_must_select_a_module') }}");
                e.preventDefault();
            } else if (!$('#latitude').val() || !$('#longitude').val()) {
                toastr.error("{{ translate('Must_click_on_the_map_for_lat/long') }}");
                e.preventDefault();
            } else if (!$('#minimum_delivery_time').val()) {
                toastr.error("{{ translate('minimum_time_is_required') }}");
                e.preventDefault();
            } else if (!$('#max_delivery_time').val()) {
                toastr.error("{{ translate('max_time_is_required') }}");
                e.preventDefault();
            } else if (!$('#f_name').val()) {
                toastr.error("{{ translate('first_name_is_required') }}");
                e.preventDefault();
            } else if (!$('#l_name').val()) {
                toastr.error("{{ translate('last_name_is_required') }}");
                e.preventDefault();
            } else if ($('#phone').val().length < 5) {
                toastr.error("{{ translate('valid_phone_number_is_required') }}");
                e.preventDefault();
            } else if (!$('#email').val()) {
                toastr.error("{{ translate('email_is_required') }}");
                e.preventDefault();
            } else if (!$('#exampleInputPassword').val()) {
                toastr.error("{{ translate('password_is_required') }}");
                e.preventDefault();
            } else if ($('#exampleRepeatPassword').val() !== $('#exampleInputPassword').val()) {
                toastr.error("{{ translate('confirm_password_does_not_match') }}");
                e.preventDefault();
            } else if (!isPasswordStrong($('#exampleRepeatPassword').val()) && !isPasswordStrong($('#exampleInputPassword').val())) {
                toastr.error("{{ translate('Password format is invalid') }}");
                e.preventDefault();
            } else {
                @if (isset($recaptcha) && $recaptcha['status'] == 1)
                if (typeof grecaptcha === 'undefined') {
                    toastr.error('Invalid recaptcha key provided. Please check the recaptcha configuration.');
                    e.preventDefault();
                    return;
                }
                grecaptcha.ready(function () {
                    grecaptcha.execute('{{ $recaptcha['site_key'] }}', {
                        action: 'submit'
                    })
                        .then(function (token) {
                            $('#g-recaptcha-response').val(token);
                        });
                });
                @endif

                @if (\App\CentralLogics\Helpers::subscription_check())
                $('#business-plan-div').removeClass('d-none');
                $('#reg-form-div').addClass('d-none');
                $('#show-step2').addClass('active');
                $('#show-step1').removeClass('active');
                $(window).scrollTop(0);
                @endif
            }
        });

        function isPasswordStrong(password) {
            const minLength = password.length >= 8;
            const hasLowerCase = /[a-z]/.test(password);
            const hasUpperCase = /[A-Z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);
            return minLength && hasLowerCase && hasUpperCase && hasNumber && hasSymbol;
        }


        $('#back-to-form').on('click', function () {
            $('#business-plan-div').addClass('d-none');
            $('#reg-form-div').removeClass('d-none');
            $('#show-step1').addClass('active');
            $('#show-step2').removeClass('active');
            $(window).scrollTop(0);
        })

    </script>
    <script src="{{ asset('public/assets/landing/js/select2.min.js') }}"></script>

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

            // Apply functionality to each upload element
            handleImageUpload(
                '#coverImageUpload',
                '#coverImageViewer',
                '#coverImageViewer ~ .upload-file__textbox'
            );

            handleImageUpload(
                '#customFileEg1',
                '#logoImageViewer',
                '#logoImageViewer ~ .upload-file__textbox'
            );
        });
        // ---- file upload with textbox ends
    </script>

    <script>
        $.fn.select2DynamicDisplay = function () {
            const limit = 10000;

            function updateDisplay($element) {
                var $rendered = $element
                    .siblings(".select2-container")
                    .find(".select2-selection--multiple")
                    .find(".select2-selection__rendered");
                var $container = $rendered.parent();
                var containerWidth = $container.width();
                var totalWidth = 0;
                var itemsToShow = [];
                var remainingCount = 0;

                // Get all selected items
                var selectedItems = $element.select2("data");

                // Create a temporary container to measure item widths
                var $tempContainer = $("<div>")
                    .css({
                        display: "inline-block",
                        padding: "0 15px",
                        "white-space": "nowrap",
                        visibility: "hidden",
                    })
                    .appendTo($container);

                // Calculate the width of items and determine how many fit
                selectedItems.forEach(function (item) {
                    var $tempItem = $("<span>")
                        .text(item.text)
                        .css({
                            display: "inline-block",
                            padding: "0 12px",
                            "white-space": "nowrap",
                        })
                        .appendTo($tempContainer);

                    var itemWidth = $tempItem.outerWidth(true);

                    if (totalWidth + itemWidth <= containerWidth - 40) {
                        totalWidth += itemWidth;
                        itemsToShow.push(item);
                    } else {
                        remainingCount = selectedItems.length - itemsToShow.length;
                        return false;
                    }
                });

                $tempContainer.remove();

                const $searchForm = $rendered.find(".select2-search");

                var html = "";
                itemsToShow.forEach(function (item) {
                    html += `<li class="name">
                                        <span>${item.text}</span>
                                        <span class="close-icon" data-id="${item.id}">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                                                <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/>
                                            </svg>
                                        </span>
                                        </li>`;
                });
                if (remainingCount > 0) {
                    html += `<li class="ms-auto">
                                        <div class="more">+${remainingCount}</div>
                                        </li>`;
                }

                if (selectedItems.length < limit) {
                    html += $searchForm.prop("outerHTML");
                }

                $rendered.html(html);

                function debounce(func, wait) {
                    let timeout;
                    return function (...args) {
                        clearTimeout(timeout);
                        timeout = setTimeout(() => func.apply(this, args), wait);
                    };
                }

                $(".select2-search input").on(
                    "input",
                    debounce(function () {
                        const inputValue = $(this).val().toLowerCase();
                        const $listItems = $(".select2-results__options li");
                        let matches = 0;

                        $listItems.each(function () {
                            const itemText = $(this).text().toLowerCase();
                            const isMatch = itemText.includes(inputValue);
                            $(this).toggle(isMatch);
                            if (isMatch) matches++;
                        });

                        if (matches === 0) {
                            $(".select2-results__options").append(
                                '<li class="no-results">No results found</li>'
                            );
                        } else {
                            $(".no-results").remove();
                        }
                    }, 100)
                );

                $(".select2-search input").on("keydown", function (e) {
                    if (e.which === 13) {
                        e.preventDefault();
                        const inputValue = $(this).val().toLowerCase();
                        const $listItems = $(".select2-results__options li:not(.no-results)");
                        const matchedItem = $listItems.filter(function () {
                            return $(this).text().toLowerCase() === inputValue;
                        });

                        if (matchedItem.length > 0) {
                            matchedItem.trigger("mouseup"); // Select the matched item
                        }

                        $(this).val("");
                    }
                });
            }

            return this.each(function () {
                var $this = $(this);

                $this.select2({
                    tags: true,
                    maximumSelectionLength: limit,
                });

                // Bind change event to update display
                $this.on("change", function () {
                    updateDisplay($this);
                });

                // Initial display update
                updateDisplay($this);

                $(window).on("resize", function () {
                    updateDisplay($this);
                });
                $(window).on("load", function () {
                    updateDisplay($this);
                });

                // Handle the click event for the remove icon
                $(document).on(
                    "click",
                    ".select2-selection__rendered .close-icon",
                    function (e) {
                        e.stopPropagation();
                        var $removeIcon = $(this);
                        var itemId = $removeIcon.data("id");
                        var $this2 = $removeIcon
                            .closest(".select2")
                            .siblings(".multiple-select2");
                        $this2.val(
                            $this2.val().filter(function (id) {
                                return id != itemId;
                            })
                        );
                        $this2.trigger("change");
                    }
                );
            });
        };
        $(".multiple-select2").select2DynamicDisplay();
    </script>
@endpush
