@extends('layouts.admin.app')

@section('title', $store->name . "'s " . translate('messages.settings'))

@push('css_or_js')
    <!-- Custom styles for this page -->
    <link href="{{ asset('public/assets/admin/css/croppie.css') }}" rel="stylesheet">
@endpush

@section('content')
    <div class="content container-fluid">
        @include('admin-views.vendor.view.partials._header', ['store' => $store])
        <!-- Page Heading -->
        <div class="tab-content">
            <div class="tab-pane fade show active" id="vendor">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">
                            <span class="card-header-icon">
                                <img class="w--22" src="{{ asset('public/assets/admin/img/store.png') }}" alt="">
                            </span>
                            <span class="p-md-1"> {{ translate('messages.store_meta_data') }}</span>
                        </h5>
                    </div>
                    @php($language = \App\Models\BusinessSetting::where('key', 'language')->first())
                    @php($language = $language->value ?? null)
                    @php($defaultLang = 'en')
                    <div class="card-body">
                        <form action="{{ route('admin.store.update-meta-data', [$store['id']]) }}" method="post"
                            enctype="multipart/form-data" class="col-12">
                            @csrf
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
                                                    @foreach (json_decode($language) as $lang)
                                                        <li class="nav-item">
                                                            <a class="nav-link lang_link" href="#"
                                                                id="{{ $lang }}-link">{{ \App\CentralLogics\Helpers::get_language_name($lang) . '(' . strtoupper($lang) . ')' }}</a>
                                                        </li>
                                                    @endforeach
                                                </ul>
                                            @endif
                                            @if ($language)
                                                <div class="lang_form" id="default-form">
                                                    <div class="form-group">
                                                        <label class="input-label"
                                                            for="default_title">{{ translate('messages.meta_title') }}
                                                            ({{ translate('messages.Default') }})
                                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                                data-placement="right"
                                                                data-original-title="{{ translate('This title appears in browser tabs, search results, and link previews.Use a short, clear, and keyword-focused title (recommended: 50–60 characters)') }}">
                                                                <img src="{{ asset('public/assets/admin/img/info-circle.svg') }}"
                                                                    alt="">
                                                            </span>
                                                        </label>
                                                        <input type="text" name="meta_title[]" id="default_title"
                                                            maxlength="60" class="form-control"
                                                            placeholder="{{ translate('messages.meta_title') }}"
                                                            value="{{ $store->getRawOriginal('meta_title') }}">
                                                    </div>
                                                    <input type="hidden" name="lang[]" value="default">
                                                    <div class="form-group mb-0">
                                                        <label class="input-label"
                                                            for="exampleFormControlInput1">{{ translate('messages.meta_description') }}
                                                            ({{ translate('messages.default') }})
                                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                                data-placement="right"
                                                                data-original-title="{{ translate('A brief summary that appears under your page title in search results.Keep it compelling and relevant (recommended: 120–160 characters)') }}">
                                                                <img src="{{ asset('public/assets/admin/img/info-circle.svg') }}"
                                                                    alt="">
                                                            </span></label>
                                                        <textarea type="text" maxlength="160" name="meta_description[]"
                                                            placeholder="{{ translate('messages.meta_description') }}" class="form-control min-h-90px ckeditor">{{ $store->getRawOriginal('meta_description') }}</textarea>
                                                    </div>
                                                </div>
                                                @foreach (json_decode($language) as $lang)
                                                    <?php
                                                    if (count($store['translations'])) {
                                                        $translate = [];
                                                        foreach ($store['translations'] as $t) {
                                                            if ($t->locale == $lang && $t->key == 'meta_title') {
                                                                $translate[$lang]['meta_title'] = $t->value;
                                                            }
                                                            if ($t->locale == $lang && $t->key == 'meta_description') {
                                                                $translate[$lang]['meta_description'] = $t->value;
                                                            }
                                                        }
                                                    }
                                                    ?>
                                                    <div class="d-none lang_form" id="{{ $lang }}-form">
                                                        <div class="form-group">
                                                            <label class="input-label"
                                                                for="{{ $lang }}_title">{{ translate('messages.meta_title') }}
                                                                ({{ strtoupper($lang) }})
                                                                <span class="form-label-secondary" data-toggle="tooltip"
                                                                    data-placement="right"
                                                                    data-original-title="{{ translate('This title appears in browser tabs, search results, and link previews.Use a short, clear, and keyword-focused title (recommended: 50–60 characters)') }}">
                                                                    <img src="{{ asset('public/assets/admin/img/info-circle.svg') }}"
                                                                        alt="">
                                                                </span>
                                                            </label>
                                                            <input type="text" name="meta_title[]"
                                                                id="{{ $lang }}_title" maxlength="60"
                                                                class="form-control"
                                                                value="{{ $translate[$lang]['meta_title'] ?? '' }}"
                                                                placeholder="{{ translate('messages.meta_title') }}">
                                                        </div>
                                                        <input type="hidden" name="lang[]" value="{{ $lang }}">
                                                        <div class="form-group mb-0">
                                                            <label class="input-label"
                                                                for="exampleFormControlInput1">{{ translate('messages.meta_description') }}
                                                                ({{ strtoupper($lang) }})
                                                                <span class="form-label-secondary" data-toggle="tooltip"
                                                                    data-placement="right"
                                                                    data-original-title="{{ translate('A brief summary that appears under your page title in search results.Keep it compelling and relevant (recommended: 120–160 characters)') }}">
                                                                    <img src="{{ asset('public/assets/admin/img/info-circle.svg') }}"
                                                                        alt="">
                                                                </span></label>
                                                            <textarea type="text" maxlength="160" name="meta_description[]"
                                                                placeholder="{{ translate('messages.meta_description') }}" class="form-control min-h-90px ckeditor">{{ $translate[$lang]['meta_description'] ?? '' }}</textarea>
                                                        </div>
                                                    </div>
                                                @endforeach
                                            @else
                                                <div id="default-form">
                                                    <div class="form-group">
                                                        <label class="input-label"
                                                            for="exampleFormControlInput1">{{ translate('messages.meta_title') }}
                                                            ({{ translate('messages.default') }})</label>
                                                        <input type="text" name="meta_title[]" class="form-control"
                                                            placeholder="{{ translate('messages.meta_title') }}">
                                                    </div>
                                                    <input type="hidden" name="lang[]" value="default">
                                                    <div class="form-group mb-0">
                                                        <label class="input-label"
                                                            for="exampleFormControlInput1">{{ translate('messages.meta_description') }}
                                                        </label>
                                                        <textarea type="text" name="meta_description[]" placeholder="{{ translate('messages.meta_description') }}"
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
                                                <span>{{ translate('store_meta_image') }}</span>
                                            </h5>
                                        </div>
                                        <div class="card-body">
                                            <div class="d-flex justify-content-center flex-wrap flex-sm-nowrap __gap-12px">
                                                <label class="__custom-upload-img mr-lg-5">
                                                    <div class="position-relative">
                                                        <label class="form-label">
                                                            {{ translate('meta_image') }} <span
                                                                class="text--primary">({{ translate('2:1') }})</span>
                                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                                data-placement="right"
                                                                data-original-title="{{ translate('This image is used as a preview thumbnail when the page link is shared on social media or messaging platforms.') }}">
                                                                <img src="{{ asset('public/assets/admin/img/info-circle.svg') }}"
                                                                    alt="">
                                                            </span></label>

                                                        <div class="text-center">
                                                            <img class="img--110 min-height-170px min-width-170px onerror-image"
                                                                id="viewer"
                                                                data-onerror-image="{{ asset('public/assets/admin/img/upload.png') }}"
                                                                src="{{ $store->meta_image_full_url ?? asset('public/assets/admin/img/upload.png') }}"
                                                                alt="{{ translate('meta_image') }}" />
                                                        </div>
                                                        <input type="file" name="meta_image" id="customFileEg1"
                                                            class="custom-file-input"
                                                            accept=".webp, .jpg, .png, .jpeg, .gif, .bmp, .tif, .tiff|image/*">

                                                        @if (isset($store->meta_image))
                                                            <span id="earning_delivery_img"
                                                                class="remove_image_button mt-4 dynamic-checkbox"
                                                                data-id="earning_delivery_img" data-type="status"
                                                                data-image-on='{{ asset('/public/assets/admin/img/modal') }}/mail-success.png'
                                                                data-image-off="{{ asset('/public/assets/admin/img/modal') }}/mail-warning.png"
                                                                data-title-on="{{ translate('Important!') }}"
                                                                data-title-off="{{ translate('Warning!') }}"
                                                                data-text-on="<p>{{ translate('Are_you_sure_you_want_to_remove_this_image') }}</p>"
                                                                data-text-off="<p>{{ translate('Are_you_sure_you_want_to_remove_this_image.') }}</p>">
                                                                <i class="tio-clear"></i></span>
                                                        @endif
                                                    </div>
                                                </label>
                                            </div>
                                             <div class="d-flex justify-content-center">
                            <div class="text-center">
                                <small>{{ translate('Upload a rectangular image (recommended size: 800×400 px, format: JPG or PNG)') }}</small>
                            </div>
                        </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="justify-content-end btn--container">
                                        <button type="submit"
                                            class="btn btn--primary">{{ translate('save_changes') }}</button>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <form id="earning_delivery_img_form" action="{{ route('admin.remove_image') }}" method="post">
        @csrf
        <input type="hidden" name="id" value="{{ $store?->id }}">
        <input type="hidden" name="model_name" value="Store">
        <input type="hidden" name="image_path" value="store">
        <input type="hidden" name="field_name" value="meta_image">
    </form>
@endsection

@push('script_2')
    <script>
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
    </script>
@endpush
