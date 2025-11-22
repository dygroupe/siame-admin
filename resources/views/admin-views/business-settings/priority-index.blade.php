@extends('layouts.admin.app')

@section('title', translate('messages.priority_settings'))

@push('css_or_js')
@endpush

@section('content')
    <div class="content container-fluid">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-header-title mr-3">
                <span class="page-header-icon">
                    <img src="{{ asset('public/assets/admin/img/business.png') }}" class="w--26" alt="">
                </span>
                <span>
                    {{ translate('business_setup') }}
                </span>
            </h1>

            @include('admin-views.business-settings.partials.nav-menu')

        </div>

        <!-- Main Content -->
        <div class="card">
            <form method="post" action="{{ route('admin.business-settings.update-priority') }}">
                @csrf
                <div class="card-body">
                    {{-- Category List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Category_List') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The_Item_Category_list_groups_similar_items_together_arranged_with_the_latest_category_first_and_in_alphabetical_order.') }}
                                </p>
                            </div>
                        </div>
                        @php($category_list_default_status = \App\Models\BusinessSetting::where('key', 'category_list_default_status')->first()?->value ?? 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by priority') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="category_list_default_status" value="1"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $category_list_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="category_list_default_status" value="0"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $category_list_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($category_list_sort_by_general = \App\Models\PriorityList::where('name', 'category_list_sort_by_general')->where('type', 'general')->first()?->value ?? '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_list_sort_by_general" value="latest"
                                                        {{ $category_list_sort_by_general == 'latest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by latest created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_list_sort_by_general" value="oldest"
                                                        {{ $category_list_sort_by_general == 'oldest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by first created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_list_sort_by_general" value="order_count"
                                                        {{ $category_list_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_list_sort_by_general" value="a_to_z"
                                                        {{ $category_list_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_list_sort_by_general" value="z_to_a"
                                                        {{ $category_list_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>

                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Best Stores Nearby List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Best Stores Nearby') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Best Stores Nearby is the list of customer choices in which customer ordered items most and also highly rated with good reviews') }}
                                </p>
                            </div>
                        </div>
                        @php($popular_store_default_status = \App\Models\BusinessSetting::where('key', 'popular_store_default_status')->first())
                        @php($popular_store_default_status = $popular_store_default_status ? $popular_store_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_distance_which_is_the_most_nearby_user_and_total_orders.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="popular_store_default_status" value="1"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $popular_store_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="popular_store_default_status" value="0"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $popular_store_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($popular_store_sort_by_rating = \App\Models\PriorityList::where('name', 'popular_store_sort_by_rating')->where('type', 'rating')->first())
                                            @php($popular_store_sort_by_rating = $popular_store_sort_by_rating ? $popular_store_sort_by_rating->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_rating" value="four_plus"
                                                        {{ $popular_store_sort_by_rating == 'four_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 4+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_rating" value="three_half_plus"
                                                        {{ $popular_store_sort_by_rating == 'three_half_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 3.5+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_rating" value="three_plus"
                                                        {{ $popular_store_sort_by_rating == 'three_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 3+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_rating" value="two_plus"
                                                        {{ $popular_store_sort_by_rating == 'two_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 2+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_rating" value="none"
                                                        {{ $popular_store_sort_by_rating == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($popular_store_sort_by_general = \App\Models\PriorityList::where('name', 'popular_store_sort_by_general')->where('type', 'general')->first())
                                            @php($popular_store_sort_by_general = $popular_store_sort_by_general ? $popular_store_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="popular_store_sort_by_general" value="nearest_first"
                                                        {{ $popular_store_sort_by_general == 'nearest_first' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Distance from customer location') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_general" value="order_count"
                                                        {{ $popular_store_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_general" value="review_count"
                                                        {{ $popular_store_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_general" value="rating"
                                                        {{ $popular_store_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($popular_store_sort_by_unavailable = \App\Models\PriorityList::where('name', 'popular_store_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($popular_store_sort_by_unavailable = $popular_store_sort_by_unavailable ? $popular_store_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_unavailable" value="last"
                                                        {{ $popular_store_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show currently closed stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_unavailable" value="remove"
                                                        {{ $popular_store_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove currently closed stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_unavailable" value="none"
                                                        {{ $popular_store_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($popular_store_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'popular_store_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($popular_store_sort_by_temp_closed = $popular_store_sort_by_temp_closed ? $popular_store_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_temp_closed" value="last"
                                                        {{ $popular_store_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show temporarily off stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_temp_closed" value="remove"
                                                        {{ $popular_store_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove temporarily off stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_store_sort_by_temp_closed" value="none"
                                                        {{ $popular_store_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Recommended Store List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Recommended Store') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Recommended Stores is the list of Admin choices which is highly recommended by admin') }}
                                </p>
                            </div>
                        </div>
                        @php($recommended_store_default_status = \App\Models\BusinessSetting::where('key', 'recommended_store_default_status')->first())
                        @php($recommended_store_default_status = $recommended_store_default_status ? $recommended_store_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_oldest_recommended_stores.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="recommended_store_default_status"
                                                    value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $recommended_store_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="recommended_store_default_status"
                                                    value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $recommended_store_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($recommended_store_sort_by_general = \App\Models\PriorityList::where('name', 'recommended_store_sort_by_general')->where('type', 'general')->first())
                                            @php($recommended_store_sort_by_general = $recommended_store_sort_by_general ? $recommended_store_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="recommended_store_sort_by_general" value="order_count"
                                                        {{ $recommended_store_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="recommended_store_sort_by_general" value="review_count"
                                                        {{ $recommended_store_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="recommended_store_sort_by_general" value="rating"
                                                        {{ $recommended_store_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($recommended_store_sort_by_rating = \App\Models\PriorityList::where('name', 'recommended_store_sort_by_rating')->where('type', 'rating')->first())
                                            @php($recommended_store_sort_by_rating = $recommended_store_sort_by_rating ? $recommended_store_sort_by_rating->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_rating" value="four_plus"
                                                        {{ $recommended_store_sort_by_rating == 'four_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 4+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_rating" value="three_half_plus"
                                                        {{ $recommended_store_sort_by_rating == 'three_half_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 3.5+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_rating" value="three_plus"
                                                        {{ $recommended_store_sort_by_rating == 'three_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 3+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_rating" value="two_plus"
                                                        {{ $recommended_store_sort_by_rating == 'two_plus' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show 2+ rated sellers') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_rating" value="none"
                                                        {{ $recommended_store_sort_by_rating == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($recommended_store_sort_by_unavailable = \App\Models\PriorityList::where('name', 'recommended_store_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($recommended_store_sort_by_unavailable = $recommended_store_sort_by_unavailable ? $recommended_store_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_unavailable" value="last"
                                                        {{ $recommended_store_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show currently closed stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_unavailable" value="remove"
                                                        {{ $recommended_store_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove currently closed stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_unavailable" value="none"
                                                        {{ $recommended_store_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($recommended_store_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'recommended_store_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($recommended_store_sort_by_temp_closed = $recommended_store_sort_by_temp_closed ? $recommended_store_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_temp_closed" value="last"
                                                        {{ $recommended_store_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show temporarily off stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_temp_closed" value="remove"
                                                        {{ $recommended_store_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove temporarily off stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="recommended_store_sort_by_temp_closed" value="none"
                                                        {{ $recommended_store_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Special Offer List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Special Offers') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The special offers includes the list of discounted items offered for the customers') }}
                                </p>
                            </div>
                        </div>
                        @php($special_offer_default_status = \App\Models\BusinessSetting::where('key', 'special_offer_default_status')->first())
                        @php($special_offer_default_status = $special_offer_default_status ? $special_offer_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by highest discount amount.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="special_offer_default_status" value="1"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $special_offer_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="special_offer_default_status" value="0"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $special_offer_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($special_offer_sort_by_general = \App\Models\PriorityList::where('name', 'special_offer_sort_by_general')->where('type', 'general')->first())
                                            @php($special_offer_sort_by_general = $special_offer_sort_by_general ? $special_offer_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_general" value="order_count"
                                                        {{ $special_offer_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_general" value="review_count"
                                                        {{ $special_offer_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_general" value="rating"
                                                        {{ $special_offer_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_general" value="a_to_z"
                                                        {{ $special_offer_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_general" value="z_to_a"
                                                        {{ $special_offer_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($special_offer_sort_by_unavailable = \App\Models\PriorityList::where('name', 'special_offer_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($special_offer_sort_by_unavailable = $special_offer_sort_by_unavailable ? $special_offer_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_unavailable" value="last"
                                                        {{ $special_offer_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_unavailable" value="remove"
                                                        {{ $special_offer_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="special_offer_sort_by_unavailable" value="none"
                                                        {{ $special_offer_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <br>

                    {{-- Most Popular Item List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Most Popular Item') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Popular item Nearby means the item items list  which are mostly ordered by the customers and have good reviews & ratings') }}
                                </p>
                            </div>
                        </div>
                        @php($popular_item_default_status = \App\Models\BusinessSetting::where('key', 'popular_item_default_status')->first())
                        @php($popular_item_default_status = $popular_item_default_status ? $popular_item_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top"
                                                    data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_higher_ordered_items.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="popular_item_default_status"
                                                    value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $popular_item_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top"
                                                    data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="popular_item_default_status"
                                                    value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $popular_item_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($popular_item_sort_by_general = \App\Models\PriorityList::where('name', 'popular_item_sort_by_general')->where('type', 'general')->first())
                                            @php($popular_item_sort_by_general = $popular_item_sort_by_general ? $popular_item_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="popular_item_sort_by_general" value="latest_created"
                                                        {{ $popular_item_sort_by_general == 'latest_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by latest created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="popular_item_sort_by_general" value="first_created"
                                                        {{ $popular_item_sort_by_general == 'first_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by first created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_general" value="order_count"
                                                        {{ $popular_item_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_general" value="review_count"
                                                        {{ $popular_item_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_general" value="rating"
                                                        {{ $popular_item_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_general" value="a_to_z"
                                                        {{ $popular_item_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_general" value="z_to_a"
                                                        {{ $popular_item_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($popular_item_sort_by_unavailable = \App\Models\PriorityList::where('name', 'popular_item_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($popular_item_sort_by_unavailable = $popular_item_sort_by_unavailable ? $popular_item_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_unavailable" value="last"
                                                        {{ $popular_item_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_unavailable" value="remove"
                                                        {{ $popular_item_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_unavailable" value="none"
                                                        {{ $popular_item_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($popular_item_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'popular_item_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($popular_item_sort_by_temp_closed = $popular_item_sort_by_temp_closed ? $popular_item_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_temp_closed" value="last"
                                                        {{ $popular_item_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show product in the last if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_temp_closed" value="remove"
                                                        {{ $popular_item_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove product from the list if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="popular_item_sort_by_temp_closed" value="none"
                                                        {{ $popular_item_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Best Reviewed Item List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Best Reviewed Item') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Best Reviewed items are the top most ordered item list of customer choice which are highly rated & reviewed ') }}
                                </p>
                            </div>
                        </div>
                        @php($best_reviewed_item_default_status = \App\Models\BusinessSetting::where('key', 'best_reviewed_item_default_status')->first())
                        @php($best_reviewed_item_default_status = $best_reviewed_item_default_status ? $best_reviewed_item_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                          data-toggle="tooltip" data-placement="top"
                                                          data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by top ratings') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="best_reviewed_item_default_status"
                                                       value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $best_reviewed_item_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                          data-toggle="tooltip" data-placement="top"
                                                          data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="best_reviewed_item_default_status"
                                                       value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $best_reviewed_item_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($best_reviewed_item_sort_by_general = \App\Models\PriorityList::where('name', 'best_reviewed_item_sort_by_general')->where('type', 'general')->first())
                                            @php($best_reviewed_item_sort_by_general = $best_reviewed_item_sort_by_general ? $best_reviewed_item_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_general" value="order_count"
                                                        {{ $best_reviewed_item_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by orders count') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_general" value="review_count"
                                                        {{ $best_reviewed_item_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by reviews count') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_general" value="rating"
                                                        {{ $best_reviewed_item_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by ratings') }}
                                                        </span>
                                                </label>
                                            </div>
                                            @php($best_reviewed_item_sort_by_unavailable = \App\Models\PriorityList::where('name', 'best_reviewed_item_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($best_reviewed_item_sort_by_unavailable = $best_reviewed_item_sort_by_unavailable ? $best_reviewed_item_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_unavailable" value="last"
                                                        {{ $best_reviewed_item_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show stockout products in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_unavailable" value="remove"
                                                        {{ $best_reviewed_item_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove stockout products from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_unavailable" value="none"
                                                        {{ $best_reviewed_item_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                            @php($best_reviewed_item_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'best_reviewed_item_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($best_reviewed_item_sort_by_temp_closed = $best_reviewed_item_sort_by_temp_closed ? $best_reviewed_item_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_temp_closed" value="last"
                                                        {{ $best_reviewed_item_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show product in the last if store is temporarily off') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_temp_closed" value="remove"
                                                        {{ $best_reviewed_item_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove product from the list if store is temporarily off') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="best_reviewed_item_sort_by_temp_closed" value="none"
                                                        {{ $best_reviewed_item_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                   {{-- Just for You (Item Campaign) --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Just for You') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Just for You is the Item campaign includes the list of discounted items offered for the customers.') }}
                                </p>
                            </div>
                        </div>
                        @php($item_campaign_default_status = \App\Models\BusinessSetting::where('key', 'item_campaign_default_status')->first()?->value ?? 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by latest') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="item_campaign_default_status" value="1"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $item_campaign_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="item_campaign_default_status" value="0"
                                                    class="toggle-switch-input collapse-div-toggler"
                                                    {{ $item_campaign_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($item_campaign_sort_by_general = \App\Models\PriorityList::where('name', 'item_campaign_sort_by_general')->where('type', 'general')->first()?->value ?? '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="order_count"
                                                        {{ $item_campaign_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="end_first"
                                                        {{ $item_campaign_sort_by_general == 'end_first' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by End Date of campaign') }}
                                                    </span>
                                                </label>
                                                {{-- <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="review_count"
                                                        {{ $item_campaign_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="ratings"
                                                        {{ $item_campaign_sort_by_general == 'ratings' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label> --}}
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="a_to_z"
                                                        {{ $item_campaign_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="item_campaign_sort_by_general" value="z_to_a"
                                                        {{ $item_campaign_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>

                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>


                {{-- New on (products latest)

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('New_0n') }} {{\App\Models\BusinessSetting::where(['key'=>'business_name'])->first()?->value}}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Best New items are the top most ordered item list of customer choice which are highly rated & reviewed ') }}
                                </p>
                            </div>
                        </div>
                        @php($latest_items_default_status = \App\Models\BusinessSetting::where('key', 'latest_items_default_status')->first())
                        @php($latest_items_default_status = $latest_items_default_status ? $latest_items_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by latest') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="latest_items_default_status"
                                                        value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $latest_items_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="latest_items_default_status"
                                                        value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $latest_items_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($latest_items_sort_by_general = \App\Models\PriorityList::where('name', 'latest_items_sort_by_general')->where('type', 'general')->first())
                                            @php($latest_items_sort_by_general = $latest_items_sort_by_general ? $latest_items_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_general" value="latest_created"
                                                        {{ $latest_items_sort_by_general == 'latest_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by latest created') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_general" value="review_count"
                                                        {{ $latest_items_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by reviews count') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_general" value="rating"
                                                        {{ $latest_items_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by ratings') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="latest_items_sort_by_general" value="a_to_z"
                                                        {{ $latest_items_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="latest_items_sort_by_general" value="z_to_a"
                                                        {{ $latest_items_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($latest_items_sort_by_unavailable = \App\Models\PriorityList::where('name', 'latest_items_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($latest_items_sort_by_unavailable = $latest_items_sort_by_unavailable ? $latest_items_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_unavailable" value="last"
                                                        {{ $latest_items_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show stockout products in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_unavailable" value="remove"
                                                        {{ $latest_items_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove stockout products from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_unavailable" value="none"
                                                        {{ $latest_items_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                            @php($latest_items_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'latest_items_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($latest_items_sort_by_temp_closed = $latest_items_sort_by_temp_closed ? $latest_items_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_temp_closed" value="last"
                                                        {{ $latest_items_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show product in the last if store is temporarily off') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_temp_closed" value="remove"
                                                        {{ $latest_items_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove product from the list if store is temporarily off') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_items_sort_by_temp_closed" value="none"
                                                        {{ $latest_items_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br> --}}


                    {{-- New on (stores latest) --}}


                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('New_0n') }} {{\App\Models\BusinessSetting::where(['key'=>'business_name'])->first()?->value}}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The New store list arranges stores based on the latest join that are closest to the customers location.') }}
                                </p>
                            </div>
                        </div>
                        @php($latest_stores_default_status = \App\Models\BusinessSetting::where('key', 'latest_stores_default_status')->first())
                        @php($latest_stores_default_status = $latest_stores_default_status ? $latest_stores_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by latest') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="latest_stores_default_status"
                                                        value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $latest_stores_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="latest_stores_default_status"
                                                        value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $latest_stores_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($latest_stores_sort_by_general = \App\Models\PriorityList::where('name', 'latest_stores_sort_by_general')->where('type', 'general')->first())
                                            @php($latest_stores_sort_by_general = $latest_stores_sort_by_general ? $latest_stores_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_general" value="latest_created"
                                                        {{ $latest_stores_sort_by_general == 'latest_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by latest created') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_general" value="review_count"
                                                        {{ $latest_stores_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by reviews count') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_general" value="rating"
                                                        {{ $latest_stores_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by ratings') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="latest_stores_sort_by_general" value="a_to_z"
                                                        {{ $latest_stores_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="latest_stores_sort_by_general" value="z_to_a"
                                                        {{ $latest_stores_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($latest_stores_sort_by_unavailable = \App\Models\PriorityList::where('name', 'latest_stores_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($latest_stores_sort_by_unavailable = $latest_stores_sort_by_unavailable ? $latest_stores_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_unavailable" value="last"
                                                        {{ $latest_stores_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show currently closed stores in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_unavailable" value="remove"
                                                        {{ $latest_stores_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove currently closed stores from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_unavailable" value="none"
                                                        {{ $latest_stores_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                            @php($latest_stores_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'latest_stores_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($latest_stores_sort_by_temp_closed = $latest_stores_sort_by_temp_closed ? $latest_stores_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_temp_closed" value="last"
                                                        {{ $latest_stores_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show temporarily off stores in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_temp_closed" value="remove"
                                                        {{ $latest_stores_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove temporarily off stores from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="latest_stores_sort_by_temp_closed" value="none"
                                                        {{ $latest_stores_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- All Stores List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('All Stores') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The all store list arranges all stores based on the latest join that are closest to the customers location.') }}
                                </p>
                            </div>
                        </div>
                        @php($all_stores_default_status = \App\Models\BusinessSetting::where('key', 'all_stores_default_status')->first())
                        @php($all_stores_default_status = $all_stores_default_status ? $all_stores_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_active_stores.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="all_stores_default_status"
                                                    value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $all_stores_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="all_stores_default_status"
                                                    value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $all_stores_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">

                                            @php($all_stores_sort_by_general = \App\Models\PriorityList::where('name', 'all_stores_sort_by_general')->where('type', 'general')->first())
                                            @php($all_stores_sort_by_general = $all_stores_sort_by_general ? $all_stores_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="latest_created"
                                                        {{ $all_stores_sort_by_general == 'latest_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by latest created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="first_created"
                                                        {{ $all_stores_sort_by_general == 'first_created' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by first created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="order_count"
                                                        {{ $all_stores_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="review_count"
                                                        {{ $all_stores_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="rating"
                                                        {{ $all_stores_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="a_to_z"
                                                        {{ $all_stores_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_general" value="z_to_a"
                                                        {{ $all_stores_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($all_stores_sort_by_unavailable = \App\Models\PriorityList::where('name', 'all_stores_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($all_stores_sort_by_unavailable = $all_stores_sort_by_unavailable ? $all_stores_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_unavailable" value="last"
                                                        {{ $all_stores_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show currently closed stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_unavailable" value="remove"
                                                        {{ $all_stores_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove currently closed stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_unavailable" value="none"
                                                        {{ $all_stores_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($all_stores_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'all_stores_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($all_stores_sort_by_temp_closed = $all_stores_sort_by_temp_closed ? $all_stores_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_temp_closed" value="last"
                                                        {{ $all_stores_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show temporarily off stores in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_temp_closed" value="remove"
                                                        {{ $all_stores_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove temporarily off stores from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="all_stores_sort_by_temp_closed" value="none"
                                                        {{ $all_stores_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Category / Subcategory wise product list --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Category / Subcategory wise product list') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Category / Subcategory Wise Items means the latest items list under a specific category') }}
                                </p>
                            </div>
                        </div>
                        @php($category_sub_category_item_default_status = \App\Models\BusinessSetting::where('key', 'category_sub_category_item_default_status')->first())
                        @php($category_sub_category_item_default_status = $category_sub_category_item_default_status ? $category_sub_category_item_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_latest_created_items.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="category_sub_category_item_default_status"
                                                    value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $category_sub_category_item_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="category_sub_category_item_default_status"
                                                    value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $category_sub_category_item_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">

                                            @php($category_sub_category_item_sort_by_general = \App\Models\PriorityList::where('name', 'category_sub_category_item_sort_by_general')->where('type', 'general')->first())
                                            @php($category_sub_category_item_sort_by_general = $category_sub_category_item_sort_by_general ? $category_sub_category_item_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">

                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_general" value="order_count"
                                                        {{ $category_sub_category_item_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_general" value="review_count"
                                                        {{ $category_sub_category_item_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_general" value="rating"
                                                        {{ $category_sub_category_item_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_general" value="a_to_z"
                                                        {{ $category_sub_category_item_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_general" value="z_to_a"
                                                        {{ $category_sub_category_item_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($category_sub_category_item_sort_by_unavailable = \App\Models\PriorityList::where('name', 'category_sub_category_item_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($category_sub_category_item_sort_by_unavailable = $category_sub_category_item_sort_by_unavailable ? $category_sub_category_item_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_unavailable" value="last"
                                                        {{ $category_sub_category_item_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_unavailable" value="remove"
                                                        {{ $category_sub_category_item_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_unavailable" value="none"
                                                        {{ $category_sub_category_item_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($category_sub_category_item_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'category_sub_category_item_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($category_sub_category_item_sort_by_temp_closed = $category_sub_category_item_sort_by_temp_closed ? $category_sub_category_item_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_temp_closed" value="last"
                                                        {{ $category_sub_category_item_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show product in the last if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_temp_closed" value="remove"
                                                        {{ $category_sub_category_item_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove product from the list if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="category_sub_category_item_sort_by_temp_closed" value="none"
                                                        {{ $category_sub_category_item_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- product search list --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('product search list') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('product search list (Search Bar) means the item list from top search bar') }}
                                </p>
                            </div>
                        </div>
                        @php($product_search_default_status = \App\Models\BusinessSetting::where('key', 'product_search_default_status')->first())
                        @php($product_search_default_status = $product_search_default_status ? $product_search_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_active_items.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="product_search_default_status"
                                                    value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $product_search_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                    data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="product_search_default_status"
                                                    value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $product_search_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">

                                            @php($product_search_sort_by_general = \App\Models\PriorityList::where('name', 'product_search_sort_by_general')->where('type', 'general')->first())
                                            @php($product_search_sort_by_general = $product_search_sort_by_general ? $product_search_sort_by_general->value : '')
                                            <input hidden class="form-check-input" type="radio"
                                            name="product_search_sort_by_general" value="order_count" checked>

                                            @php($product_search_sort_by_unavailable = \App\Models\PriorityList::where('name', 'product_search_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($product_search_sort_by_unavailable = $product_search_sort_by_unavailable ? $product_search_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_unavailable" value="last"
                                                        {{ $product_search_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_unavailable" value="remove"
                                                        {{ $product_search_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_unavailable" value="none"
                                                        {{ $product_search_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($product_search_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'product_search_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($product_search_sort_by_temp_closed = $product_search_sort_by_temp_closed ? $product_search_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_temp_closed" value="last"
                                                        {{ $product_search_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show product in the last if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_temp_closed" value="remove"
                                                        {{ $product_search_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove product from the list if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="product_search_sort_by_temp_closed" value="none"
                                                        {{ $product_search_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Basic Medicine Nearby list --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Basic Medicine Nearby') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Basic Medicine Nearby is item list of the stores based on the latest join that are closest to the customers location.') }}
                                </p>
                            </div>
                        </div>
                        @php($basic_medicine_default_status = \App\Models\BusinessSetting::where('key', 'basic_medicine_default_status')->first())
                        @php($basic_medicine_default_status = $basic_medicine_default_status ? $basic_medicine_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_total_orders.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="basic_medicine_default_status"
                                                       value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $basic_medicine_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="basic_medicine_default_status"
                                                       value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $basic_medicine_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">

                                            @php($basic_medicine_sort_by_general = \App\Models\PriorityList::where('name', 'basic_medicine_sort_by_general')->where('type', 'general')->first())
                                            @php($basic_medicine_sort_by_general = $basic_medicine_sort_by_general ? $basic_medicine_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">

                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_general" value="order_count"
                                                        {{ $basic_medicine_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_general" value="review_count"
                                                        {{ $basic_medicine_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_general" value="rating"
                                                        {{ $basic_medicine_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_general" value="a_to_z"
                                                        {{ $basic_medicine_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_general" value="z_to_a"
                                                        {{ $basic_medicine_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($basic_medicine_sort_by_unavailable = \App\Models\PriorityList::where('name', 'basic_medicine_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($basic_medicine_sort_by_unavailable = $basic_medicine_sort_by_unavailable ? $basic_medicine_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_unavailable" value="last"
                                                        {{ $basic_medicine_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_unavailable" value="remove"
                                                        {{ $basic_medicine_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_unavailable" value="none"
                                                        {{ $basic_medicine_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($basic_medicine_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'basic_medicine_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($basic_medicine_sort_by_temp_closed = $basic_medicine_sort_by_temp_closed ? $basic_medicine_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_temp_closed" value="last"
                                                        {{ $basic_medicine_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show product in the last if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_temp_closed" value="remove"
                                                        {{ $basic_medicine_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove product from the list if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="basic_medicine_sort_by_temp_closed" value="none"
                                                        {{ $basic_medicine_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Common Condition List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Common Condition') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('Common Condition is the list of items which are mostly commonly used by the users.') }}
                                </p>
                            </div>
                        </div>
                        @php($common_condition_default_status = \App\Models\BusinessSetting::where('key', 'common_condition_default_status')->first()?->value ?? 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by active conditions') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="common_condition_default_status" value="1"
                                                       class="toggle-switch-input collapse-div-toggler"
                                                    {{ $common_condition_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="common_condition_default_status" value="0"
                                                       class="toggle-switch-input collapse-div-toggler"
                                                    {{ $common_condition_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($common_condition_sort_by_general = \App\Models\PriorityList::where('name', 'common_condition_sort_by_general')->where('type', 'general')->first()?->value ?? '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="common_condition_sort_by_general" value="latest"
                                                        {{ $common_condition_sort_by_general == 'latest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by latest created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="common_condition_sort_by_general" value="oldest"
                                                        {{ $common_condition_sort_by_general == 'oldest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by first created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="common_condition_sort_by_general" value="order_count"
                                                        {{ $common_condition_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="common_condition_sort_by_general" value="a_to_z"
                                                        {{ $common_condition_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="common_condition_sort_by_general" value="z_to_a"
                                                        {{ $common_condition_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>

                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Brand List --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Brand') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The list of well known brands.') }}
                                </p>
                            </div>
                        </div>
                        @php($brand_default_status = \App\Models\BusinessSetting::where('key', 'brand_default_status')->first()?->value ?? 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Currently sorting this section by active brands') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="brand_default_status" value="1"
                                                       class="toggle-switch-input collapse-div-toggler"
                                                    {{ $brand_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="brand_default_status" value="0"
                                                       class="toggle-switch-input collapse-div-toggler"
                                                    {{ $brand_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($brand_sort_by_general = \App\Models\PriorityList::where('name', 'brand_sort_by_general')->where('type', 'general')->first()?->value ?? '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_sort_by_general" value="latest"
                                                        {{ $brand_sort_by_general == 'latest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by latest created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_sort_by_general" value="oldest"
                                                        {{ $brand_sort_by_general == 'oldest' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by first created') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_sort_by_general" value="order_count"
                                                        {{ $brand_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_sort_by_general" value="a_to_z"
                                                        {{ $brand_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_sort_by_general" value="z_to_a"
                                                        {{ $brand_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>

                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Brand wise product list --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Brand wise product list') }}</h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The Brand wise product list groups similar items together arranged with the latest brand first.') }}
                                </p>
                            </div>
                        </div>
                        @php($brand_item_default_status = \App\Models\BusinessSetting::where('key', 'brand_item_default_status')->first())
                        @php($brand_item_default_status = $brand_item_default_status ? $brand_item_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use default sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('This_section_is_currently_sorted_by_latest_created_items.') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="brand_item_default_status"
                                                       value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $brand_item_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">{{ translate('Use custom sorting list') }}
                                            </h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                <span class="input-label-secondary text--title ml-0 mr-1"
                                                      data-toggle="tooltip" data-placement="top" data-original-title="">
                                                    <i class="tio-info-outined"></i>
                                                </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}</div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="brand_item_default_status"
                                                       value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $brand_item_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">

                                            @php($brand_item_sort_by_general = \App\Models\PriorityList::where('name', 'brand_item_sort_by_general')->where('type', 'general')->first())
                                            @php($brand_item_sort_by_general = $brand_item_sort_by_general ? $brand_item_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">

                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_general" value="order_count"
                                                        {{ $brand_item_sort_by_general == 'order_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by orders') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_general" value="review_count"
                                                        {{ $brand_item_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by reviews count') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_general" value="rating"
                                                        {{ $brand_item_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by ratings') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_general" value="a_to_z"
                                                        {{ $brand_item_sort_by_general == 'a_to_z' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (A to Z)') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_general" value="z_to_a"
                                                        {{ $brand_item_sort_by_general == 'z_to_a' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Sort by Alphabetical (Z to A)') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($brand_item_sort_by_unavailable = \App\Models\PriorityList::where('name', 'brand_item_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($brand_item_sort_by_unavailable = $brand_item_sort_by_unavailable ? $brand_item_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_unavailable" value="last"
                                                        {{ $brand_item_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show stockout products in the last') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_unavailable" value="remove"
                                                        {{ $brand_item_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove stockout products from the list') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_unavailable" value="none"
                                                        {{ $brand_item_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($brand_item_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'brand_item_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($brand_item_sort_by_temp_closed = $brand_item_sort_by_temp_closed ? $brand_item_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_temp_closed" value="last"
                                                        {{ $brand_item_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Show product in the last if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_temp_closed" value="remove"
                                                        {{ $brand_item_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Remove product from the list if store is temporarily off') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                           name="brand_item_sort_by_temp_closed" value="none"
                                                        {{ $brand_item_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('None') }}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    {{-- Top offer near me (discounted) --}}

                    <div class="row g-3">
                        <div class="col-lg-6">
                            <div class="max-w-353px">
                                <h4 class="mb-2 mt-4">{{ translate('Top_offer_near_me') }} </h4>
                                <p class="m-0 fs-12">
                                    {{ translate('The store list arranges stores based on the dicount and closest to the customers location.') }}
                                </p>
                            </div>
                        </div>
                        @php($top_offer_near_me_stores_default_status = \App\Models\BusinessSetting::where('key', 'top_offer_near_me_stores_default_status')->first())
                        @php($top_offer_near_me_stores_default_status = $top_offer_near_me_stores_default_status ? $top_offer_near_me_stores_default_status->value : 1)
                        <div class="col-lg-6">
                            <div class="__bg-FAFAFA rounded">
                                <!-- Default Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use default sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('This section sorted based on the dicount and closest to the customers location') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="top_offer_near_me_stores_default_status"
                                                        value="1" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $top_offer_near_me_stores_default_status == '1' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <!-- Custom Collapsible Card -->
                                <div class="sorting-card p-20px">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div class="w-0 flex-grow">
                                            <h5 class="fs-14 font-semibold">
                                                {{ translate('Use custom sorting list') }}</h5>
                                            <label class="form-label d-flex align-items-center m-0">
                                                    <span class="input-label-secondary text--title ml-0 mr-1"
                                                            data-toggle="tooltip" data-placement="top"
                                                            data-original-title="">
                                                        <i class="tio-info-outined"></i>
                                                    </span>
                                                <div class="fs-13">
                                                    {{ translate('Set customized condition to show this list') }}
                                                </div>
                                            </label>
                                        </div>
                                        <div>
                                            <label
                                                class="switch--custom-label toggle-switch toggle-switch-sm d-inline-flex">
                                                <input type="radio" name="top_offer_near_me_stores_default_status"
                                                        value="0" class="toggle-switch-input collapse-div-toggler"
                                                    {{ $top_offer_near_me_stores_default_status == '0' ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                        <span class="toggle-switch-indicator"></span>
                                                    </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="inner-collapse-div">
                                        <div class="pt-4">
                                            @php($top_offer_near_me_stores_sort_by_general = \App\Models\PriorityList::where('name', 'top_offer_near_me_stores_sort_by_general')->where('type', 'general')->first())
                                            @php($top_offer_near_me_stores_sort_by_general = $top_offer_near_me_stores_sort_by_general ? $top_offer_near_me_stores_sort_by_general->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_general" value="review_count"
                                                        {{ $top_offer_near_me_stores_sort_by_general == 'review_count' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by reviews count') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_general" value="rating"
                                                        {{ $top_offer_near_me_stores_sort_by_general == 'rating' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Sort by ratings') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="top_offer_near_me_stores_sort_by_general" value="asc_discount"
                                                        {{ $top_offer_near_me_stores_sort_by_general == 'asc_discount' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Based on the Discount amount - Ascending') }}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                        name="top_offer_near_me_stores_sort_by_general" value="desc_discount"
                                                        {{ $top_offer_near_me_stores_sort_by_general == 'desc_discount' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{ translate('Based on the Discount amount - Descending') }}
                                                    </span>
                                                </label>
                                            </div>
                                            @php($top_offer_near_me_stores_sort_by_unavailable = \App\Models\PriorityList::where('name', 'top_offer_near_me_stores_sort_by_unavailable')->where('type', 'unavailable')->first())
                                            @php($top_offer_near_me_stores_sort_by_unavailable = $top_offer_near_me_stores_sort_by_unavailable ? $top_offer_near_me_stores_sort_by_unavailable->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_unavailable" value="last"
                                                        {{ $top_offer_near_me_stores_sort_by_unavailable == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show currently closed stores in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_unavailable" value="remove"
                                                        {{ $top_offer_near_me_stores_sort_by_unavailable == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove currently closed stores from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_unavailable" value="none"
                                                        {{ $top_offer_near_me_stores_sort_by_unavailable == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                            @php($top_offer_near_me_stores_sort_by_temp_closed = \App\Models\PriorityList::where('name', 'top_offer_near_me_stores_sort_by_temp_closed')->where('type', 'temp_closed')->first())
                                            @php($top_offer_near_me_stores_sort_by_temp_closed = $top_offer_near_me_stores_sort_by_temp_closed ? $top_offer_near_me_stores_sort_by_temp_closed->value : '')
                                            <div class="border rounded p-3 d-flex flex-column gap-2 fs-14 mb-10px">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_temp_closed" value="last"
                                                        {{ $top_offer_near_me_stores_sort_by_temp_closed == 'last' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Show temporarily off stores in the last') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_temp_closed" value="remove"
                                                        {{ $top_offer_near_me_stores_sort_by_temp_closed == 'remove' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('Remove temporarily off stores from the list') }}
                                                        </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio"
                                                            name="top_offer_near_me_stores_sort_by_temp_closed" value="none"
                                                        {{ $top_offer_near_me_stores_sort_by_temp_closed == 'none' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                            {{ translate('None') }}
                                                        </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>



                    <div class="btn--container justify-content-end position-sticky bottom-0 p-3 bg-white border-top">
                        <button id="reset_btn" type="reset"
                            class="btn btn--reset">{{ translate('Reset') }}</button>
                        <button type="submit"
                            class="btn btn--primary">{{ translate('Save Information') }}</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
@endsection

@push('script_2')
    <script>
        $(".collapse-div-toggler").on('change', function() {
            $(this).closest('.sorting-card').find('.inner-collapse-div').slideToggle();
            $(this).closest('.sorting-card').siblings().find('.inner-collapse-div').slideUp();
            $(this).closest('.sorting-card').siblings().find('.toggle-switch-input').prop('checked', false);
        });

        $(window).on('load', function() {
            $('.collapse-div-toggler').each(function() {
                if ($(this).prop('checked') == true) {
                    $(this).closest('.sorting-card').find('.inner-collapse-div').show();
                }
            });
        })

        $('#reset_btn').click(function() {
            $('.collapse-div-toggler').each(function() {
                if ($(this).prop('checked') == true) {
                    $(this).closest('.sorting-card').find('.inner-collapse-div').show();
                } else {
                    $(this).closest('.sorting-card').siblings().find('.inner-collapse-div').slideUp();
                    $(this).closest('.sorting-card').siblings().find('.toggle-switch-input').prop('checked',
                        false);
                }
            });
        })
    </script>
@endpush
