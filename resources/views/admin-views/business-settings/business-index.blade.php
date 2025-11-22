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

    <div class="card mb-3">
        <div class="card-body">
            <div
                class="maintenance-mode-toggle-bar d-flex flex-wrap justify-content-between border border-info rounded align-items-center p-2">
                @php($config = \App\CentralLogics\Helpers::get_business_settings('maintenance_mode'))
                <h5 class="text-capitalize m-0 text--primary">
                    <i class="tio-settings-outlined"></i>
                    {{ translate('messages.maintenance_mode') }}
                </h5>
                <label class="toggle-switch toggle-switch-sm">
                    <input type="checkbox" class="status toggle-switch-input maintenance-mode" {{ isset($config) && $config ? 'checked' : '' }}>
                    <span class="toggle-switch-label text mb-0">
                        <span class="toggle-switch-indicator"></span>
                    </span>
                </label>
            </div>
            <div class="mt-2">
                {{ translate('messages.By_turning_the_‘Maintenance_Mode’_ON,_all_your_apps_and_customer_website_will_be_disabled_temporarily._Only_the_Admin_Panel,_Admin_Landing_Page_&_Store_Panel_will_be_functional.') }}
            </div>
        </div>
    </div>
    <form action="{{ route('admin.business-settings.update-setup') }}" method="post" enctype="multipart/form-data">
        @csrf
        @php($name = \App\Models\BusinessSetting::where('key', 'business_name')->first())

        <div class="row g-3">
            <div class="col-lg-12">
                <h4 class="card-title mb-3 mt-1">
                    <span class="card-header-icon mr-2"><i class="tio-user"></i></span>
                    <span>{{ translate('Company Information') }}</span>
                </h4>
                <div class="card">
                    <div class="card-body">
                        <div class="row g-3">
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                <div class="form-group mb-0">
                                    <label class="form-label"
                                        for="store_name">{{ translate('messages.company_name') }}</label>
                                    <input id="store_name" type="text" name="store_name"
                                        value="{{ $name->value ?? '' }}" class="form-control"
                                        placeholder="{{ translate('messages.new_company') }}" required>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($email = \App\Models\BusinessSetting::where('key', 'email_address')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label" for="email">{{ translate('messages.email') }}</label>
                                    <input id="email" type="email" value="{{ $email->value ?? '' }}" name="email"
                                        class="form-control"
                                        placeholder="{{ translate('messages.Ex_:_ex@example.com') }}" required>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($phone = \App\Models\BusinessSetting::where('key', 'phone')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label" for="phone">{{ translate('messages.phone') }}</label>
                                    <input type="tel" value="{{ $phone->value ?? '' }}" id="phone" name="phone"
                                        class="form-control" placeholder="{{ translate('messages.Ex: +3264124565') }}"
                                        required>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                <div class="form-group mb-0">
                                    <label class="form-label text-capitalize"
                                        for="country">{{ translate('messages.country') }}</label>
                                    <select id="country" name="country" class="form-control  js-select2-custom">
                                        <option value="AF">Afghanistan</option>
                                        <option value="AX">Åland Islands</option>
                                        <option value="AL">Albania</option>
                                        <option value="DZ">Algeria</option>
                                        <option value="AS">American Samoa</option>
                                        <option value="AD">Andorra</option>
                                        <option value="AO">Angola</option>
                                        <option value="AI">Anguilla</option>
                                        <option value="AQ">Antarctica</option>
                                        <option value="AG">Antigua and Barbuda</option>
                                        <option value="AR">Argentina</option>
                                        <option value="AM">Armenia</option>
                                        <option value="AW">Aruba</option>
                                        <option value="AU">Australia</option>
                                        <option value="AT">Austria</option>
                                        <option value="AZ">Azerbaijan</option>
                                        <option value="BS">Bahamas</option>
                                        <option value="BH">Bahrain</option>
                                        <option value="BD">Bangladesh</option>
                                        <option value="BB">Barbados</option>
                                        <option value="BY">Belarus</option>
                                        <option value="BE">Belgium</option>
                                        <option value="BZ">Belize</option>
                                        <option value="BJ">Benin</option>
                                        <option value="BM">Bermuda</option>
                                        <option value="BT">Bhutan</option>
                                        <option value="BO">Bolivia, Plurinational State of</option>
                                        <option value="BQ">Bonaire, Sint Eustatius and Saba</option>
                                        <option value="BA">Bosnia and Herzegovina</option>
                                        <option value="BW">Botswana</option>
                                        <option value="BV">Bouvet Island</option>
                                        <option value="BR">Brazil</option>
                                        <option value="IO">British Indian Ocean Territory</option>
                                        <option value="BN">Brunei Darussalam</option>
                                        <option value="BG">Bulgaria</option>
                                        <option value="BF">Burkina Faso</option>
                                        <option value="BI">Burundi</option>
                                        <option value="KH">Cambodia</option>
                                        <option value="CM">Cameroon</option>
                                        <option value="CA">Canada</option>
                                        <option value="CV">Cape Verde</option>
                                        <option value="KY">Cayman Islands</option>
                                        <option value="CF">Central African Republic</option>
                                        <option value="TD">Chad</option>
                                        <option value="CL">Chile</option>
                                        <option value="CN">China</option>
                                        <option value="CX">Christmas Island</option>
                                        <option value="CC">Cocos (Keeling) Islands</option>
                                        <option value="CO">Colombia</option>
                                        <option value="KM">Comoros</option>
                                        <option value="CG">Congo</option>
                                        <option value="CD">Congo, the Democratic Republic of the</option>
                                        <option value="CK">Cook Islands</option>
                                        <option value="CR">Costa Rica</option>
                                        <option value="CI">Côte d'Ivoire</option>
                                        <option value="HR">Croatia</option>
                                        <option value="CU">Cuba</option>
                                        <option value="CW">Curaçao</option>
                                        <option value="CY">Cyprus</option>
                                        <option value="CZ">Czech Republic</option>
                                        <option value="DK">Denmark</option>
                                        <option value="DJ">Djibouti</option>
                                        <option value="DM">Dominica</option>
                                        <option value="DO">Dominican Republic</option>
                                        <option value="EC">Ecuador</option>
                                        <option value="EG">Egypt</option>
                                        <option value="SV">El Salvador</option>
                                        <option value="GQ">Equatorial Guinea</option>
                                        <option value="ER">Eritrea</option>
                                        <option value="EE">Estonia</option>
                                        <option value="ET">Ethiopia</option>
                                        <option value="FK">Falkland Islands (Malvinas)</option>
                                        <option value="FO">Faroe Islands</option>
                                        <option value="FJ">Fiji</option>
                                        <option value="FI">Finland</option>
                                        <option value="FR">France</option>
                                        <option value="GF">French Guiana</option>
                                        <option value="PF">French Polynesia</option>
                                        <option value="TF">French Southern Territories</option>
                                        <option value="GA">Gabon</option>
                                        <option value="GM">Gambia</option>
                                        <option value="GE">Georgia</option>
                                        <option value="DE">Germany</option>
                                        <option value="GH">Ghana</option>
                                        <option value="GI">Gibraltar</option>
                                        <option value="GR">Greece</option>
                                        <option value="GL">Greenland</option>
                                        <option value="GD">Grenada</option>
                                        <option value="GP">Guadeloupe</option>
                                        <option value="GU">Guam</option>
                                        <option value="GT">Guatemala</option>
                                        <option value="GG">Guernsey</option>
                                        <option value="GN">Guinea</option>
                                        <option value="GW">Guinea-Bissau</option>
                                        <option value="GY">Guyana</option>
                                        <option value="HT">Haiti</option>
                                        <option value="HM">Heard Island and McDonald Islands</option>
                                        <option value="VA">Holy See (Vatican City State)</option>
                                        <option value="HN">Honduras</option>
                                        <option value="HK">Hong Kong</option>
                                        <option value="HU">Hungary</option>
                                        <option value="IS">Iceland</option>
                                        <option value="IN">India</option>
                                        <option value="ID">Indonesia</option>
                                        <option value="IR">Iran, Islamic Republic of</option>
                                        <option value="IQ">Iraq</option>
                                        <option value="IE">Ireland</option>
                                        <option value="IM">Isle of Man</option>
                                        <option value="IL">Israel</option>
                                        <option value="IT">Italy</option>
                                        <option value="JM">Jamaica</option>
                                        <option value="JP">Japan</option>
                                        <option value="JE">Jersey</option>
                                        <option value="JO">Jordan</option>
                                        <option value="KZ">Kazakhstan</option>
                                        <option value="KE">Kenya</option>
                                        <option value="KI">Kiribati</option>
                                        <option value="KP">Korea, Democratic People's Republic of</option>
                                        <option value="KR">Korea, Republic of</option>
                                        <option value="KW">Kuwait</option>
                                        <option value="KG">Kyrgyzstan</option>
                                        <option value="LA">Lao People's Democratic Republic</option>
                                        <option value="LV">Latvia</option>
                                        <option value="LB">Lebanon</option>
                                        <option value="LS">Lesotho</option>
                                        <option value="LR">Liberia</option>
                                        <option value="LY">Libya</option>
                                        <option value="LI">Liechtenstein</option>
                                        <option value="LT">Lithuania</option>
                                        <option value="LU">Luxembourg</option>
                                        <option value="MO">Macao</option>
                                        <option value="MK">Macedonia, the former Yugoslav Republic of</option>
                                        <option value="MG">Madagascar</option>
                                        <option value="MW">Malawi</option>
                                        <option value="MY">Malaysia</option>
                                        <option value="MV">Maldives</option>
                                        <option value="ML">Mali</option>
                                        <option value="MT">Malta</option>
                                        <option value="MH">Marshall Islands</option>
                                        <option value="MQ">Martinique</option>
                                        <option value="MR">Mauritania</option>
                                        <option value="MU">Mauritius</option>
                                        <option value="YT">Mayotte</option>
                                        <option value="MX">Mexico</option>
                                        <option value="FM">Micronesia, Federated States of</option>
                                        <option value="MD">Moldova, Republic of</option>
                                        <option value="MC">Monaco</option>
                                        <option value="MN">Mongolia</option>
                                        <option value="ME">Montenegro</option>
                                        <option value="MS">Montserrat</option>
                                        <option value="MA">Morocco</option>
                                        <option value="MZ">Mozambique</option>
                                        <option value="MM">Myanmar</option>
                                        <option value="NA">Namibia</option>
                                        <option value="NR">Nauru</option>
                                        <option value="NP">Nepal</option>
                                        <option value="NL">Netherlands</option>
                                        <option value="NC">New Caledonia</option>
                                        <option value="NZ">New Zealand</option>
                                        <option value="NI">Nicaragua</option>
                                        <option value="NE">Niger</option>
                                        <option value="NG">Nigeria</option>
                                        <option value="NU">Niue</option>
                                        <option value="NF">Norfolk Island</option>
                                        <option value="MP">Northern Mariana Islands</option>
                                        <option value="NO">Norway</option>
                                        <option value="OM">Oman</option>
                                        <option value="PK">Pakistan</option>
                                        <option value="PW">Palau</option>
                                        <option value="PS">Palestinian Territory, Occupied</option>
                                        <option value="PA">Panama</option>
                                        <option value="PG">Papua New Guinea</option>
                                        <option value="PY">Paraguay</option>
                                        <option value="PE">Peru</option>
                                        <option value="PH">Philippines</option>
                                        <option value="PN">Pitcairn</option>
                                        <option value="PL">Poland</option>
                                        <option value="PT">Portugal</option>
                                        <option value="PR">Puerto Rico</option>
                                        <option value="QA">Qatar</option>
                                        <option value="RE">Réunion</option>
                                        <option value="RO">Romania</option>
                                        <option value="RU">Russian Federation</option>
                                        <option value="RW">Rwanda</option>
                                        <option value="BL">Saint Barthélemy</option>
                                        <option value="SH">Saint Helena, Ascension and Tristan da Cunha</option>
                                        <option value="KN">Saint Kitts and Nevis</option>
                                        <option value="LC">Saint Lucia</option>
                                        <option value="MF">Saint Martin (French part)</option>
                                        <option value="PM">Saint Pierre and Miquelon</option>
                                        <option value="VC">Saint Vincent and the Grenadines</option>
                                        <option value="WS">Samoa</option>
                                        <option value="SM">San Marino</option>
                                        <option value="ST">Sao Tome and Principe</option>
                                        <option value="SA">Saudi Arabia</option>
                                        <option value="SN">Senegal</option>
                                        <option value="RS">Serbia</option>
                                        <option value="SC">Seychelles</option>
                                        <option value="SL">Sierra Leone</option>
                                        <option value="SG">Singapore</option>
                                        <option value="SX">Sint Maarten (Dutch part)</option>
                                        <option value="SK">Slovakia</option>
                                        <option value="SI">Slovenia</option>
                                        <option value="SB">Solomon Islands</option>
                                        <option value="SO">Somalia</option>
                                        <option value="ZA">South Africa</option>
                                        <option value="GS">South Georgia and the South Sandwich Islands</option>
                                        <option value="SS">South Sudan</option>
                                        <option value="ES">Spain</option>
                                        <option value="LK">Sri Lanka</option>
                                        <option value="SD">Sudan</option>
                                        <option value="SR">Suriname</option>
                                        <option value="SJ">Svalbard and Jan Mayen</option>
                                        <option value="SZ">Swaziland</option>
                                        <option value="SE">Sweden</option>
                                        <option value="CH">Switzerland</option>
                                        <option value="SY">Syrian Arab Republic</option>
                                        <option value="TW">Taiwan, Province of China</option>
                                        <option value="TJ">Tajikistan</option>
                                        <option value="TZ">Tanzania, United Republic of</option>
                                        <option value="TH">Thailand</option>
                                        <option value="TL">Timor-Leste</option>
                                        <option value="TG">Togo</option>
                                        <option value="TK">Tokelau</option>
                                        <option value="TO">Tonga</option>
                                        <option value="TT">Trinidad and Tobago</option>
                                        <option value="TN">Tunisia</option>
                                        <option value="TR">Turkey</option>
                                        <option value="TM">Turkmenistan</option>
                                        <option value="TC">Turks and Caicos Islands</option>
                                        <option value="TV">Tuvalu</option>
                                        <option value="UG">Uganda</option>
                                        <option value="UA">Ukraine</option>
                                        <option value="AE">United Arab Emirates</option>
                                        <option value="GB">United Kingdom</option>
                                        <option value="US">United States</option>
                                        <option value="UM">United States Minor Outlying Islands</option>
                                        <option value="UY">Uruguay</option>
                                        <option value="UZ">Uzbekistan</option>
                                        <option value="VU">Vanuatu</option>
                                        <option value="VE">Venezuela, Bolivarian Republic of</option>
                                        <option value="VN">Viet Nam</option>
                                        <option value="VG">Virgin Islands, British</option>
                                        <option value="VI">Virgin Islands, U.S.</option>
                                        <option value="WF">Wallis and Futuna</option>
                                        <option value="EH">Western Sahara</option>
                                        <option value="YE">Yemen</option>
                                        <option value="ZM">Zambia</option>
                                        <option value="ZW">Zimbabwe</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="row g-3 mt-2">
                            <div class="col-md-6">
                                <div class="row g-3">
                                    <div class="col-sm-12">
                                        @php($address = \App\Models\BusinessSetting::where('key', 'address')->first())
                                        <div class="form-group mb-0">
                                            <label class="form-label"
                                                for="address">{{ translate('messages.address') }}</label>
                                            <textarea type="text" id="address" name="address"
                                                class="form-control h--90px"
                                                placeholder="{{ translate('messages.Ex: address') }}" rows="1"
                                                required>{{ $address->value ?? '' }}</textarea>
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        @php($default_location = \App\Models\BusinessSetting::where('key', 'default_location')->first())
                                        @php($default_location = $default_location?->value ? json_decode($default_location->value, true) : 0)
                                        <div class="form-group mb-0">
                                            <label class="form-label text-capitalize"
                                                for="latitude">{{ translate('messages.latitude') }}<span
                                                    class="form-label-secondary" data-toggle="tooltip"
                                                    data-placement="right"
                                                    data-original-title="{{ translate('messages.click_on_the_map_select_your_defaul_location') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.click_on_the_map_select_your_defaul_location') }}"></span></label>
                                            <input type="text" id="latitude" name="latitude" class="form-control"
                                                placeholder="{{ translate('messages.Ex:') }} -94.22213"
                                                value="{{ $default_location ? $default_location['lat'] : 0 }}" required
                                                readonly>
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        <div class="form-group mb-0">
                                            <label class="form-label text-capitalize"
                                                for="longitude">{{ translate('messages.longitude') }}<span
                                                    class="form-label-secondary" data-toggle="tooltip"
                                                    data-placement="right"
                                                    data-original-title="{{ translate('messages.click_on_the_map_select_your_defaul_location') }}"><img
                                                        src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                        alt="{{ translate('messages.click_on_the_map_select_your_defaul_location') }}"></span></label>
                                            <input type="text" name="longitude" class="form-control"
                                                placeholder="{{ translate('messages.Ex:') }} 103.344322" id="longitude"
                                                value="{{ $default_location ? $default_location['lng'] : 0 }}" required
                                                readonly>
                                        </div>
                                    </div>
                                </div>
                                <div class="d-flex __gap-12px mt-4">
                                    <div class="__custom-upload-img mr-lg-5">
                                        @php($logo = \App\Models\BusinessSetting::where('key', 'logo')->first())
                                        <label class="form-label">
                                            {{ translate('logo') }} <span class="text--primary">( {{ translate('3:1') }}
                                                )</span>
                                        </label>
                                        <label class="text-center position-relative">
                                            <img class="img--vertical onerror-image image--border" id="viewer"
                                                data-onerror-image="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                src="{{\App\CentralLogics\Helpers::get_full_url('business', $logo?->value ?? '', $logo?->storage[0]?->value ?? 'public', 'upload_image')}}"
                                                alt="logo image" />
                                            <div class="icon-file-group">
                                                <div class="icon-file">
                                                    <input type="file" name="logo" id="customFileEg1"
                                                        class="custom-file-input"
                                                        accept=".webp, .jpg, .png, .jpeg, .gif, .bmp, .tif, .tiff|image/*">
                                                    <i class="tio-edit"></i>
                                                </div>
                                            </div>
                                        </label>
                                    </div>

                                    <div class="__custom-upload-img">
                                        @php($icon = \App\Models\BusinessSetting::where('key', 'icon')->first())
                                        <label class="form-label">
                                            {{ translate('Favicon') }} <span class="text--primary">(
                                                {{ translate('1:1') }} )</span>
                                        </label>
                                        <label class="text-center position-relative">
                                            <img class="img--133 onerror-image image--border" id="iconViewer"
                                                data-onerror-image="{{ asset('public/assets/admin/img/upload-img.png') }}"
                                                src="{{\App\CentralLogics\Helpers::get_full_url('business', $icon?->value ?? '', $icon?->storage[0]?->value ?? 'public', 'upload_image')}}"
                                                alt="Fav icon" />
                                            <div class="icon-file-group">
                                                <div class="icon-file">
                                                    <input type="file" name="icon" id="favIconUpload"
                                                        class="custom-file-input"
                                                        accept=".webp, .jpg, .png, .jpeg, .gif, .bmp, .tif, .tiff|image/*">
                                                    <i class="tio-edit"></i>
                                                </div>

                                            </div>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div>
                                    <label class="form-label">&nbsp;</label>
                                    <div class="p-3 rounded border border-success">
                                        <div class="d-flex mb-3 fs-12">
                                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none"
                                                xmlns="http://www.w3.org/2000/svg">
                                                <path
                                                    d="M12 2C6.48 2 2 6.48 2 12C2 17.52 6.48 22 12 22C17.52 22 22 17.52 22 12C22 6.48 17.52 2 12 2ZM13 17H11V11H13V17ZM13 9H11V7H13V9Z"
                                                    fill="#039D55" />
                                            </svg>
                                            <div class="w-0 flex-grow pl-2">
                                                {{ translate('clicking_on_the_map_will_set_Latitude_and_Longitude_automatically') }}
                                            </div>
                                        </div>
                                        <input id="pac-input" class="controls rounded" data-toggle="tooltip"
                                            data-placement="right"
                                            data-original-title="{{ translate('messages.search_your_location_here') }}"
                                            type="text" placeholder="{{ translate('messages.search_here') }}" />
                                        <div id="location_map_canvas" class="overflow-hidden rounded height-285px">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-12">
                <h4 class="card-title mb-3">
                    <span class="card-header-icon mr-2"><i class="tio-settings-outlined"></i></span>
                    <span>{{ translate('General Settings') }}</span>
                </h4>
                <div class="card">
                    <div class="card-body">
                        <div class="row g-3">

                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($tz = \App\Models\BusinessSetting::where('key', 'timezone')->first())
                                @php($tz = $tz ? $tz->value : 0)
                                <div class="form-group mb-0">
                                    <label for="timezone"
                                        class="form-label text-capitalize">{{ translate('messages.time_zone') }}</label>
                                    <select id="timezone" name="timezone" class="form-control js-select2-custom">
                                        <option value="UTC" {{ $tz ? ($tz == '' ? 'selected' : '') : '' }}>UTC </option>
                                        <option value="Etc/GMT+12" {{ $tz ? ($tz == 'Etc/GMT+12' ? 'selected' : '') : '' }}>(GMT-12:00)International Date Line West</option>
                                        <option value="Pacific/Midway" {{ $tz ? ($tz == 'Pacific/Midway' ? 'selected' : '') : '' }}>
                                            (GMT-11:00) Midway Island, Samoa</option>
                                        <option value="Pacific/Honolulu" {{ $tz ? ($tz == 'Pacific/Honolulu' ? 'selected' : '') : '' }}>
                                            (GMT-10:00) Hawaii</option>
                                        <option value="US/Alaska" {{ $tz ? ($tz == 'US/Alaska' ? 'selected' : '') : '' }}>
                                            (GMT-09:00)Alaska</option>
                                        <option value="America/Los_Angeles" {{ $tz ? ($tz == 'America/Los_Angeles' ? 'selected' : '') : '' }}>
                                            (GMT-08:00) Pacific Time
                                            (US & Canada)</option>
                                        <option value="America/Tijuana" {{ $tz ? ($tz == 'America/Tijuana' ? 'selected' : '') : '' }}>
                                            (GMT-08:00) Tijuana, Baja California</option>
                                        <option value="US/Arizona" {{ $tz ? ($tz == 'US/Arizona' ? 'selected' : '') : '' }}>(GMT-07:00)Arizona</option>
                                        <option value="America/Chihuahua" {{ $tz ? ($tz == 'America/Chihuahua' ? 'selected' : '') : '' }}>(GMT-07:00)Chihuahua, La
                                            Paz, Mazatlan</option>
                                        <option value="US/Mountain" {{ $tz ? ($tz == 'US/Mountain' ? 'selected' : '') : '' }}>(GMT-07:00)Mountain Time (US & Canada)</option>
                                        <option value="America/Managua" {{ $tz ? ($tz == 'America/Managua' ? 'selected' : '') : '' }}>
                                            (GMT-06:00) Central America</option>
                                        <option value="US/Central" {{ $tz ? ($tz == 'US/Central' ? 'selected' : '') : '' }}>(GMT-06:00)Central Time (US & Canada)</option>
                                        <option value="America/Mexico_City" {{ $tz ? ($tz == 'America/Mexico_City' ? 'selected' : '') : '' }}>
                                            (GMT-06:00) Guadalajara,
                                            Mexico City, Monterrey</option>
                                        <option value="Canada/Saskatchewan" {{ $tz ? ($tz == 'Canada/Saskatchewan' ? 'selected' : '') : '' }}>
                                            (GMT-06:00) Saskatchewan </option>
                                        <option value="America/Bogota" {{ $tz ? ($tz == 'America/Bogota' ? 'selected' : '') : '' }}>
                                            (GMT-05:00) Bogota, Lima, Quito, Rio Branco</option>
                                        <option value="US/Eastern" {{ $tz ? ($tz == 'US/Eastern' ? 'selected' : '') : '' }}>(GMT-05:00)Eastern Time (US & Canada)</option>
                                        <option value="US/East-Indiana" {{ $tz ? ($tz == 'US/East-Indiana' ? 'selected' : '') : '' }}>
                                            (GMT-05:00) Indiana (East)</option>
                                        <option value="Canada/Atlantic" {{ $tz ? ($tz == 'Canada/Atlantic' ? 'selected' : '') : '' }}>
                                            (GMT-04:00) Atlantic Time (Canada)</option>
                                        <option value="America/Caracas" {{ $tz ? ($tz == 'America/Caracas' ? 'selected' : '') : '' }}>
                                            (GMT-04:00) Caracas, La Paz</option>
                                        <option value="America/Manaus" {{ $tz ? ($tz == 'America/Manaus' ? 'selected' : '') : '' }}>
                                            (GMT-04:00) Manaus</option>
                                        <option value="America/Santiago" {{ $tz ? ($tz == 'America/Santiago' ? 'selected' : '') : '' }}>
                                            (GMT-04:00) Santiago</option>
                                        <option value="Canada/Newfoundland" {{ $tz ? ($tz == 'Canada/Newfoundland' ? 'selected' : '') : '' }}>
                                            (GMT-03:30) Newfoundland </option>
                                        <option value="America/Sao_Paulo" {{ $tz ? ($tz == 'America/Sao_Paulo' ? 'selected' : '') : '' }}>(GMT-03:00)Brasilia</option>
                                        <option value="America/Argentina/Buenos_Aires" {{ $tz ? ($tz == 'America/Argentina/Buenos_Aires' ? 'selected' : '') : '' }}>
                                            (GMT-03:00)Buenos Aires, Georgetown</option>
                                        <option value="America/Godthab" {{ $tz ? ($tz == 'America/Godthab' ? 'selected' : '') : '' }}>
                                            (GMT-03:00) Greenland</option>
                                        <option value="America/Montevideo" {{ $tz ? ($tz == 'America/Montevideo' ? 'selected' : '') : '' }}>
                                            (GMT-03:00) Montevideo </option>
                                        <option value="America/Noronha" {{ $tz ? ($tz == 'America/Noronha' ? 'selected' : '') : '' }}>
                                            (GMT-02:00) Mid-Atlantic</option>
                                        <option value="Atlantic/Cape_Verde" {{ $tz ? ($tz == 'Atlantic/Cape_Verde' ? 'selected' : '') : '' }}>
                                            (GMT-01:00) Cape Verde Is. </option>
                                        <option value="Atlantic/Azores" {{ $tz ? ($tz == 'Atlantic/Azores' ? 'selected' : '') : '' }}>
                                            (GMT-01:00) Azores</option>
                                        <option value="Africa/Casablanca" {{ $tz ? ($tz == 'Africa/Casablanca' ? 'selected' : '') : '' }}>(GMT+00:00)Casablanca,
                                            Monrovia, Reykjavik</option>
                                        <option value="Etc/Greenwich" {{ $tz ? ($tz == 'Etc/Greenwich' ? 'selected' : '') : '' }}>
                                            (GMT+00:00) Greenwich Mean Time : Dublin, Edinburgh, Lisbon, London</option>
                                        <option value="Europe/Amsterdam" {{ $tz ? ($tz == 'Europe/Amsterdam' ? 'selected' : '') : '' }}>
                                            (GMT+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna</option>
                                        <option value="Europe/Belgrade" {{ $tz ? ($tz == 'Europe/Belgrade' ? 'selected' : '') : '' }}>
                                            (GMT+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague</option>
                                        <option value="Europe/Brussels" {{ $tz ? ($tz == 'Europe/Brussels' ? 'selected' : '') : '' }}>
                                            (GMT+01:00) Brussels, Copenhagen, Madrid, Paris</option>
                                        <option value="Europe/Sarajevo" {{ $tz ? ($tz == 'Europe/Sarajevo' ? 'selected' : '') : '' }}>
                                            (GMT+01:00) Sarajevo, Skopje, Warsaw, Zagreb</option>
                                        <option value="Africa/Lagos" {{ $tz ? ($tz == 'Africa/Lagos' ? 'selected' : '') : '' }}>
                                            (GMT+01:00) West Central Africa</option>
                                        <option value="Asia/Amman" {{ $tz ? ($tz == 'Asia/Amman' ? 'selected' : '') : '' }}>(GMT+02:00)Amman</option>
                                        <option value="Europe/Athens" {{ $tz ? ($tz == 'Europe/Athens' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Athens, Bucharest, Istanbul</option>
                                        <option value="Asia/Beirut" {{ $tz ? ($tz == 'Asia/Beirut' ? 'selected' : '') : '' }}>(GMT+02:00)Beirut</option>
                                        <option value="Africa/Cairo" {{ $tz ? ($tz == 'Africa/Cairo' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Cairo</option>
                                        <option value="Africa/Harare" {{ $tz ? ($tz == 'Africa/Harare' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Harare, Pretoria</option>
                                        <option value="Europe/Helsinki" {{ $tz ? ($tz == 'Europe/Helsinki' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius</option>
                                        <option value="Asia/Jerusalem" {{ $tz ? ($tz == 'Asia/Jerusalem' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Jerusalem</option>
                                        <option value="Europe/Minsk" {{ $tz ? ($tz == 'Europe/Minsk' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Minsk</option>
                                        <option value="Africa/Windhoek" {{ $tz ? ($tz == 'Africa/Windhoek' ? 'selected' : '') : '' }}>
                                            (GMT+02:00) Windhoek</option>
                                        <option value="Asia/Kuwait" {{ $tz ? ($tz == 'Asia/Kuwait' ? 'selected' : '') : '' }}>(GMT+03:00)Kuwait, Riyadh Baghdad</option>
                                        <option value="Europe/Moscow" {{ $tz ? ($tz == 'Europe/Moscow' ? 'selected' : '') : '' }}>
                                            (GMT+03:00) Moscow, St. Petersburg, Volgograd</option>
                                        <option value="Africa/Nairobi" {{ $tz ? ($tz == 'Africa/Nairobi' ? 'selected' : '') : '' }}>
                                            (GMT+03:00) Nairobi</option>
                                        <option value="Asia/Tbilisi" {{ $tz ? ($tz == 'Asia/Tbilisi' ? 'selected' : '') : '' }}>
                                            (GMT+03:00) Tbilisi</option>
                                        <option value="Asia/Tehran" {{ $tz ? ($tz == 'Asia/Tehran' ? 'selected' : '') : '' }}>(GMT+03:30)Tehran</option>
                                        <option value="Asia/Muscat" {{ $tz ? ($tz == 'Asia/Muscat' ? 'selected' : '') : '' }}>(GMT+04:00)Abu Dhabi,Muscat</option>
                                        <option value="Asia/Baku" {{ $tz ? ($tz == 'Asia/Baku' ? 'selected' : '') : '' }}>
                                            (GMT+04:00)Baku</option>
                                        <option value="Asia/Yerevan" {{ $tz ? ($tz == 'Asia/Yerevan' ? 'selected' : '') : '' }}>
                                            (GMT+04:00) Yerevan</option>
                                        <option value="Asia/Kabul" {{ $tz ? ($tz == 'Asia/Kabul' ? 'selected' : '') : '' }}>(GMT+04:30)Kabul</option>
                                        <option value="Asia/Yekaterinburg" {{ $tz ? ($tz == 'Asia/Yekaterinburg' ? 'selected' : '') : '' }}>
                                            (GMT+05:00) Yekaterinburg </option>
                                        <option value="Asia/Karachi" {{ $tz ? ($tz == 'Asia/Karachi' ? 'selected' : '') : '' }}>
                                            (GMT+05:00) Islamabad, Karachi, Tashkent</option>
                                        <option value="Asia/Calcutta" {{ $tz ? ($tz == 'Asia/Calcutta' ? 'selected' : '') : '' }}>
                                            (GMT+05:30) Chennai, Kolkata, Mumbai, New Delhi</option>
                                        <!-- <option value="Asia/Calcutta"  {{ $tz ? ($tz == 'Asia/Calcutta' ? 'selected' : '') : '' }}>(GMT+05:30) Sri Jayawardenapura</option> -->
                                        <option value="Asia/Kathmandu" {{ $tz ? ($tz == 'Asia/Kathmandu' ? 'selected' : '') : '' }}>
                                            (GMT+05:45) Kathmandu</option>
                                        <option value="Asia/Almaty" {{ $tz ? ($tz == 'Asia/Almaty' ? 'selected' : '') : '' }}>(GMT+06:00)Almaty, Novosibirsk</option>
                                        <option value="Asia/Dhaka" {{ $tz ? ($tz == 'Asia/Dhaka' ? 'selected' : '') : '' }}>(GMT+06:00)Astana, Dhaka</option>
                                        <option value="Asia/Rangoon" {{ $tz ? ($tz == 'Asia/Rangoon' ? 'selected' : '') : '' }}>
                                            (GMT+06:30) Yangon (Rangoon)</option>
                                        <option value="Asia/Bangkok" {{ $tz ? ($tz == 'Asia/Bangkok' ? 'selected' : '') : '' }}>
                                            (GMT+07:00) Bangkok, Hanoi, Jakarta</option>
                                        <option value="Asia/Krasnoyarsk" {{ $tz ? ($tz == 'Asia/Krasnoyarsk' ? 'selected' : '') : '' }}>
                                            (GMT+07:00) Krasnoyarsk</option>
                                        <option value="Asia/Hong_Kong" {{ $tz ? ($tz == 'Asia/Hong_Kong' ? 'selected' : '') : '' }}>
                                            (GMT+08:00) Beijing, Chongqing, Hong Kong, Urumqi</option>
                                        <option value="Asia/Kuala_Lumpur" {{ $tz ? ($tz == 'Asia/Kuala_Lumpur' ? 'selected' : '') : '' }}>
                                            (GMT+08:00) Kuala Lumpur,
                                            Singapore</option>
                                        <option value="Asia/Irkutsk" {{ $tz ? ($tz == 'Asia/Irkutsk' ? 'selected' : '') : '' }}>
                                            (GMT+08:00) Irkutsk, Ulaan Bataar</option>
                                        <option value="Australia/Perth" {{ $tz ? ($tz == 'Australia/Perth' ? 'selected' : '') : '' }}>
                                            (GMT+08:00) Perth</option>
                                        <option value="Asia/Taipei" {{ $tz ? ($tz == 'Asia/Taipei' ? 'selected' : '') : '' }}>(GMT+08:00)Taipei</option>
                                        <option value="Asia/Tokyo" {{ $tz ? ($tz == 'Asia/Tokyo' ? 'selected' : '') : '' }}>(GMT+09:00)Osaka, Sapporo, Tokyo</option>
                                        <option value="Asia/Seoul" {{ $tz ? ($tz == 'Asia/Seoul' ? 'selected' : '') : '' }}>(GMT+09:00)Seoul</option>
                                        <option value="Asia/Yakutsk" {{ $tz ? ($tz == 'Asia/Yakutsk' ? 'selected' : '') : '' }}>
                                            (GMT+09:00) Yakutsk</option>
                                        <option value="Australia/Adelaide" {{ $tz ? ($tz == 'Australia/Adelaide' ? 'selected' : '') : '' }}>
                                            (GMT+09:30) Adelaide </option>
                                        <option value="Australia/Darwin" {{ $tz ? ($tz == 'Australia/Darwin' ? 'selected' : '') : '' }}>
                                            (GMT+09:30) Darwin</option>
                                        <option value="Australia/Brisbane" {{ $tz ? ($tz == 'Australia/Brisbane' ? 'selected' : '') : '' }}>
                                            (GMT+10:00) Brisbane </option>
                                        <option value="Australia/Canberra" {{ $tz ? ($tz == 'Australia/Canberra' ? 'selected' : '') : '' }}>
                                            (GMT+10:00) Canberra,
                                            Melbourne, Sydney</option>
                                        <option value="Australia/Hobart" {{ $tz ? ($tz == 'Australia/Hobart' ? 'selected' : '') : '' }}>
                                            (GMT+10:00) Hobart</option>
                                        <option value="Pacific/Guam" {{ $tz ? ($tz == 'Pacific/Guam' ? 'selected' : '') : '' }}>
                                            (GMT+10:00) Guam, Port Moresby</option>
                                        <option value="Asia/Vladivostok" {{ $tz ? ($tz == 'Asia/Vladivostok' ? 'selected' : '') : '' }}>
                                            (GMT+10:00) Vladivostok</option>
                                        <option value="Asia/Magadan" {{ $tz ? ($tz == 'Asia/Magadan' ? 'selected' : '') : '' }}>
                                            (GMT+11:00) Magadan, Solomon Is., New Caledonia</option>
                                        <option value="Pacific/Auckland" {{ $tz ? ($tz == 'Pacific/Auckland' ? 'selected' : '') : '' }}>
                                            (GMT+12:00) Auckland, Wellington</option>
                                        <option value="Pacific/Fiji" {{ $tz ? ($tz == 'Pacific/Fiji' ? 'selected' : '') : '' }}>
                                            (GMT+12:00) Fiji, Kamchatka, Marshall Is.</option>
                                        <option value="Pacific/Tongatapu" {{ $tz ? ($tz == 'Pacific/Tongatapu' ? 'selected' : '') : '' }}>
                                            (GMT+13:00) Nuku'alofa </option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($tf = \App\Models\BusinessSetting::where('key', 'timeformat')->first())
                                @php($tf = $tf ? $tf->value : '24')
                                <div class="form-group mb-0">
                                    <label for="time_format"
                                        class="form-label text-capitalize">{{ translate('messages.time_format') }}</label>
                                    <select id="time_format" name="time_format" class="form-control">
                                        <option value="12" {{ $tf == '12' ? 'selected' : '' }}>
                                            {{ translate('messages.12_hour') }}
                                        </option>
                                        <option value="24" {{ $tf == '24' ? 'selected' : '' }}>
                                            {{ translate('messages.24_hour') }}
                                        </option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($currency_code = \App\Models\BusinessSetting::where('key', 'currency')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label" for="currency">{{ translate('Currency Symbol') }}</label>
                                    <select id="change_currency" name="currency" class="form-control js-select2-custom">
                                        @foreach (\App\Models\Currency::orderBy('currency_code')->get() as $currency)
                                            <option value="{{ $currency['currency_code'] }}" {{ $currency_code ? ($currency_code->value == $currency['currency_code'] ? 'selected' : '') : '' }}>
                                                {{ $currency['currency_code'] }} ({{ $currency['currency_symbol'] }})
                                            </option>
                                        @endforeach
                                    </select>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($currency_symbol_position = \App\Models\BusinessSetting::where('key', 'currency_symbol_position')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label text-capitalize"
                                        for="currency_symbol_position">{{ translate('Currency Position') }}
                                    </label>
                                    <div class="resturant-type-group border">
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="left"
                                                name="currency_symbol_position" {{ $currency_symbol_position ? ($currency_symbol_position->value == 'left' ? 'checked' : '') : '' }}>
                                            <span class="form-check-label">
                                                ($) {{translate('Left')}}
                                            </span>
                                        </label>
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="right"
                                                name="currency_symbol_position" {{ $currency_symbol_position ? ($currency_symbol_position->value == 'right' ? 'checked' : '') : '' }}>
                                            <span class="form-check-label">
                                                {{translate('Right')}} ($)
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div class="col-sm-6 col-md-4 col-xl-3">
                                @php($digit_after_decimal_point = \App\Models\BusinessSetting::where('key', 'digit_after_decimal_point')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label text-capitalize"
                                        for="digit_after_decimal_point">{{ translate('messages.Digit after decimal point') }}
                                        <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('how_many_fractional_digit_to_show_after_decimal_value') }}">
                                            <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                        </span>
                                    </label>
                                    <input type="number" name="digit_after_decimal_point" class="form-control"
                                        id="digit_after_decimal_point" placeholder="{{ translate('messages.ex_:_2') }}"
                                        value="{{ $digit_after_decimal_point ? $digit_after_decimal_point->value : 0 }}"
                                        min="0" max="4" required>
                                </div>
                            </div>
                            <div class="col-md-4 col-xl-5">
                                @php($footer_text = \App\Models\BusinessSetting::where('key', 'footer_text')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label" for="footer_text">{{ translate('Copyright Text') }}
                                        <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('messages.make_visitors_aware_of_your_business‘s_rights_&_legal_information.') }}">
                                            <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                        </span>
                                    </label>
                                    <textarea type="text" id="footer_text" name="footer_text" class="form-control h--45"
                                        placeholder="{{ translate('messages.Ex_:_Copyright_Text') }}"
                                        required>{{ $footer_text->value ?? '' }}</textarea>
                                </div>
                            </div>
                            <div class="col-md-4 col-xl-4">
                                @php($cookies_text = \App\Models\BusinessSetting::where('key', 'cookies_text')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label" for="cookies_text">{{ translate('Cookies Text') }}
                                        <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('messages.make_visitors_aware_of_your_business‘s_rights_&_legal_information.') }}">
                                            <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                        </span>
                                    </label>
                                    <textarea type="text" id="cookies_text" name="cookies_text"
                                        class="form-control h--45"
                                        placeholder="{{ translate('messages.Ex_:_Cookies_Text') }}"
                                        required>{{ $cookies_text->value ?? '' }}</textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-12">
                <h4 class="card-title mb-3 d-flex align-items-center"> <span class="card-header-icon mr-2"><i
                            class="tio-neighborhood"></i></span>
                    <span>{{ translate('messages.Business_Rules_setup') }} </span>
                </h4>
                <div class="card">
                    <div class="card-body">
                        <div class="row g-3 align-items-end">
                            <div class="col-sm-6 col-lg-4">
                                @php($admin_commission = \App\Models\BusinessSetting::where('key', 'admin_commission')->first())
                                <div class="form-group mb-0">
                                    <label class="form-label text-capitalize" for="admin_commission">
                                        {{ translate('messages.Default_Commission_Rate_On_Order') }} (%)
                                        <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('messages.Set_up_‘Default_Commission_Rate’_on_every_Order._Admin_can_also_set_store-wise_different_commission_rates_from_respective_store_settings.') }}">
                                            <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                        </span>
                                    </label>
                                    <input type="number" name="admin_commission" class="form-control"
                                        id="admin_commission" placeholder="{{ translate('messages.Ex:_10') }}"
                                        value="{{ $admin_commission ? $admin_commission->value : 0 }}" min="0" max="100"
                                        required>
                                </div>
                            </div>
                            <div class="col-sm-6 col-lg-4">
                                @php($delivery_charge_comission = \App\Models\BusinessSetting::where('key', 'delivery_charge_comission')->first())
                                <div class="form-group mb-0">
                                    <label class="input-label text-capitalize d-flex alig-items-center"
                                        for="admin_comission_in_delivery_charge">
                                        {{translate('messages.Commission_Rate_On_Delivery_Charge')}} (%)
                                        <span class="form-label-secondary" data-toggle="tooltip" data-placement="right"
                                            data-original-title="{{ translate('messages.Set_a_default_‘Commission_Rate’_for_freelance_deliverymen_(under_admin)_on_every_deliveryman. ') }}">
                                            <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                        </span>
                                    </label>
                                    <input type="number" name="admin_comission_in_delivery_charge" class="form-control"
                                        id="admin_comission_in_delivery_charge"
                                        placeholder="{{ translate('messages.Ex:_10') }}" min="0" max="100" step="0.01"
                                        value="{{ $delivery_charge_comission ? $delivery_charge_comission->value : 0 }}">
                                </div>
                            </div>

                            <div class="col-lg-4 col-sm-6">
                                @php($order_confirmation_model = \App\Models\BusinessSetting::where('key', 'order_confirmation_model')->first())
                                @php($order_confirmation_model = $order_confirmation_model ? $order_confirmation_model->value : 'deliveryman')
                                <div class="form-group mb-0">
                                    <label class="input-label text-capitalize d-flex alig-items-center"><span
                                            class="line--limit-1">{{ translate('messages.Who_Will_Confirm_Order?') }}
                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.After_a_customer_order_placement,_Admin_can_define_who_will_confirm_the_order_first-_Deliveryman_or_Store?_For_example,_if_you_choose_‘Delivery_man’,_the_deliveryman_nearby_will_confirm_the_order_and_forward_it_to_the_related_store_to_process_the_order._It_works_vice-versa_if_you_choose_‘Store’.') }}">
                                                <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                            </span>
                                        </span>
                                    </label>
                                    <div class="resturant-type-group border">
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="store"
                                                name="order_confirmation_model" id="order_confirmation_model" {{ $order_confirmation_model == 'store' ? 'checked' : '' }}>
                                            <span class="form-check-label">
                                                {{ translate('messages.store') }}
                                            </span>
                                        </label>
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="deliveryman"
                                                name="order_confirmation_model" id="order_confirmation_model2" {{ $order_confirmation_model == 'deliveryman' ? 'checked' : '' }}>
                                            <span class="form-check-label">
                                                {{ translate('messages.deliveryman') }}
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="col-sm-6 col-lg-4">
                                @php($vnv = \App\Models\BusinessSetting::where('key', 'toggle_veg_non_veg')->first())
                                @php($vnv = $vnv ? $vnv->value : 0)
                                <div class="form-group mb-0">

                                    <label
                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                        <span class="pr-1 d-flex align-items-center switch--label">
                                            <span class="line--limit-1">
                                                {{ translate('messages.Customer’s_Food_Preference') }}
                                            </span>
                                            <span class="form-label-secondary text-danger d-flex" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.If_this_feature_is_active,_customers_can_filter_food_according_to_their_preference_from_the_Customer_App_or_Website.') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.veg_non_veg') }}"> * </span>
                                        </span>
                                        <input type="checkbox" data-id="vnv1" data-type="toggle"
                                            data-image-on="{{ asset('/public/assets/admin/img/modal/veg-on.png') }}"
                                            data-image-off="{{ asset('/public/assets/admin/img/modal/veg-off.png') }}"
                                            data-title-on="{{ translate('messages.Want_to_enable_the') }} <strong>{{ translate('messages.‘Veg/Non-Veg’_feature?') }}</strong>"
                                            data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.the_Veg/Non-Veg_Feature?') }}</strong>"
                                            data-text-on="<p>{{ translate('messages.If_you_enable_this,_customers_can_filter_food_items_by_choosing_food_from_the_Veg/Non-Veg_feature.') }}</p>"
                                            data-text-off="<p>{{ translate('messages.If_you_disable_this,_the_Veg/Non-Veg_feature_will_be_hidden_in_the_Customer_App_&_Website.') }}</p>"
                                            class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                            name="vnv" id="vnv1" {{ $vnv == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                            <div class="col-sm-6 col-lg-4">
                                @php($admin_order_notification = \App\Models\BusinessSetting::where('key', 'admin_order_notification')->first())
                                @php($admin_order_notification = $admin_order_notification ? $admin_order_notification->value : 0)
                                <div class="form-group mb-0">

                                    <label
                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                        <span class="pr-1 d-flex align-items-center switch--label">
                                            <span class="line--limit-1">
                                                {{ translate('messages.Order_Notification_for_Admin') }}
                                            </span>
                                            <span class="form-label-secondary text-danger d-flex" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.Admin_will_get_a_pop-up_notification_with_sounds_for_any_order_placed_by_customers.') }}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.customer_varification_toggle') }}"> *
                                            </span>
                                        </span>
                                        <input type="checkbox" data-id="aon1" data-type="toggle"
                                            data-image-on="{{ asset('/public/assets/admin/img/modal/order-notification-on.png') }}"
                                            data-image-off="{{ asset('/public/assets/admin/img/modal/order-notification-off.png') }}"
                                            data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.Order_Notification_for_Admin?') }}</strong>"
                                            data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.Order_Notification_for_Admin?') }}</strong>"
                                            data-text-on="<p>{{ translate('messages.If_you_enable_this,_the_Admin_will_receive_a_Notification_for_every_order_placed.') }}</p>"
                                            data-text-off="<p>{{ translate('messages.If_you_disable_this,_the_Admin_will_NOT_receive_a_Notification_for_every_order_placed.') }}</p>"
                                            class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                            name="admin_order_notification" id="aon1" {{ $admin_order_notification == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                            <div class="col-sm-6 col-lg-4">
                                @php($order_notification_type = \App\Models\BusinessSetting::where('key', 'order_notification_type')->first())
                                <div class="form-group mb-0">
                                    <label class="input-label text-capitalize d-flex alig-items-center"><span
                                            class="line--limit-1">{{ translate('Order_Notification_Type') }}
                                            <span class="form-label-secondary" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('For_Firebase,_a_single_real-time_notification_will_be_sent_upon_order_placement,_with_no_repetition._For_the_Manual_option,_notifications_will_appear_at_10-second_intervals_until_the_order_is_viewed.') }}">
                                                <img src="{{asset('public/assets/admin/img/info-circle.svg')}}" alt="">
                                            </span>
                                        </span>
                                    </label>
                                    <div class="resturant-type-group border">
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="firebase"
                                                name="order_notification_type" {{ $order_notification_type ? ($order_notification_type->value == 'firebase' ? 'checked' : '') : '' }}>
                                            <span class="form-check-label">
                                                {{translate('firebase')}}
                                            </span>
                                        </label>
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio" value="manual"
                                                name="order_notification_type" {{ $order_notification_type ? ($order_notification_type->value == 'manual' ? 'checked' : '') : '' }}>
                                            <span class="form-check-label">
                                                {{translate('manual')}}
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="col-sm-6 col-lg-4">
                                @php($guest_checkout_status = \App\Models\BusinessSetting::where('key', 'guest_checkout_status')->first())
                                @php($guest_checkout_status = $guest_checkout_status ? $guest_checkout_status->value : 0)
                                <div class="form-group mb-0">
                                    <label
                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                        <span class="pr-1 d-flex align-items-center switch--label">
                                            <span class="line--limit-1">
                                                {{translate('messages.guest_checkout') }}
                                            </span>
                                            <span class="form-label-secondary text-danger d-flex" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.If_enabled,_customers_do_not_have_to_login_while_checking_out_orders.')}}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.customer_varification_toggle') }}"> *
                                            </span>
                                        </span>
                                        <input type="checkbox" data-id="guest_checkout_status" data-type="toggle"
                                            data-image-on="{{ asset('/public/assets/admin/img/modal/dm-tips-on.png') }}"
                                            data-image-off="{{ asset('/public/assets/admin/img/modal/dm-tips-off.png') }}"
                                            data-title-on="<strong>{{ translate('messages.Want_to_enable_guest_checkout?') }}</strong>"
                                            data-title-off="<strong>{{ translate('messages.Want_to_disable_guest_checkout?') }}</strong>"
                                            data-text-on="<p>{{ translate('messages.If_you_enable_this,_guest_checkout_will_be_visible_when_customer_is_not_logged_in.') }}</p>"
                                            data-text-off="<p>{{ translate('messages.If_you_disable_this,_guest_checkout_will_not_be_visible_when_customer_is_not_logged_in.') }}</p>"
                                            class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                            name="guest_checkout_status" id="guest_checkout_status" {{ $guest_checkout_status == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>






                            <div class="col-sm-6 col-lg-4">
                                @php($country_picker_status = \App\Models\BusinessSetting::where('key', 'country_picker_status')->first())
                                @php($country_picker_status = $country_picker_status ? $country_picker_status->value : 0)
                                <div class="form-group mb-0">
                                    <label
                                        class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                        <span class="pr-1 d-flex align-items-center switch--label">
                                            <span class="line--limit-1">
                                                {{translate('messages.country_picker') }}
                                            </span>
                                            <span class="form-label-secondary text-danger d-flex" data-toggle="tooltip"
                                                data-placement="right"
                                                data-original-title="{{ translate('messages.If_you_enable_this_option,_in_all_phone_no_field_will_show_a_country_picker_list.')}}"><img
                                                    src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                    alt="{{ translate('messages.customer_varification_toggle') }}">
                                            </span>
                                        </span>
                                        <input type="checkbox" data-id="country_picker_status" data-type="toggle"
                                            data-image-on="{{ asset('/public/assets/admin/img/modal/mail-success.png') }}"
                                            data-image-off="{{ asset('/public/assets/admin/img/modal/mail-warning.png') }}"
                                            data-title-on="<strong>{{ translate('messages.Want_to_enable_country_picker?') }}</strong>"
                                            data-title-off="<strong>{{ translate('messages.Want_to_disable_country_picker?') }}</strong>"
                                            data-text-on="<p>{{ translate('messages.If_you_enable_this,_user_can_select_country_from_country_picker') }}</p>"
                                            data-text-off="<p>{{ translate('messages.If_you_disable_this,_user_can_not_select_country_from_country_picker,_default_country_will_be_selected') }}</p>"
                                            class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                            name="country_picker_status" id="country_picker_status" {{ $country_picker_status == 1 ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text">
                                            <span class="toggle-switch-indicator"></span>
                                        </span>
                                    </label>
                                </div>
                            </div>


                            {{-- free_delivery_over_status --}}

                        </div>
                        <div class="__bg-F8F9FC-card p-0 mt-4">
                            @php($admin_free_delivery_status = \App\Models\BusinessSetting::where('key', 'admin_free_delivery_status')->first())

                            <div class="border-bottom d-flex justify-content-between p-3">
                                <h4 class="card-title m-0 text--title">{{translate('Free Delivery Option')}}</h4>
                                <label class="form-label d-flex justify-content-between text-capitalize mb-1"
                                    for="admin_free_delivery_status">

                                    <span class="toggle-switch toggle-switch-sm pr-sm-3">
                                        <input type="checkbox" data-id="admin_free_delivery_status" data-type="toggle"
                                            data-image-on="{{ asset('/public/assets/admin/img/modal/free-delivery-on.png') }}"
                                            data-image-off="{{ asset('/public/assets/admin/img/modal/free-delivery-off.png') }}"
                                            data-title-on="<strong>{{ translate('messages.Want_to_enable_Free_Delivery_Option?') }}</strong>"
                                            data-title-off="<strong>{{ translate('messages.Want_to_disable_Free_Delivery_Option?') }}</strong>"
                                            class="status toggle-switch-input dynamic-checkbox-toggle"
                                            name="admin_free_delivery_status" id="admin_free_delivery_status" value="1"
                                            {{ $admin_free_delivery_status?->value ? 'checked' : '' }}>
                                        <span class="toggle-switch-label text mb-0"><span
                                                class="toggle-switch-indicator"></span></span>
                                    </span>
                                </label>
                            </div>


                            <div class="card-body">
                                <div class="row g-3 align-items-end">
                                    <div class="col-sm-6 col-lg-6">


                                        @php($free_delivery_over = \App\Models\BusinessSetting::where('key', 'free_delivery_over')->first())
                                        @php($admin_free_delivery_option = \App\Models\BusinessSetting::where('key', 'admin_free_delivery_option')->first())
{{--                                        @dd($admin_free_delivery_status?->value)--}}

                                        <div class="form-group mb-0">
                                            <label
                                                class="input-label text-capitalize d-flex alig-items-center add_text_mute {{ $admin_free_delivery_status?->value ? '' : 'text-muted' }} "><span
                                                    class="line--limit-1">{{ translate('Choose Free Delivery Option') }}
                                                </span>
                                            </label>
                                            <div class="resturant-type-group border bg-white">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input radio-trigger" type="radio" {{ $admin_free_delivery_status?->value ? '' : 'disabled' }}
                                                        value="free_delivery_to_all_store"
                                                        name="admin_free_delivery_option" {{ $admin_free_delivery_option?->value == 'free_delivery_to_all_store' ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{translate('Set free delivery for all store')}}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input
                                                        class="form-check-input radio-trigger"
                                                        type="radio" {{ $admin_free_delivery_status?->value ? '' : 'disabled' }} value="free_delivery_by_order_amount"
                                                        name="admin_free_delivery_option" {{ $admin_free_delivery_option?->value == 'free_delivery_by_order_amount' || $admin_free_delivery_option?->value == null ? 'checked' : '' }}>
                                                    <span class="form-check-label">
                                                        {{translate('Set Specific Criteria')}}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>



                                    <div id="show_free_delivery_over"
                                        class="col-sm-6 col-lg-6 {{ $admin_free_delivery_option?->value == 'free_delivery_by_order_amount' || $admin_free_delivery_option?->value == null ? '' : 'd-none' }}">
                                        <div class="form-group mb-0">
                                            <label
                                                class="form-label d-flex justify-content-between text-capitalize mb-1 add_text_mute {{ $admin_free_delivery_status?->value ? '' : 'text-muted' }} "
                                                for="">
                                                <span
                                                    class="line--limit-1">{{ translate('messages.free_delivery_over') }}
                                                    ({{ \App\CentralLogics\Helpers::currency_symbol() }}) <small
                                                        class="text-danger"><span class="form-label-secondary"
                                                            data-toggle="tooltip" data-placement="right"
                                                            data-original-title="{{ translate('messages.Set_a_minimum_order_value_for_automated_free_delivery._If_the_minimum_amount_is_exceeded,_the_Delivery_Fee_is_deducted_from_Admin’s_commission_and_added_to_Admin’s_expense.') }}"><img
                                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                                alt="{{ translate('messages.free_over_delivery_message') }}"></span>
                                                        *</small></span>

                                            </label>

                                            <input type="number" name="free_delivery_over" class="form-control"
                                                id="free_delivery_over" placeholder="{{ translate('messages.Ex:_10') }}"
                                                value="{{ $free_delivery_over ? $free_delivery_over->value : 0 }}"
                                                min="1" step=".01" {{ $admin_free_delivery_option?->value == 'free_delivery_by_order_amount' ? 'required' : '' }} {{ $admin_free_delivery_status?->value ? '' : 'readonly' }}>
                                        </div>
                                    </div>
                                    <div id="show_text_for_all_store_free_delivery"
                                        class="col-sm-6 col-lg-6 {{ $admin_free_delivery_option?->value == 'free_delivery_to_all_store' ? '' : ' d-none' }}">
                                        <div class="alert fs-13 alert-primary-light text-dark mb-0  mt-md-0 add_text_mute text-muted"
                                            role="alert">
                                            <img src="{{ asset('/public/assets/admin/img/lnfo_light.png') }}" alt="">
                                            {{translate('Free delivery is active for all stores. Cost bearer for the free delivery is')}}
                                            <strong>{{ translate('Admin') }}</strong>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>


                        <div class="__bg-F8F9FC-card p-0 mt-4">
                            <div class="border-bottom p-3">
                                <h4 class="card-title m-0 text--title">{{translate('Additional Charge')}}</h4>
                            </div>
                            <div class="card-body">
                                <div class="row g-3 align-items-end">
                                    <div class="col-sm-6 col-lg-4">
                                        @php($additional_charge_status = \App\Models\BusinessSetting::where('key', 'additional_charge_status')->first())
                                        @php($additional_charge_status = $additional_charge_status ? $additional_charge_status->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{translate('messages.additional_charge') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.If_enabled,_customers_need_to_pay_an_extra_charge_while_checking_out_orders.')}}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.customer_varification_toggle') }}">
                                                        *
                                                    </span>
                                                </span>
                                                <input type="checkbox" data-id="additional_charge_status"
                                                    data-type="toggle"
                                                    data-image-on="{{ asset('/public/assets/admin/img/modal/dm-tips-on.png') }}"
                                                    data-image-off="{{ asset('/public/assets/admin/img/modal/dm-tips-off.png') }}"
                                                    data-title-on="<strong>{{ translate('messages.Want_to_enable_additional_charge?') }}</strong>"
                                                    data-title-off="<strong>{{ translate('messages.Want_to_disable_additional_charge?') }}</strong>"
                                                    data-text-on="<p>{{ translate('messages.If_you_enable_this,_additional_charge_will_be_added_with_order_amount,_it_will_be_added_in_admin_wallet') }}</p>"
                                                    data-text-off="<p>{{ translate('messages.If_you_disable_this,_additional_charge_will_not_be_added_with_order_amount.') }}</p>"
                                                    class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                                    name="additional_charge_status" id="additional_charge_status" {{ $additional_charge_status == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($additional_charge_name = \App\Models\BusinessSetting::where('key', 'additional_charge_name')->first())
                                        <div class="form-group mb-0">
                                            <label
                                                class="form-label d-flex justify-content-between text-capitalize mb-1"
                                                for="additional_charge_name">
                                                <span
                                                    class="line--limit-1">{{ translate('messages.additional_charge_name') }}
                                                    <small class="text-danger"><span class="form-label-secondary"
                                                            data-toggle="tooltip" data-placement="right"
                                                            data-original-title="{{ translate('messages.Set_a_name_for_the_additional_charge,_e.g._“Processing_Fee”.') }}"><img
                                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                                alt="{{ translate('messages.free_over_delivery_message') }}"></span>
                                                        *</small></span>
                                            </label>

                                            <input type="text" name="additional_charge_name" class="form-control"
                                                id="additional_charge_name"
                                                placeholder="{{ translate('messages.Ex:_Processing_Fee') }}"
                                                value="{{ $additional_charge_name ? $additional_charge_name->value : '' }}"
                                                {{ isset($additional_charge_status) ? '' : 'readonly' }} required>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($additional_charge = \App\Models\BusinessSetting::where('key', 'additional_charge')->first())
                                        <div class="form-group mb-0">
                                            <label
                                                class="form-label d-flex justify-content-between text-capitalize mb-1"
                                                for="additional_charge">
                                                <span class="line--limit-1">{{ translate('messages.charge_amount') }}
                                                    ({{ \App\CentralLogics\Helpers::currency_symbol() }}) <small
                                                        class="text-danger"><span class="form-label-secondary"
                                                            data-toggle="tooltip" data-placement="right"
                                                            data-original-title="{{ translate('messages.Set_the_value_(amount)_customers_need_to_pay_as_additional_charge.') }}"><img
                                                                src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                                alt="{{ translate('messages.free_over_delivery_message') }}"></span>
                                                        *</small></span>
                                            </label>

                                            <input type="number" name="additional_charge" class="form-control"
                                                id="additional_charge" placeholder="{{ translate('messages.Ex:_10') }}"
                                                value="{{ $additional_charge ? $additional_charge->value : 0 }}" min="0"
                                                step=".01" {{ isset($additional_charge_status) ? '' : 'readonly' }}>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="__bg-F8F9FC-card p-0 mt-4">
                            <div class="border-bottom p-3">
                                <h4 class="card-title m-0 text--title">{{translate('Payment')}}</h4>
                            </div>
                            <div class="card-body">
                                <div class="row g-3 align-items-end">
                                    <div class="col-sm-6 col-lg-4">
                                        @php($partial_payment = \App\Models\BusinessSetting::where('key', 'partial_payment_status')->first())
                                        @php($partial_payment = $partial_payment ? $partial_payment->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('messages.partial_payment') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('messages.If_enabled,_customers_can_make_partial_payments._For_example,_a_customer_can_pay_$20_initially_out_of_their_$50_payment_&_use_other_payment_methods_for_the_rest._Partial_payments_must_be_made_through_their_wallets.')}}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.customer_varification_toggle') }}">
                                                        *
                                                    </span>
                                                </span>
                                                <input type="checkbox" data-id="partial_payment" data-type="toggle"
                                                    data-image-on="{{ asset('/public/assets/admin/img/modal/schedule-on.png') }}"
                                                    data-image-off="{{ asset('/public/assets/admin/img/modal/schedule-off.png') }}"
                                                    data-title-on="{{ translate('messages.Want_to_enable') }} <strong>{{ translate('messages.partial_payment_?') }}</strong>"
                                                    data-title-off="{{ translate('messages.Want_to_disable') }} <strong>{{ translate('messages.partial_payment_?') }}</strong>"
                                                    data-text-on="<p>{{ translate('messages.If_you_enable_this,_customers_can_choose_partial_payment_during_checkout.') }}</p>"
                                                    data-text-off="<p>{{ translate('messages.If_you_disable_this,_the_partial_payment_feature_will_be_hidden.') }}</p>"
                                                    class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                                    name="partial_payment_status" id="partial_payment" {{ $partial_payment == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($partial_payment_method = \App\Models\BusinessSetting::where('key', 'partial_payment_method')->first())
                                        <div class="form-group mb-0">
                                            <label class="input-label text-capitalize d-flex alig-items-center"><span
                                                    class="line--limit-1">{{ translate('Can_Pay_the_Rest_Amount_using') }}
                                                    <span class="form-label-secondary" data-toggle="tooltip"
                                                        data-placement="right"
                                                        data-original-title="{{ translate('messages.Set_the_method(s)_that_customers_can_pay_the_remainder_after_partial_payment.') }}"
                                                        alt="">
                                                        <img src="{{asset('public/assets/admin/img/info-circle.svg')}}"
                                                            alt="">
                                                    </span>
                                                </span>
                                            </label>
                                            <div class="resturant-type-group border bg-white">
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio" value="cod"
                                                        name="partial_payment_method" {{ $partial_payment_method ? ($partial_payment_method->value == 'cod' ? 'checked' : '') : '' }}>
                                                    <span class="form-check-label">
                                                        {{translate('cod')}}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio" value="digital_payment"
                                                        name="partial_payment_method" {{ $partial_payment_method ? ($partial_payment_method->value == 'digital_payment' ? 'checked' : '') : '' }}>
                                                    <span class="form-check-label">
                                                        {{translate('digital_payment')}}
                                                    </span>
                                                </label>
                                                <label class="form-check form--check">
                                                    <input class="form-check-input" type="radio" value="both"
                                                        name="partial_payment_method" {{ $partial_payment_method ? ($partial_payment_method->value == 'both' ? 'checked' : '') : '' }}>
                                                    <span class="form-check-label">
                                                        {{translate('both')}}
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>


                        <div class="__bg-F8F9FC-card p-0 mt-4">
                            <div class="border-bottom p-3">
                                <h4 class="card-title m-0 text--title">{{translate('Business_Plan')}}</h4>
                            </div>
                            <div class="card-body">
                                <div class="row g-3 align-items-end">
                                    <div class="col-sm-6 col-lg-4">
                                        @php($subscription_business_model = \App\Models\BusinessSetting::where('key', 'subscription_business_model')->first())
                                        @php($subscription_business_model = $subscription_business_model ? $subscription_business_model->value : 0)
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('Subscription') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('If_enabled,_the_package_based_subscription_business_model_option_will_be_available_for_stores')}}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.customer_varification_toggle') }}">
                                                        *
                                                    </span>
                                                </span>
                                                <input type="checkbox" data-id="subscription_business_model"
                                                    data-type="toggle"
                                                    data-image-on="{{ asset('/public/assets/admin/img/modal/mail-success.png') }}"
                                                    data-image-off="{{ asset('/public/assets/admin/img/modal/mail-warning.png') }}"
                                                    data-title-on="{{ translate('Want_to_enable_the') }} <strong>{{ translate('Subscription_Base') }}</strong> {{ translate('Business_Model') }} ?"
                                                    data-title-off="{{ translate('Want_to_disable_the') }} <strong>{{ translate('Subscription_Base') }} {{ translate('Business_Model') }}</strong> ?"
                                                    data-text-on="<p>{{ translate('If_enabled,_the_subscription_based_store_business_model_option_will_be_available_in_this_store') }}</p>"
                                                    data-text-off="<p>{{ translate('If_disabled,_the_subscription_based_store_business_model_option_will_be_hidden_from_this_store_panel._The_existing_subscribed_stores’_subscriptions_will_be_valid_till_the_packages_expire') }}</p>"
                                                    class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                                    name="subscription_business_model" id="subscription_business_model"
                                                    {{ $subscription_business_model == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-sm-6 col-lg-4">
                                        @php($commission_business_model = \App\Models\BusinessSetting::where('key', 'commission_business_model')->first())
                                        @php($commission_business_model = $commission_business_model ? $commission_business_model->value : 0)
                                        {{-- {{ dd($commission_business_model) }} --}}
                                        <div class="form-group mb-0">
                                            <label
                                                class="toggle-switch h--45px toggle-switch-sm d-flex justify-content-between border rounded px-3 py-0 form-control">
                                                <span class="pr-1 d-flex align-items-center switch--label">
                                                    <span class="line--limit-1">
                                                        {{ translate('Commission') }}
                                                    </span>
                                                    <span class="form-label-secondary text-danger d-flex"
                                                        data-toggle="tooltip" data-placement="right"
                                                        data-original-title="{{ translate('If_enabled,_the_commission_based_business_model_option_will_be_available_for_stores.')}}"><img
                                                            src="{{ asset('/public/assets/admin/img/info-circle.svg') }}"
                                                            alt="{{ translate('messages.customer_varification_toggle') }}">
                                                        *
                                                    </span>
                                                </span>
                                                <input type="checkbox" data-id="commission_business_model"
                                                    data-type="toggle"
                                                    data-image-on="{{ asset('/public/assets/admin/img/modal/mail-success.png') }}"
                                                    data-image-off="{{ asset('/public/assets/admin/img/modal/mail-warning.png') }}"
                                                    data-title-on="{{ translate('Want_to_enable_the') }} <strong>{{ translate('Commission_Base') }}</strong> {{ translate('Business_Model') }} ?"
                                                    data-title-off="{{ translate('Want_to_disable_the') }} <strong>{{ translate('Commission_Base') }} {{ translate('Business_Model') }}</strong> ?"
                                                    data-text-on="<p>{{ translate('If_enabled,_the_commission_based_store_business_model_option_will_be_available_for_this_store') }}</p>"
                                                    data-text-off="<p>{{ translate('If_disabled,_the_commission_based_store_business_model_option_will_be_hidden_from_this_store_panel._And_it_can_only_use_the_subscription_based_business_model') }}</p>"
                                                    class="status toggle-switch-input dynamic-checkbox-toggle" value="1"
                                                    name="commission_business_model" id="commission_business_model" {{ $commission_business_model == 1 ? 'checked' : '' }}>
                                                <span class="toggle-switch-label text">
                                                    <span class="toggle-switch-indicator"></span>
                                                </span>
                                            </label>
                                        </div>
                                    </div>

                                </div>
                            </div>
                        </div>

                        <div class="btn--container justify-content-end mt-3">
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



<div class="modal fade" id="currency-warning-modal">
    <div class="modal-dialog modal-dialog-centered status-warning-modal">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">
                    <span aria-hidden="true" class="tio-clear"></span>
                </button>
            </div>
            <div class="modal-body pb-5 pt-0">
                <div class="max-349 mx-auto mb-20">
                    <div>
                        <div class="text-center">
                            <img width="80" src="{{  asset('public/assets/admin/img/modal/currency.png') }}"
                                class="mb-20">
                            <h5 class="modal-title"></h5>
                        </div>
                        <div class="text-center">
                            <h3> {{ translate('Are_you_sure_to_change_the_currency_?') }}</h3>
                            <div>
                                <p>{{ translate('If_you_enable_this_currency,_you_must_active_at_least_one_digital_payment_method_that_supports_this_currency._Otherwise_customers_cannot_pay_via_digital_payments_from_the_app_and_websites._And_Also_restaurants_cannot_pay_you_digitally') }}
                                    </h3>
                                </p>
                            </div>
                        </div>

                        <div class="text-center mb-4">
                            <a class="text--underline"
                                href="{{ route('admin.business-settings.third-party.payment-method') }}">
                                {{ translate('Go_to_payment_method_settings.') }}</a>
                        </div>
                    </div>

                    <div class="btn--container justify-content-center">
                        <button data-dismiss="modal" id="confirm-currency-change"
                            class="btn btn--cancel min-w-120">{{translate("Cancel")}}</button>
                        <button data-dismiss="modal" type="button"
                            class="btn btn--primary min-w-120">{{translate('OK')}}</button>

                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="confirmation_modal_free_delivery_by_order_amount" tabindex="-1" role="dialog"
    aria-labelledby="modalLabel" aria-hidden="true">
    <div class=" modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body pb-5 pt-0">
                <div class="max-349 mx-auto mb-20">
                    <div>
                        <div class="text-center">
                            <img src="{{asset('/public/assets/admin/img/subscription-plan/package-status-disable.png')}}"
                                class="mb-20">

                            <h5 class="modal-title"></h5>
                        </div>
                        <div class="text-center">
                            <h3> {{ translate('Do You Want Active “Set Specific Criteria”?') }}</h3>
                            <div>
                                <p>{{ translate('Are you sure to active “Set Specific Criteria”? If you active this delivery charge will not added to order when customer order more then your “Free Delivery Over” amount.') }}
                                    </h3>
                                </p>
                            </div>
                        </div>



                        <div class="btn--container justify-content-center">
                            <button data-dismiss="modal"
                                class="btn btn-soft-secondary min-w-120">{{translate("Cancel")}}</button>
                            <button data-dismiss="modal" type="button" id="confirmBtn_free_delivery_by_order_amount"
                                class="btn btn--primary min-w-120">{{translate('Yes')}}</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>


<div class="modal fade" id="confirmation_modal_free_delivery_to_all_store" tabindex="-1" role="dialog"
    aria-labelledby="modalLabel" aria-hidden="true">
    <div class="modal-dialog-centered modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body pb-5 pt-0">
                <div class="max-349 mx-auto mb-20">
                    <div>
                        <div class="text-center">
                            <img src="{{asset('/public/assets/admin/img/subscription-plan/package-status-disable.png')}}"
                                class="mb-20">

                            <h5 class="modal-title"></h5>
                        </div>
                        <div class="text-center">
                            <h3> {{ translate('Do You Want Active “Free Delivery for All Stores”?') }}</h3>
                            <div>
                                <p>{{ translate('Are you sure to active “Free delivery order for all Stores”? If you active this no delivery charge will added to order and the cost will be added to you.') }}
                                    </h3>
                                </p>
                            </div>
                        </div>
                        <div class="btn--container justify-content-center">
                            <button data-dismiss="modal"
                                class="btn btn-soft-secondary min-w-120">{{translate("Cancel")}}</button>
                            <button data-dismiss="modal" type="button" id="confirmBtn_free_delivery_to_all_store"
                                class="btn btn--primary min-w-120">{{translate('Yes')}}</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@push('script_2')

    <script>
        "use strict";

        $(document).ready(function () {
            let selectedRadio = null;

            // Function to update field validation based on selected option and status
            function updateFieldValidation() {
                const isEnabled = $('#admin_free_delivery_status').is(':checked');
                const selectedValue = $('input[name="admin_free_delivery_option"]:checked').val();

                if (!isEnabled) {
                    // When disabled, remove validation and make readonly
                    $('#free_delivery_over').removeAttr('required').prop('readonly', true);
                    $('.radio-trigger').prop('disabled', true);
                } else {
                    // When enabled, set validation based on selected radio
                    $('.radio-trigger').prop('disabled', false);

                    if (selectedValue === 'free_delivery_by_order_amount') {
                        $('#show_free_delivery_over').removeClass('d-none');
                        $('#show_text_for_all_store_free_delivery').addClass('d-none');
                        $('#free_delivery_over').prop('readonly', false).prop('required', true);
                    } else if (selectedValue === 'free_delivery_to_all_store') {
                        $('#show_free_delivery_over').addClass('d-none');
                        $('#show_text_for_all_store_free_delivery').removeClass('d-none');
                        $('#free_delivery_over').val('').prop('required', false).prop('readonly', true);
                    }
                }

                // Update text-muted classes
                if (isEnabled) {
                    $('.add_text_mute').removeClass('text-muted');
                } else {
                    $('.add_text_mute').addClass('text-muted');
                }
            }

            // Handle radio button clicks
            $(".radio-trigger").on("click", function (event) {
                event.preventDefault();
                selectedRadio = this;
                let selectedValue = $(this).val();

                if (selectedValue === 'free_delivery_to_all_store') {
                    $("#confirmation_modal_free_delivery_to_all_store").modal("show");
                } else {
                    $("#confirmation_modal_free_delivery_by_order_amount").modal("show");
                }
            });

            // Handle confirmation for "free delivery to all store"
            $("#confirmBtn_free_delivery_to_all_store").on("click", function () {
                if (selectedRadio) {
                    selectedRadio.checked = true;
                    updateFieldValidation();
                }
                $("#confirmation_modal_free_delivery_to_all_store").modal("hide");
            });

            // Handle confirmation for "free delivery by order amount"
            $("#confirmBtn_free_delivery_by_order_amount").on("click", function () {
                if (selectedRadio) {
                    selectedRadio.checked = true;
                    updateFieldValidation();
                }
                $("#confirmation_modal_free_delivery_by_order_amount").modal("hide");
            });

            // Handle toggle switch change - using multiple event listeners to catch all scenarios
            $('#admin_free_delivery_status').on('change', function() {
                // Use setTimeout to ensure this runs after any other handlers
                setTimeout(function() {
                    updateFieldValidation();
                }, 100);
            });

            // Also listen for click events on the toggle
            $('#admin_free_delivery_status').on('click', function() {
                setTimeout(function() {
                    updateFieldValidation();
                }, 100);
            });

            // Listen for changes on the parent toggle switch span (in case the event bubbles from there)
            $('.toggle-switch-input').on('change', function() {
                setTimeout(function() {
                    updateFieldValidation();
                }, 100);
            });

            // Initialize validation state on page load
            setTimeout(function() {
                updateFieldValidation();
            }, 200);
        });

        $(document).ready(function () {
            let selectedCurrency = "{{ $currency_code ? $currency_code->value : 'USD' }}";
            let currencyConfirmed = false;
            let updatingCurrency = false;

            $("#change_currency").change(function () {
                if (!updatingCurrency) check_currency($(this).val());
            });

            $("#confirm-currency-change").click(function () {
                currencyConfirmed = true;
                update_currency(selectedCurrency);
                $('#currency-warning-modal').modal('hide');
            });

            function check_currency(currency) {
                $.ajax({
                    headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') },
                    url: "{{route('admin.system_currency')}}",
                    method: 'GET',
                    data: { currency: currency },
                    success: function (response) {
                        if (response.data) {
                            $('#currency-warning-modal').modal('show');
                        } else {
                            update_currency(currency);
                        }
                    }
                });
            }

            function update_currency(currency) {
                if (currencyConfirmed) {
                    updatingCurrency = true;
                    $("#change_currency").val(currency).trigger('change');
                    updatingCurrency = false;
                    currencyConfirmed = false;
                }
            }
        });
    </script>

<script
    src="https://maps.googleapis.com/maps/api/js?key={{ \App\Models\BusinessSetting::where('key', 'map_api_key')->first()->value }}&libraries=places,marker&v=3.61">
    </script>
<script>
    "use strict";
    $(document).on('ready', function () {
        @php($country = \App\Models\BusinessSetting::where('key', 'country')->first())

        @if ($country)
            $("#country option[value='{{ $country->value }}']").attr('selected', 'selected').change();
        @endif
        });

    @php($language = \App\Models\BusinessSetting::where('key', 'language')->first())
    @php($language = $language->value ?? null)
    let language = <?php echo $language; ?>;
    $('[id=language]').val(language);


    $(document).on('click', '.maintenance-mode', function () {
        @if (env('APP_MODE') == 'demo')
            toastr.warning('Sorry! You can not enable maintenance mode in demo!');
        @else
            Swal.fire({
                title: '{{ translate('messages.Are you sure?') }}',
                text: '{{ translate('messages.all_your_apps_and_customer_website_will_be_disabled_until_you_‘Turn_Off’ _maintenance_mode.') }}',
                type: 'warning',
                showCancelButton: true,
                cancelButtonColor: 'default',
                confirmButtonColor: '#00868F',
                cancelButtonText: '{{ translate('messages.no') }}',
                confirmButtonText: '{{ translate('messages.yes') }}',
                reverseButtons: true
            }).then((result) => {
                if (result.value) {
                    $.get({
                        url: '{{ route('admin.maintenance-mode') }}',
                        contentType: false,
                        processData: false,
                        beforeSend: function () {
                            $('#loading').show();
                        },
                        success: function (data) {
                            toastr.success(data.message);
                        },
                        complete: function () {
                            $('#loading').hide();
                        },
                    });
                } else {
                    location.reload();
                }
            })
        @endif

        });


    function readURL(input, viewer) {
        if (input.files && input.files[0]) {
            let reader = new FileReader();
            reader.onload = function (e) {
                $('#' + viewer).attr('src', e.target.result);
            }
            reader.readAsDataURL(input.files[0]);
        }
    }

    $("#customFileEg1").change(function () {
        readURL(this, 'viewer');
    });

    $("#favIconUpload").change(function () {
        readURL(this, 'iconViewer');
    });

    function initAutocomplete() {
        const mapId = "{{ \App\Models\BusinessSetting::where('key', 'map_api_key')->first()->value }}"

        var myLatLng = {
            lat: {{ $default_location ? $default_location['lat'] : '-33.8688' }},
            lng: {{ $default_location ? $default_location['lng'] : '151.2195' }}
            };
        const map = new google.maps.Map(document.getElementById("location_map_canvas"), {
            center: {
                lat: {{ $default_location ? $default_location['lat'] : '-33.8688' }},
                lng: {{ $default_location ? $default_location['lng'] : '151.2195' }}
                },
            zoom: 13,
            mapTypeId: "roadmap",
            mapId: mapId,
        });

        const { AdvancedMarkerElement } = google.maps.marker;

        var marker = new AdvancedMarkerElement({
            position: myLatLng,
            map: map,
        });

        var geocoder = geocoder = new google.maps.Geocoder();
        google.maps.event.addListener(map, 'click', function (mapsMouseEvent) {
            var coordinates = JSON.stringify(mapsMouseEvent.latLng.toJSON(), null, 2);
            var coordinates = JSON.parse(coordinates);
            var latlng = new google.maps.LatLng(coordinates['lat'], coordinates['lng']);
            marker.position = latlng;
            map.panTo(latlng);

            document.getElementById('latitude').value = coordinates['lat'];
            document.getElementById('longitude').value = coordinates['lng'];


            geocoder.geocode({
                'latLng': latlng
            }, function (results, status) {
                if (status == google.maps.GeocoderStatus.OK) {
                    if (results[1]) {
                        document.getElementById('address').value = results[1].formatted_address;
                    }
                }
            });
        });
        // Create the search box and link it to the UI element.
        const input = document.getElementById("pac-input");
        const searchBox = new google.maps.places.SearchBox(input);
        map.controls[google.maps.ControlPosition.TOP_CENTER].push(input);
        // Bias the SearchBox results towards current map's viewport.
        map.addListener("bounds_changed", () => {
            searchBox.setBounds(map.getBounds());
        });
        let markers = [];
        // Listen for the event fired when the user selects a prediction and retrieve
        // more details for that place.
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
                if (!place.geometry || !place.geometry.location) {
                    console.log("Returned place contains no geometry");
                    return;
                }
                const { AdvancedMarkerElement } = google.maps.marker;
                var mrkr = new AdvancedMarkerElement({
                    map,
                    title: place.name,
                    position: place.geometry.location,
                });
                google.maps.event.addListener(mrkr, "click", function (event) {
                    document.getElementById('latitude').value = this.position.lat();
                    document.getElementById('longitude').value = this.position.lng();
                });

                markers.push(mrkr);

                if (place.geometry.viewport) {
                    // Only geocodes have viewport.
                    bounds.union(place.geometry.viewport);
                } else {
                    bounds.extend(place.geometry.location);
                }
            });
            map.fitBounds(bounds);
        });
    };

    $(document).on('ready', function () {
        initAutocomplete();
    });

    $(document).on("keydown", "input", function (e) {
        if (e.which === 13) e.preventDefault();
    });
</script>
@endpush
