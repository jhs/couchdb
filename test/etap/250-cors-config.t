#!/usr/bin/env escript
% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

default_config() ->
    test_util:build_file("etc/couchdb/default_dev.ini").

main(_) ->
    test_util:init_code_path(),

    etap:plan(20),
    case (catch test()) of
        ok ->
            etap:end_tests();
        Other ->
            etap:diag(io_lib:format("Test died abnormally: ~p", [Other])),
            etap:bail(Other)
    end,
    ok.

test() ->
    % start couch_config with default
    couch_config:start_link([default_config()]),
    test_api_calls(),
    test_policy_structure(),
    test_lowercase_headers(),
    test_defaults(),
    ok.

test_api_calls() ->
    etap:is(threw(fun() -> couch_cors_policy:global_config() end),
            false, "No problem building global CORS policy"),

    % Test the "shortcut" policy check call, which requires couch_config.
    Req = {'GET', []},
    etap:not_ok(threw(fun() -> couch_cors_policy:headers(Req) end),
                "Policy check with one valid parameter"),
    etap:not_ok(threw(fun() -> couch_cors_policy:headers([], Req) end),
                "Policy check with two valid parameters"),
    ok.

test_policy_structure() ->
    couch_config:set("origins", "example.com",
                     "http://origin.com, https://origin.com:6984", false),

    Config = couch_cors_policy:global_config(),
    etap:ok(is_list(Config), "Global CORS config is a list"),

    HttpdObj = couch_util:get_value(<<"httpd">>, Config),
    etap:ok(is_tuple(HttpdObj), "Global CORS config: httpd section"),

    {Httpd} = HttpdObj,
    etap:ok(is_list(Httpd), "Global CORS httpd section looks good"),

    Enabled = couch_util:get_value(<<"cors_enabled">>, Httpd),
    etap:ok(is_boolean(Enabled), "Boolean global CORS enabled flag"),

    XHost = couch_util:get_value(<<"x_forwarded_host">>, Httpd),
    etap:is(XHost, <<"X-Forwarded-Host">>,
            "CORS config has X-Forwarded-Host setting"),

    OriginsObj = couch_util:get_value(<<"origins">>, Config),
    etap:ok(is_tuple(OriginsObj), "Global CORS config: origins section"),

    {Origins} = OriginsObj,
    etap:ok(is_list(Origins), "Global CORS origins section looks good"),

    ExampleObj = couch_util:get_value(<<"example.com">>, Origins),
    etap:ok(is_tuple(ExampleObj), "Configured origins object: example.com"),

    Nope1 = couch_util:get_value(<<"http://origin.com">>, Config, false),
    etap:not_ok(Nope1, "No top-level config: http://origin.com"),

    Nope2 = couch_util:get_value(<<"http://origin.com">>, Config, false),
    etap:not_ok(Nope2, "No top-level config: https://origin.com:6984"),

    {Example} = ExampleObj,
    {Origin1} = couch_util:get_value(<<"http://origin.com">>, Example),
    etap:ok(is_list(Origin1), "CORS origin config: http://origin.com"),

    {Origin2} = couch_util:get_value(<<"http://origin.com">>, Example),
    etap:ok(is_list(Origin2), "CORS origin config: http://origin.com"),

    ok.

test_lowercase_headers() ->
    couch_config:set("origins", "example.com",
                     "http://origin.com, https://origin.com:6984", false),
    couch_config:set("http://origin.com", "allow_headers",
                     "X-Some-Header", false),

    FauxReq = {'GET', [{"Host", "example.com"}]},
    Config = couch_cors_policy:global_config(),
    NormalConfig = couch_cors_policy:origins_config(Config, [], FauxReq),
    {Policy} = couch_util:get_value(<<"http://origin.com">>, NormalConfig),
    Headers = couch_util:get_value(<<"allow_headers">>, Policy),
    etap:is(Headers, <<"x-some-header">>,
            "CORS config lower-cases the allowed headers"),
    ok.

test_defaults() ->
    Headers = [],
    Req = {'GET', Headers},

    Hosts = couch_cors_policy:origins_config([], [], Req),
    {Config} = couch_util:get_value(<<"*">>, Hosts),

    etap:ok(is_list(Config), "Default CORS origin is *"),
    etap:is(couch_util:get_value(<<"allow_credentials">>, Config),
            false, "CORS default: allow_credentials"),
    etap:is(couch_util:get_value(<<"max_age">>, Config),
            14400, "CORS default: max_age"),
    etap:is(couch_util:get_value(<<"allow_methods">>, Config),
            <<"GET, HEAD, POST">>, "CORS default: allow_methods"),
    ok.

%
% Utilities
%

threw(Function) ->
    try Function() of
        _Nope -> false
        catch _:_ -> true
    end.

% vim: sts=4 sw=4 et