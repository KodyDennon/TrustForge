-module(trustforge_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    decode_allow/1,
    decode_deny_4xx/1,
    network_error/1,
    request_payload_drops_undefined/1,
    evaluate_maps_verbs/1,
    new_trace_id_format/1,
    sends_correct_url_and_headers/1
]).

all() ->
    [
        decode_allow,
        decode_deny_4xx,
        network_error,
        request_payload_drops_undefined,
        evaluate_maps_verbs,
        new_trace_id_format,
        sends_correct_url_and_headers
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(jsx),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Helpers
%%====================================================================

ok_response(BodyMap) -> ok_response(BodyMap, 200).
ok_response(BodyMap, Status) ->
    Bin = jsx:encode(BodyMap),
    fun(post, _Req, _HOpts, _ROpts) ->
        {ok, {{"HTTP/1.1", Status, "OK"}, [], Bin}}
    end.

err_response(Reason) ->
    fun(post, _Req, _HOpts, _ROpts) -> {error, Reason} end.

%%====================================================================
%% Cases
%%====================================================================

decode_allow(_Config) ->
    Req = #{action => <<"fs.read">>, trace_id => <<"tf-1">>},
    HttpFun = ok_response(#{
        <<"decision">> => <<"allow">>,
        <<"proof_id">> => <<"p-1">>,
        <<"danger_tags">> => [<<"fs">>]
    }),
    {ok, Resp} = trustforge:decide(Req, #{http_fun => HttpFun}),
    <<"allow">> = maps:get(decision, Resp),
    <<"p-1">> = maps:get(proof_id, Resp),
    [<<"fs">>] = maps:get(danger_tags, Resp),
    ok.

decode_deny_4xx(_Config) ->
    Req = #{action => <<"fs.read">>, trace_id => <<"tf-1">>},
    HttpFun = ok_response(#{<<"decision">> => <<"deny">>}, 403),
    {error, Err} = trustforge:decide(Req, #{http_fun => HttpFun}),
    403 = maps:get(status, Err),
    Msg = maps:get(message, Err),
    true = nomatch /= binary:match(Msg, <<"403">>),
    ok.

network_error(_Config) ->
    Req = #{action => <<"x">>, trace_id => <<"tf-1">>},
    {error, Err} = trustforge:decide(Req, #{http_fun => err_response(nxdomain)}),
    0 = maps:get(status, Err),
    Msg = maps:get(message, Err),
    true = nomatch /= binary:match(Msg, <<"network error">>),
    ok.

request_payload_drops_undefined(_Config) ->
    Req = #{
        action => <<"fs.read">>,
        trace_id => <<"tf-1">>,
        host_token => undefined,
        actor => undefined,
        target => <<"/etc/hosts">>,
        context => #{<<"method">> => <<"GET">>}
    },
    Payload = trustforge:request_to_payload(Req),
    %% No undefined values, with binary keys:
    <<"fs.read">> = maps:get(<<"action">>, Payload),
    <<"tf-1">> = maps:get(<<"trace_id">>, Payload),
    <<"/etc/hosts">> = maps:get(<<"target">>, Payload),
    error = maps:find(<<"host_token">>, Payload),
    error = maps:find(<<"actor">>, Payload),
    ok.

evaluate_maps_verbs(_Config) ->
    Req = #{action => <<"x">>, trace_id => <<"tf-1">>},

    Cases = [
        {<<"allow">>, allow},
        {<<"deny">>, deny},
        {<<"approval-required">>, approval_required},
        {<<"escalate">>, approval_required},
        {<<"log-only">>, log_only},
        {<<"weird">>, deny}
    ],
    lists:foreach(
        fun({Verb, Tag}) ->
            HttpFun = ok_response(#{<<"decision">> => Verb}),
            {ResultTag, _Resp} = trustforge:evaluate(Req, #{http_fun => HttpFun}),
            ResultTag = Tag
        end,
        Cases
    ),
    ok.

new_trace_id_format(_Config) ->
    TraceId = trustforge:new_trace_id(),
    true = is_binary(TraceId),
    <<"tf-", Rest/binary>> = TraceId,
    16 = byte_size(Rest),
    ok.

sends_correct_url_and_headers(_Config) ->
    Self = self(),
    HttpFun = fun(Method, Request, _HOpts, _ROpts) ->
        Self ! {captured, Method, Request},
        {ok, {{"HTTP/1.1", 200, "OK"},
              [],
              jsx:encode(#{<<"decision">> => <<"allow">>})}}
    end,

    Req = #{
        action => <<"fs.read">>,
        trace_id => <<"tf-xyz">>,
        target => <<"/etc/hosts">>,
        host_token => <<"abc.def">>,
        host_token_kind => <<"oauth-jwt">>
    },

    {ok, _Resp} = trustforge:decide(Req, #{
        daemon_url => "http://127.0.0.1:8787/",
        admin_token => <<"ADMIN">>,
        http_fun => HttpFun
    }),

    receive
        {captured, post, {Url, Headers, ContentType, Body}} ->
            "http://127.0.0.1:8787/v1/decide" = Url,
            "application/json" = ContentType,
            true = lists:member({"accept", "application/json"}, Headers),
            true = lists:member({"authorization", "Bearer ADMIN"}, Headers),
            Decoded = jsx:decode(Body, [return_maps]),
            <<"fs.read">> = maps:get(<<"action">>, Decoded),
            <<"tf-xyz">> = maps:get(<<"trace_id">>, Decoded),
            <<"oauth-jwt">> = maps:get(<<"host_token_kind">>, Decoded)
    after 1000 ->
        ct:fail("did not capture HTTP request")
    end,
    ok.
