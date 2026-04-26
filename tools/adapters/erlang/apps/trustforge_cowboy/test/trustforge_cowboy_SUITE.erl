-module(trustforge_cowboy_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    build_request_extracts_fields/1,
    allow_passes_through/1,
    deny_replies_403/1,
    approval_required_replies_202/1,
    daemon_error_replies_503/1,
    observe_only_passes_deny_through/1,
    execute_uses_action_fun/1
]).

all() ->
    [
        build_request_extracts_fields,
        allow_passes_through,
        deny_replies_403,
        approval_required_replies_202,
        daemon_error_replies_503,
        observe_only_passes_deny_through,
        execute_uses_action_fun
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(jsx),
    {ok, _} = application:ensure_all_started(cowlib),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Helpers
%%====================================================================

%% Build a fake cowboy req map. cowboy_req's accessors read from these fields.
fake_req() -> fake_req(#{}).
fake_req(Overrides) ->
    Default = #{
        method => <<"GET">>,
        path => <<"/refund">>,
        peer => {{127, 0, 0, 1}, 60000},
        headers => #{},
        version => 'HTTP/1.1',
        scheme => <<"http">>,
        host => <<"localhost">>,
        port => 80,
        qs => <<"">>,
        bindings => #{},
        ref => fake_listener,
        pid => self(),
        streamid => 1
    },
    maps:merge(Default, Overrides).

capture_reply(Self) ->
    fun(Status, Headers, Body, Req) ->
        Self ! {reply, Status, Headers, Body},
        Req
    end.

%%====================================================================
%% Cases
%%====================================================================

build_request_extracts_fields(_Config) ->
    Req = fake_req(#{
        method => <<"POST">>,
        path => <<"/refund/42">>,
        headers => #{
            <<"authorization">> => <<"Bearer abc123">>,
            <<"x-tf-trace-id">> => <<"tf-fixed">>
        }
    }),

    DReq = trustforge_cowboy_middleware:build_request(Req, <<"billing.refund">>),
    <<"billing.refund">> = maps:get(action, DReq),
    <<"tf-fixed">> = maps:get(trace_id, DReq),
    <<"/refund/42">> = maps:get(target, DReq),
    <<"abc123">> = maps:get(host_token, DReq),
    <<"bearer-opaque">> = maps:get(host_token_kind, DReq),
    Ctx = maps:get(context, DReq),
    <<"POST">> = maps:get(<<"method">>, Ctx),
    ok.

allow_passes_through(_Config) ->
    Self = self(),
    Cfg = #{reply_fun => capture_reply(Self)},
    Req = fake_req(),
    Resp = #{decision => <<"allow">>, proof_id => <<"p">>},
    {ok, NewReq, _Env} = trustforge_cowboy_middleware:handle_decision({ok, Resp}, Req, Cfg),
    Resp = maps:get(tf_decision, NewReq),
    ok.

deny_replies_403(_Config) ->
    Self = self(),
    Cfg = #{reply_fun => capture_reply(Self)},
    Req = fake_req(),
    Resp = #{decision => <<"deny">>, reason => <<"blocked">>, proof_id => <<"p">>},
    {stop, _Req1} = trustforge_cowboy_middleware:handle_decision({ok, Resp}, Req, Cfg),
    receive
        {reply, 403, _Headers, Body} ->
            Decoded = jsx:decode(Body, [return_maps]),
            <<"denied">> = maps:get(<<"error">>, Decoded),
            <<"blocked">> = maps:get(<<"reason">>, Decoded)
    after 1000 ->
        ct:fail("did not capture reply")
    end,
    ok.

approval_required_replies_202(_Config) ->
    Self = self(),
    Cfg = #{reply_fun => capture_reply(Self)},
    Req = fake_req(),
    Resp = #{
        decision => <<"approval-required">>,
        approval_id => <<"appr-7">>,
        reason => <<"please confirm">>
    },
    {stop, _} = trustforge_cowboy_middleware:handle_decision({ok, Resp}, Req, Cfg),
    receive
        {reply, 202, Headers, Body} ->
            <<"appr-7">> = maps:get(<<"x-tf-approval-id">>, Headers),
            Decoded = jsx:decode(Body, [return_maps]),
            <<"approval-required">> = maps:get(<<"status">>, Decoded),
            <<"appr-7">> = maps:get(<<"approval_id">>, Decoded)
    after 1000 ->
        ct:fail("did not capture reply")
    end,
    ok.

daemon_error_replies_503(_Config) ->
    Self = self(),
    Cfg = #{reply_fun => capture_reply(Self)},
    Req = fake_req(),
    Err = #{type => trustforge_error, message => <<"boom">>, status => 0, body => undefined},
    {stop, _} = trustforge_cowboy_middleware:handle_decision({error, Err}, Req, Cfg),
    receive
        {reply, 503, _Headers, Body} ->
            Decoded = jsx:decode(Body, [return_maps]),
            <<"trustforge daemon error">> = maps:get(<<"error">>, Decoded)
    after 1000 ->
        ct:fail("did not capture reply")
    end,
    ok.

observe_only_passes_deny_through(_Config) ->
    Self = self(),
    Cfg = #{reply_fun => capture_reply(Self), mode => observe_only},
    Req = fake_req(),
    Resp = #{decision => <<"deny">>, reason => <<"would-block">>},
    {ok, NewReq, _Env} = trustforge_cowboy_middleware:handle_decision({ok, Resp}, Req, Cfg),
    Resp = maps:get(tf_decision, NewReq),
    %% No reply_fun should have been called.
    receive
        {reply, _, _, _} -> ct:fail("observe-only mode should not have replied")
    after 100 -> ok
    end,
    ok.

execute_uses_action_fun(_Config) ->
    Self = self(),
    DecideFun = fun(DReq, _Opts) ->
        Self ! {decide_called, DReq},
        {ok, #{decision => <<"allow">>}}
    end,
    ActionFun = fun(R) ->
        <<"POST">> = cowboy_req:method(R),
        <<"custom.action">>
    end,
    Cfg = #{
        action_fun => ActionFun,
        decide_fun => DecideFun,
        reply_fun => capture_reply(Self)
    },
    Env = #{trustforge => Cfg},
    Req = fake_req(#{method => <<"POST">>}),
    {ok, _NewReq, _NewEnv} = trustforge_cowboy_middleware:execute(Req, Env),
    receive
        {decide_called, DReq} ->
            <<"custom.action">> = maps:get(action, DReq)
    after 1000 ->
        ct:fail("decide not invoked")
    end,
    ok.
