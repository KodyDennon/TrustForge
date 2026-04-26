%% @doc TrustForge HTTP client (Erlang).
%%
%% Wire-compatible with `conformance/decide-protocol-vectors.yaml'.
%% Only `POST /v1/decide' is implemented; framework adapters compose on top.
%%
%% Uses OTP `httpc' so that no third-party HTTP client is required.

-module(trustforge).

-export([
    decide/1,
    decide/2,
    evaluate/1,
    evaluate/2,
    new_trace_id/0,
    request_to_payload/1,
    response_from_map/1,
    default_opts/0
]).

-export_type([
    decide_request/0,
    decide_response/0,
    error_info/0,
    decision_verb/0,
    opts/0
]).

-type decision_verb() ::
    allow | deny | escalate | approval_required | log_only.

-type decide_request() :: #{
    actor => binary() | undefined,
    host_token => binary() | undefined,
    host_token_kind => binary() | undefined,
    action := binary(),
    target => binary() | undefined,
    context => map(),
    trace_id := binary()
}.

-type decide_response() :: #{
    decision := binary(),
    reason := binary(),
    approval_id := binary() | undefined,
    proof_id := binary(),
    actor_resolved := binary(),
    trust_level := binary(),
    authority_mode := binary(),
    danger_tags := [binary()]
}.

-type error_info() :: #{
    type := trustforge_error,
    message := binary(),
    status := non_neg_integer(),
    body := term()
}.

-type opts() :: #{
    daemon_url => string() | binary(),
    admin_token => binary() | undefined,
    timeout_ms => non_neg_integer(),
    http_fun =>
        fun((atom(), tuple(), list(), list()) -> {ok, term()} | {error, term()})
}.

%%====================================================================
%% Public API
%%====================================================================

-spec decide(decide_request()) -> {ok, decide_response()} | {error, error_info()}.
decide(Req) -> decide(Req, #{}).

-spec decide(decide_request(), opts()) -> {ok, decide_response()} | {error, error_info()}.
decide(Req, Opts) when is_map(Req), is_map(Opts) ->
    Url = base_url(Opts) ++ "/v1/decide",
    Body = jsx:encode(request_to_payload(Req)),

    Headers0 = [{"accept", "application/json"}],
    Headers1 = case admin_token(Opts) of
        undefined -> Headers0;
        T -> [{"authorization", "Bearer " ++ binary_to_list(T)} | Headers0]
    end,

    Request = {Url, Headers1, "application/json", Body},
    HttpOpts = [
        {timeout, timeout_ms(Opts)},
        {connect_timeout, timeout_ms(Opts)}
    ],
    RequestOpts = [{body_format, binary}],
    HttpFun = http_fun(Opts),

    case HttpFun(post, Request, HttpOpts, RequestOpts) of
        {ok, {{_Vsn, Status, _Phrase}, _RespHeaders, RespBody}} when is_binary(RespBody) ->
            decode_response(Status, RespBody);
        {ok, {{_Vsn, Status, _Phrase}, _RespHeaders, RespBody}} when is_list(RespBody) ->
            decode_response(Status, list_to_binary(RespBody));
        {error, Reason} ->
            {error, #{
                type => trustforge_error,
                message => iolist_to_binary(io_lib:format("tf-daemon /v1/decide network error: ~p", [Reason])),
                status => 0,
                body => undefined
            }}
    end.

-spec evaluate(decide_request()) ->
    {decision_verb(), decide_response()} | {error, error_info()}.
evaluate(Req) -> evaluate(Req, #{}).

-spec evaluate(decide_request(), opts()) ->
    {decision_verb(), decide_response()} | {error, error_info()}.
evaluate(Req, Opts) ->
    case decide(Req, Opts) of
        {ok, #{decision := <<"allow">>} = R} -> {allow, R};
        {ok, #{decision := <<"deny">>} = R} -> {deny, R};
        {ok, #{decision := <<"approval-required">>} = R} -> {approval_required, R};
        {ok, #{decision := <<"escalate">>} = R} -> {approval_required, R};
        {ok, #{decision := <<"log-only">>} = R} -> {log_only, R};
        {ok, R} -> {deny, R};
        {error, _} = E -> E
    end.

-spec new_trace_id() -> binary().
new_trace_id() ->
    Hex = string:lowercase(binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8)))),
    list_to_binary("tf-" ++ Hex).

-spec default_opts() -> opts().
default_opts() ->
    #{
        daemon_url => application:get_env(trustforge, daemon_url, "http://127.0.0.1:8787"),
        admin_token => application:get_env(trustforge, admin_token, undefined),
        timeout_ms => application:get_env(trustforge, timeout_ms, 5000)
    }.

%%====================================================================
%% Encoding helpers (exported for adapter reuse + tests)
%%====================================================================

-spec request_to_payload(decide_request()) -> map().
request_to_payload(Req) ->
    %% Drop undefined values; preserve ordering by relying on the map shape.
    maps:fold(
        fun
            (_K, undefined, Acc) -> Acc;
            (K, V, Acc) -> Acc#{atom_key(K) => V}
        end,
        #{},
        ensure_required(Req)
    ).

-spec response_from_map(map()) -> decide_response().
response_from_map(M) when is_map(M) ->
    #{
        decision => get_bin(M, decision, <<"deny">>),
        reason => get_bin(M, reason, <<"">>),
        approval_id => maps:get(<<"approval_id">>, M, undefined),
        proof_id => get_bin(M, proof_id, <<"">>),
        actor_resolved => get_bin(M, actor_resolved, <<"">>),
        trust_level => get_bin(M, trust_level, <<"">>),
        authority_mode => get_bin(M, authority_mode, <<"layered">>),
        danger_tags => maps:get(<<"danger_tags">>, M, [])
    }.

%%====================================================================
%% Internal
%%====================================================================

base_url(Opts) ->
    Raw =
        case maps:get(daemon_url, Opts, undefined) of
            undefined ->
                application:get_env(trustforge, daemon_url, "http://127.0.0.1:8787");
            U -> U
        end,
    Str = case Raw of
        B when is_binary(B) -> binary_to_list(B);
        L when is_list(L) -> L
    end,
    string:trim(Str, trailing, "/").

admin_token(Opts) ->
    case maps:get(admin_token, Opts, undefined) of
        undefined -> application:get_env(trustforge, admin_token, undefined);
        T when is_binary(T) -> T;
        T when is_list(T) -> list_to_binary(T)
    end.

timeout_ms(Opts) ->
    case maps:get(timeout_ms, Opts, undefined) of
        undefined -> application:get_env(trustforge, timeout_ms, 5000);
        T -> T
    end.

http_fun(Opts) ->
    case maps:get(http_fun, Opts, undefined) of
        undefined ->
            fun(Method, Req, HOpts, ROpts) ->
                ensure_inets_started(),
                httpc:request(Method, Req, HOpts, ROpts)
            end;
        F when is_function(F, 4) -> F
    end.

ensure_inets_started() ->
    _ = application:ensure_all_started(inets),
    ok.

decode_response(Status, _Raw) when Status >= 400 ->
    error_for_status(Status, _Raw);
decode_response(Status, Raw) ->
    case jsx:decode(Raw, [return_maps]) of
        Map when is_map(Map) ->
            {ok, response_from_map(map_keys_to_binaries(Map))};
        _ ->
            {error, #{
                type => trustforge_error,
                message => <<"tf-daemon /v1/decide returned non-object body">>,
                status => Status,
                body => Raw
            }}
    end.

error_for_status(Status, Raw) ->
    Body =
        try jsx:decode(Raw, [return_maps])
        catch _:_ -> Raw
        end,
    {error, #{
        type => trustforge_error,
        message => iolist_to_binary(io_lib:format("tf-daemon /v1/decide returned ~w", [Status])),
        status => Status,
        body => Body
    }}.

%% Tolerate atom-keyed input from Erlang callers; convert to binary keys for jsx.
map_keys_to_binaries(M) when is_map(M) ->
    maps:fold(
        fun
            (K, V, Acc) when is_atom(K) -> Acc#{atom_to_binary(K, utf8) => V};
            (K, V, Acc) -> Acc#{K => V}
        end,
        #{},
        M
    ).

ensure_required(Req) ->
    case Req of
        #{action := A, trace_id := T} when is_binary(A), is_binary(T) -> Req;
        _ -> error({trustforge_request_missing_keys, Req})
    end.

atom_key(K) when is_atom(K) -> atom_to_binary(K, utf8);
atom_key(K) -> K.

get_bin(M, K, Default) ->
    BK = atom_to_binary(K, utf8),
    case maps:get(BK, M, undefined) of
        undefined -> Default;
        V when is_binary(V) -> V;
        V -> iolist_to_binary(io_lib:format("~p", [V]))
    end.
