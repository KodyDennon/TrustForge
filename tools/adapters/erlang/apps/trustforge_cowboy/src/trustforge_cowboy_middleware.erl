%% @doc TrustForge cowboy middleware.
%%
%% Implements the `cowboy_middleware' behaviour. Configure inside cowboy:
%%
%%   {ok, _} = cowboy:start_clear(http_listener, [{port, 8080}], #{
%%       env => #{
%%           dispatch => Dispatch,
%%           trustforge => #{
%%               action_fun => fun route_to_action/1,
%%               %% Optional client opts:
%%               client_opts => #{daemon_url => "http://127.0.0.1:8787"},
%%               mode => enforce
%%           }
%%       },
%%       middlewares => [cowboy_router, trustforge_cowboy_middleware, cowboy_handler]
%%   }).
%%
%% Where `route_to_action/1' is a fun taking the cowboy request and returning
%% the binary action key (e.g. `<<"http.request">>'), or `skip' to bypass.
%%
%% On `allow', the request is annotated with `tf_decision' in the cowboy req
%% map and forwarded. On `deny', a `403' is sent and the middleware halts the
%% pipeline. On `approval-required', a `202' is sent. On daemon error in
%% enforce mode, a `503' is sent. In `observe-only' mode, all decisions pass
%% through but are still annotated.

-module(trustforge_cowboy_middleware).

-behaviour(cowboy_middleware).

-export([execute/2]).

-export([
    %% Helpers exposed for tests / programmatic use:
    build_request/2,
    handle_decision/3
]).

%%====================================================================
%% cowboy_middleware behaviour
%%====================================================================

execute(Req, Env) ->
    Cfg = maps:get(trustforge, Env, #{}),
    case action_for(Req, Cfg) of
        skip ->
            {ok, Req, Env};
        Action when is_binary(Action) ->
            DecideReq = build_request(Req, Action),
            ClientOpts = maps:get(client_opts, Cfg, #{}),
            DecideFun = maps:get(decide_fun, Cfg, fun trustforge:decide/2),
            handle_decision(DecideFun(DecideReq, ClientOpts), Req, Cfg)
    end.

%%====================================================================
%% Internal
%%====================================================================

action_for(Req, Cfg) ->
    case maps:get(action_fun, Cfg, undefined) of
        undefined ->
            %% Default action key is the HTTP method, lowercased.
            Method = cowboy_req:method(Req),
            <<"http.", (lowercase(Method))/binary>>;
        F when is_function(F, 1) ->
            F(Req)
    end.

lowercase(B) when is_binary(B) ->
    list_to_binary(string:lowercase(binary_to_list(B))).

%%====================================================================
%% Public helpers
%%====================================================================

build_request(Req, Action) when is_binary(Action) ->
    Method = cowboy_req:method(Req),
    Path = cowboy_req:path(Req),
    Peer = case cowboy_req:peer(Req) of
        {Ip, _Port} -> iolist_to_binary(io_lib:format("~p", [Ip]));
        _ -> <<"">>
    end,
    {HostToken, HostTokenKind} = extract_token(Req),
    TraceId =
        case cowboy_req:header(<<"x-tf-trace-id">>, Req, undefined) of
            undefined -> trustforge:new_trace_id();
            <<"">> -> trustforge:new_trace_id();
            T -> T
        end,
    #{
        action => Action,
        trace_id => TraceId,
        target => Path,
        host_token => HostToken,
        host_token_kind => HostTokenKind,
        context => #{
            <<"method">> => Method,
            <<"client">> => Peer
        }
    }.

handle_decision(Result, Req, Cfg) ->
    Reply = maps:get(reply_fun, Cfg, fun cowboy_req:reply/4),
    do_handle(Result, Req, Cfg, Reply).

do_handle({ok, #{decision := <<"allow">>} = Resp}, Req, _Cfg, _Reply) ->
    {ok, annotate(Req, Resp), env_for(Req)};
do_handle({ok, #{decision := <<"log-only">>} = Resp}, Req, _Cfg, _Reply) ->
    {ok, annotate(Req, Resp), env_for(Req)};
do_handle({ok, #{decision := <<"deny">>} = Resp}, Req, Cfg, Reply) ->
    case maps:get(mode, Cfg, enforce) of
        observe_only ->
            {ok, annotate(Req, Resp), env_for(Req)};
        _ ->
            Body = jsx:encode(#{
                <<"error">> => <<"denied">>,
                <<"reason">> => maps:get(reason, Resp, <<"">>),
                <<"proof_id">> => maps:get(proof_id, Resp, <<"">>)
            }),
            Req1 = Reply(403, json_headers(), Body, annotate(Req, Resp)),
            {stop, Req1}
    end;
do_handle({ok, #{decision := Verb} = Resp}, Req, Cfg, Reply)
    when Verb =:= <<"approval-required">> orelse Verb =:= <<"escalate">>
->
    case maps:get(mode, Cfg, enforce) of
        observe_only ->
            {ok, annotate(Req, Resp), env_for(Req)};
        _ ->
            ApprovalId = maps:get(approval_id, Resp, <<"">>),
            ApprovalIdBin =
                case ApprovalId of
                    undefined -> <<"">>;
                    Bin when is_binary(Bin) -> Bin
                end,
            Body = jsx:encode(#{
                <<"status">> => <<"approval-required">>,
                <<"approval_id">> => ApprovalIdBin,
                <<"reason">> => maps:get(reason, Resp, <<"">>)
            }),
            Headers = #{
                <<"content-type">> => <<"application/json">>,
                <<"x-tf-approval-id">> => ApprovalIdBin
            },
            Req1 = Reply(202, Headers, Body, annotate(Req, Resp)),
            {stop, Req1}
    end;
do_handle({ok, #{} = Resp}, Req, Cfg, Reply) ->
    %% Unknown verb -> deny.
    do_handle({ok, Resp#{decision => <<"deny">>}}, Req, Cfg, Reply);
do_handle({error, Err}, Req, Cfg, Reply) ->
    case maps:get(mode, Cfg, enforce) of
        observe_only ->
            Fallback = #{
                decision => <<"log-only">>,
                reason => iolist_to_binary([<<"observe-only: ">>, maps:get(message, Err, <<"">>)]),
                approval_id => undefined,
                proof_id => <<"">>,
                actor_resolved => <<"">>,
                trust_level => <<"">>,
                authority_mode => <<"layered">>,
                danger_tags => [<<"trustforge.daemon.error">>]
            },
            {ok, annotate(Req, Fallback), env_for(Req)};
        _ ->
            Body = jsx:encode(#{
                <<"error">> => <<"trustforge daemon error">>,
                <<"detail">> => maps:get(message, Err, <<"">>)
            }),
            Req1 = Reply(503, json_headers(), Body, Req),
            {stop, Req1}
    end.

%%====================================================================
%% Internal
%%====================================================================

annotate(Req, Resp) -> Req#{tf_decision => Resp}.

env_for(_Req) -> #{}.

json_headers() ->
    #{<<"content-type">> => <<"application/json">>}.

extract_token(Req) ->
    case cowboy_req:header(<<"authorization">>, Req, undefined) of
        undefined -> {undefined, undefined};
        Hdr when is_binary(Hdr) ->
            case Hdr of
                <<"Bearer ", Tok/binary>> -> {Tok, <<"bearer-opaque">>};
                <<"bearer ", Tok/binary>> -> {Tok, <<"bearer-opaque">>};
                _ -> {undefined, undefined}
            end
    end.
