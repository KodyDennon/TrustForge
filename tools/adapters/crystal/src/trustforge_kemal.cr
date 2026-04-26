# trustforge_kemal — middleware for Kemal-style apps.
#
# Kemal exposes `add_handler` which accepts any `HTTP::Handler`. We ship a
# plain stdlib `HTTP::Handler` so this is both a Kemal adapter and a generic
# `HTTP::Server` middleware in one shot.
#
# Usage in a Kemal app:
#
#   require "trustforge_kemal"
#
#   client = TrustForge::Client.new("http://127.0.0.1:8787")
#   add_handler TrustForge::Kemal::Middleware.new(client, action: "http.request")
#
# To read back the decision in a downstream handler, pass an `on_decision`
# callback:
#
#   add_handler TrustForge::Kemal::Middleware.new(
#     client,
#     action: "http.request",
#     on_decision: ->(ctx : HTTP::Server::Context, r : TrustForge::DecideResponse) {
#       ctx.response.headers["x-tf-proof-id"] = r.proof_id
#     }
#   )

require "http/server/handler"
require "json"
require "./trustforge"

module TrustForge
  module Kemal
    class Middleware
      include HTTP::Handler

      alias ActionResolver = Proc(HTTP::Server::Context, String)
      alias DecisionCallback = Proc(HTTP::Server::Context, TrustForge::DecideResponse, Nil)

      def initialize(
        @client : TrustForge::Client,
        action : String | ActionResolver,
        @mode : TrustForge::AdapterMode = TrustForge::AdapterMode::Enforce,
        @on_decision : DecisionCallback? = nil
      )
        @action_resolver =
          case action
          when String
            literal = action.as(String)
            ActionResolver.new { |_ctx| literal }
          else
            action.as(ActionResolver)
          end
      end

      def call(context : HTTP::Server::Context)
        trace_id = trace_id_for(context)
        host_token, host_token_kind = TrustForge.extract_bearer(
          context.request.headers["authorization"]?
        )

        if host_token.nil?
          if cookie = context.request.cookies["tf_session"]?
            value = cookie.value
            unless value.empty?
              host_token = value
              host_token_kind = "session-cookie"
            end
          end
        end

        ctx_map = {
          "method" => JSON::Any.new(context.request.method),
          "client" => JSON::Any.new(context.request.remote_address.to_s),
        } of String => JSON::Any

        req = TrustForge::DecideRequest.new(
          action: @action_resolver.call(context),
          trace_id: trace_id,
          host_token: host_token,
          host_token_kind: host_token_kind,
          target: context.request.path,
          context: ctx_map
        )

        resp =
          begin
            @client.decide(req)
          rescue ex : TrustForge::Error
            return handle_daemon_error(context, ex)
          end

        handle_decision(context, resp)
      end

      private def trace_id_for(context : HTTP::Server::Context) : String
        if header = context.request.headers["x-tf-trace-id"]?
          return header unless header.empty?
        end
        TrustForge.new_trace_id
      end

      private def handle_decision(context : HTTP::Server::Context, resp : TrustForge::DecideResponse)
        notify(context, resp)
        case resp.decision
        when TrustForge::DECISION_ALLOW, TrustForge::DECISION_LOG_ONLY
          call_next(context)
        when TrustForge::DECISION_DENY
          if @mode.observe_only?
            call_next(context)
          else
            write_json(context, 403, {
              "error"    => "denied",
              "reason"   => resp.reason,
              "proof_id" => resp.proof_id,
            })
          end
        when TrustForge::DECISION_APPROVAL_REQUIRED, TrustForge::DECISION_ESCALATE
          if @mode.observe_only?
            call_next(context)
          else
            context.response.headers["x-tf-approval-id"] = resp.approval_id || ""
            write_json(context, 202, {
              "status"      => "approval-required",
              "approval_id" => resp.approval_id || "",
              "reason"      => resp.reason,
            })
          end
        else
          write_json(context, 403, {
            "error"  => "unknown decision",
            "reason" => resp.reason,
          })
        end
      end

      private def handle_daemon_error(context : HTTP::Server::Context, err : TrustForge::Error)
        if @mode.observe_only?
          fallback = TrustForge::DecideResponse.from_json({
            "decision"    => "log-only",
            "reason"      => "observe-only: #{err.message}",
            "proof_id"    => "",
            "danger_tags" => ["trustforge.daemon.error"],
          }.to_json)
          notify(context, fallback)
          call_next(context)
        else
          write_json(context, 503, {
            "error"  => "trustforge daemon error",
            "detail" => err.message,
          })
        end
      end

      private def notify(context : HTTP::Server::Context, resp : TrustForge::DecideResponse)
        cb = @on_decision
        cb.call(context, resp) if cb
      end

      private def write_json(context : HTTP::Server::Context, status : Int32, body)
        context.response.status_code = status
        context.response.headers["content-type"] = "application/json"
        context.response.print(body.to_json)
      end
    end
  end
end
