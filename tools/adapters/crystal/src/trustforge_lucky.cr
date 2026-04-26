# trustforge_lucky — Lucky action helper.
#
# Lucky's action class uses `before` callbacks to short-circuit a request.
# This adapter exposes a single helper, `TrustForge::Lucky::Authorizer`,
# which evaluates a TrustForge decision and produces a structured outcome
# the action can act on.
#
# In a Lucky action you'd write:
#
#   class Refunds::Create < ApiAction
#     post "/refunds" do
#       outcome = TrustForge::Lucky.authorize(
#         client: TF_CLIENT,
#         action: "billing.refund",
#         method: request.method,
#         path: request.path,
#         authorization: request.headers["Authorization"]?,
#         remote: request.remote_address.to_s,
#         trace_header: request.headers["x-tf-trace-id"]?,
#       )
#
#       case outcome
#       when TrustForge::Lucky::Outcome::Allow
#         json({ok: true})
#       when TrustForge::Lucky::Outcome::Deny
#         response.status_code = 403
#         json({error: "denied", reason: outcome.response.reason})
#       when TrustForge::Lucky::Outcome::ApprovalRequired
#         response.headers["x-tf-approval-id"] = outcome.response.approval_id || ""
#         response.status_code = 202
#         json({status: "approval-required"})
#       when TrustForge::Lucky::Outcome::DaemonError
#         response.status_code = 503
#         json({error: "trustforge daemon error", detail: outcome.error.message})
#       end
#     end
#   end
#
# Keeping this as a value-returning function (rather than directly mutating a
# Lucky context) means we don't require Lucky as a dependency. Adopters
# typically wrap this in a base action class.

require "json"
require "./trustforge"

module TrustForge
  module Lucky
    abstract struct Outcome
      struct Allow < Outcome
        getter response : TrustForge::DecideResponse

        def initialize(@response : TrustForge::DecideResponse)
        end
      end

      struct LogOnly < Outcome
        getter response : TrustForge::DecideResponse

        def initialize(@response : TrustForge::DecideResponse)
        end
      end

      struct Deny < Outcome
        getter response : TrustForge::DecideResponse

        def initialize(@response : TrustForge::DecideResponse)
        end
      end

      struct ApprovalRequired < Outcome
        getter response : TrustForge::DecideResponse

        def initialize(@response : TrustForge::DecideResponse)
        end
      end

      struct DaemonError < Outcome
        getter error : TrustForge::Error

        def initialize(@error : TrustForge::Error)
        end
      end
    end

    # Pure helper: build a `DecideRequest` from primitive request fields and
    # invoke the supplied client.
    def self.authorize(
      *,
      client : TrustForge::Client,
      action : String,
      method : String,
      path : String,
      authorization : String? = nil,
      cookie_tf_session : String? = nil,
      remote : String? = nil,
      trace_header : String? = nil,
      target : String? = nil,
      mode : TrustForge::AdapterMode = TrustForge::AdapterMode::Enforce,
      extra_context : Hash(String, JSON::Any) = {} of String => JSON::Any
    ) : Outcome
      host_token, host_token_kind = TrustForge.extract_bearer(authorization)
      if host_token.nil? && cookie_tf_session && !cookie_tf_session.empty?
        host_token = cookie_tf_session
        host_token_kind = "session-cookie"
      end

      trace_id =
        if trace_header && !trace_header.empty?
          trace_header
        else
          TrustForge.new_trace_id
        end

      ctx = {
        "method" => JSON::Any.new(method),
        "client" => JSON::Any.new(remote || ""),
      } of String => JSON::Any
      extra_context.each { |k, v| ctx[k] = v }

      req = TrustForge::DecideRequest.new(
        action: action,
        trace_id: trace_id,
        host_token: host_token,
        host_token_kind: host_token_kind,
        target: target || path,
        context: ctx
      )

      resp =
        begin
          client.decide(req)
        rescue ex : TrustForge::Error
          if mode.observe_only?
            fallback = TrustForge::DecideResponse.from_json({
              "decision"    => "log-only",
              "reason"      => "observe-only: #{ex.message}",
              "proof_id"    => "",
              "danger_tags" => ["trustforge.daemon.error"],
            }.to_json)
            return Outcome::LogOnly.new(fallback)
          end
          return Outcome::DaemonError.new(ex)
        end

      case resp.decision
      when TrustForge::DECISION_ALLOW
        Outcome::Allow.new(resp)
      when TrustForge::DECISION_LOG_ONLY
        Outcome::LogOnly.new(resp)
      when TrustForge::DECISION_DENY
        if mode.observe_only?
          Outcome::Allow.new(resp)
        else
          Outcome::Deny.new(resp)
        end
      when TrustForge::DECISION_APPROVAL_REQUIRED, TrustForge::DECISION_ESCALATE
        if mode.observe_only?
          Outcome::Allow.new(resp)
        else
          Outcome::ApprovalRequired.new(resp)
        end
      else
        # Unknown verb -> treat as deny (fail-safe).
        Outcome::Deny.new(resp)
      end
    end
  end
end
