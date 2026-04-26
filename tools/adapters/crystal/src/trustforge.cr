# TrustForge — Crystal client for tf-daemon's `POST /v1/decide`.
#
# Wire-compatible with the Python/TS reference clients; only `/v1/decide` is
# exposed here. Framework adapters (`trustforge_kemal`, `trustforge_lucky`)
# build on top.
#
# We use the stdlib `HTTP::Client` and `JSON::Serializable` so the shared
# client has no external shard dependencies.

require "http/client"
require "json"
require "uri"
require "random/secure"

module TrustForge
  VERSION = "0.1.0"

  # Decision verbs as returned by the daemon. Match the wire spelling exactly.
  DECISION_ALLOW             = "allow"
  DECISION_DENY              = "deny"
  DECISION_ESCALATE          = "escalate"
  DECISION_APPROVAL_REQUIRED = "approval-required"
  DECISION_LOG_ONLY          = "log-only"

  enum AdapterMode
    Enforce
    ObserveOnly
  end

  # Wire-format request for `POST /v1/decide`. Field naming follows the JSON
  # contract; we override the JSON keys with `JSON::Field`.
  class DecideRequest
    include JSON::Serializable

    @[JSON::Field(emit_null: false)]
    property actor : String?

    @[JSON::Field(key: "host_token", emit_null: false)]
    property host_token : String?

    @[JSON::Field(key: "host_token_kind", emit_null: false)]
    property host_token_kind : String?

    property action : String

    @[JSON::Field(emit_null: false)]
    property target : String?

    property context : Hash(String, JSON::Any)

    @[JSON::Field(key: "trace_id")]
    property trace_id : String

    def initialize(
      @action : String,
      @trace_id : String,
      @actor : String? = nil,
      @host_token : String? = nil,
      @host_token_kind : String? = nil,
      @target : String? = nil,
      @context : Hash(String, JSON::Any) = {} of String => JSON::Any
    )
    end
  end

  # Wire-format response from `POST /v1/decide`.
  class DecideResponse
    include JSON::Serializable

    property decision : String
    property reason : String = ""

    @[JSON::Field(key: "approval_id")]
    property approval_id : String?

    @[JSON::Field(key: "proof_id")]
    property proof_id : String = ""

    @[JSON::Field(key: "actor_resolved")]
    property actor_resolved : String = ""

    @[JSON::Field(key: "trust_level")]
    property trust_level : String = ""

    @[JSON::Field(key: "authority_mode")]
    property authority_mode : String = "layered"

    @[JSON::Field(key: "danger_tags")]
    property danger_tags : Array(String) = [] of String

    def allow?
      decision == DECISION_ALLOW
    end

    def deny?
      decision == DECISION_DENY
    end

    def approval_required?
      decision == DECISION_APPROVAL_REQUIRED || decision == DECISION_ESCALATE
    end

    def log_only?
      decision == DECISION_LOG_ONLY
    end
  end

  # Raised when tf-daemon returns a non-2xx HTTP status, or the network layer
  # fails entirely.
  class Error < Exception
    getter status : Int32
    getter body : String?

    def initialize(message : String, @status : Int32 = 0, @body : String? = nil)
      super(message)
    end
  end

  # Pluggable HTTP transport so the spec suite can stub responses without
  # opening a real socket.
  abstract class Transport
    abstract def send(
      url : String,
      method : String,
      headers : Hash(String, String),
      body : String
    ) : {Int32, String}
  end

  # Default transport using stdlib `HTTP::Client.exec`.
  class HTTPClientTransport < Transport
    def initialize(@timeout : Time::Span = 5.seconds)
    end

    def send(
      url : String,
      method : String,
      headers : Hash(String, String),
      body : String
    ) : {Int32, String}
      uri = URI.parse(url)
      http_headers = HTTP::Headers.new
      headers.each { |k, v| http_headers[k] = v }
      client = HTTP::Client.new(uri)
      client.read_timeout = @timeout
      client.connect_timeout = @timeout
      response = client.exec(method, uri.request_target, headers: http_headers, body: body)
      {response.status_code, response.body}
    rescue ex : IO::Error | Socket::Error
      raise Error.new("tf-daemon network error: #{ex.message}", 0, nil)
    end
  end

  # Async / blocking client. Crystal fibers make blocking-with-timeout the
  # natural model.
  class Client
    getter daemon_url : String
    getter admin_token : String?
    getter transport : Transport

    def initialize(
      daemon_url : String,
      @admin_token : String? = nil,
      @transport : Transport = HTTPClientTransport.new
    )
      raise ArgumentError.new("daemon_url is required") if daemon_url.empty?
      @daemon_url = daemon_url.rstrip('/')
    end

    def decide(req : DecideRequest) : DecideResponse
      url = "#{@daemon_url}/v1/decide"
      headers = {
        "content-type" => "application/json",
        "accept"       => "application/json",
      } of String => String
      if (token = @admin_token) && !token.empty?
        headers["authorization"] = "Bearer #{token}"
      end

      payload = req.to_json
      status, body = @transport.send(url, "POST", headers, payload)

      if status >= 400
        raise Error.new(
          "tf-daemon /v1/decide returned #{status}",
          status,
          body
        )
      end

      DecideResponse.from_json(body)
    rescue ex : JSON::ParseException
      raise Error.new("tf-daemon /v1/decide JSON decode failed: #{ex.message}", 0, nil)
    end

    # Returns one of `:allow`, `:deny`, `:approval_required`, `:log_only`
    # together with the parsed response. Network/daemon errors raise.
    def evaluate(req : DecideRequest) : {Symbol, DecideResponse}
      r = decide(req)
      tag =
        case r.decision
        when DECISION_ALLOW
          :allow
        when DECISION_DENY
          :deny
        when DECISION_APPROVAL_REQUIRED, DECISION_ESCALATE
          :approval_required
        when DECISION_LOG_ONLY
          :log_only
        else
          :deny
        end
      {tag, r}
    end
  end

  # Generates a `tf-` trace id for callers that don't already have one.
  def self.new_trace_id : String
    bytes = Random::Secure.random_bytes(8)
    "tf-#{bytes.hexstring}"
  end

  # Extract a bearer token from an `authorization` header value.
  def self.extract_bearer(auth_header : String?) : {String?, String?}
    return {nil, nil} unless auth_header
    lower = auth_header.downcase
    return {nil, nil} unless lower.starts_with?("bearer ")
    token = auth_header[7..-1].strip
    return {nil, nil} if token.empty?
    {token, "bearer-opaque"}
  end
end
