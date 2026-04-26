require "spec"
require "json"
require "http/server"
require "http/server/handler"
require "../src/trustforge"
require "../src/trustforge_kemal"
require "../src/trustforge_lucky"

# A `TrustForge::Transport` that records the last request and returns
# user-controlled `(status, body)` pairs in order. Spec suites use this to
# avoid hitting real sockets.
class StubTransport < TrustForge::Transport
  property captured_url : String?
  property captured_method : String?
  property captured_headers : Hash(String, String) = {} of String => String
  property captured_body : String?

  @responses : Array({Int32, String})
  @raise_error : TrustForge::Error?

  def initialize(@responses : Array({Int32, String}) = [] of {Int32, String})
  end

  def with_error(err : TrustForge::Error) : self
    @raise_error = err
    self
  end

  def send(
    url : String,
    method : String,
    headers : Hash(String, String),
    body : String
  ) : {Int32, String}
    @captured_url = url
    @captured_method = method
    @captured_headers = headers
    @captured_body = body
    if err = @raise_error
      raise err
    end
    raise TrustForge::Error.new("no responses queued") if @responses.empty?
    @responses.shift
  end

  def self.json(obj, status : Int32 = 200)
    new(responses: [{status, obj.to_json}])
  end
end

# Fake `HTTP::Server::Context` builder for Kemal-middleware specs. We use a
# real `HTTP::Server::Context` instance backed by a `IO::Memory` response and
# a synthesized `HTTP::Request`.
def build_context(
  method : String = "GET",
  path : String = "/",
  headers : Hash(String, String) = {} of String => String
) : {HTTP::Server::Context, IO::Memory}
  http_headers = HTTP::Headers.new
  headers.each { |k, v| http_headers[k] = v }
  request = HTTP::Request.new(method, path, http_headers)
  # `remote_address` defaults to nil on synthesized requests, which is fine —
  # the middleware tolerates a nil remote and writes "" into the context map.

  io = IO::Memory.new
  response = HTTP::Server::Response.new(io)
  context = HTTP::Server::Context.new(request, response)
  {context, io}
end
