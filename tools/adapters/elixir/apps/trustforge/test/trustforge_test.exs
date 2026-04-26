defmodule TrustForgeTest do
  use ExUnit.Case, async: true

  alias TrustForge.{DecideRequest, DecideResponse, Error}

  defp ok(body, status \\ 200) do
    fn :post, _request, _http_opts, _request_opts ->
      {:ok, {{~c"HTTP/1.1", status, ~c"OK"}, [], Jason.encode!(body)}}
    end
  end

  defp http_error(reason) do
    fn :post, _request, _http_opts, _request_opts -> {:error, reason} end
  end

  defp capture(parent) do
    fn :post, request, _http_opts, _request_opts ->
      send(parent, {:request, request})

      {:ok,
       {{~c"HTTP/1.1", 200, ~c"OK"},
        [],
        Jason.encode!(%{
          "decision" => "allow",
          "proof_id" => "p-1",
          "danger_tags" => []
        })}}
    end
  end

  test "decide/2 returns parsed response on 200" do
    req = %DecideRequest{action: "fs.read", trace_id: "tf-abc"}

    body = %{
      "decision" => "allow",
      "reason" => "ok",
      "proof_id" => "proof-001",
      "actor_resolved" => "tf:actor:user:alice",
      "trust_level" => "T3",
      "authority_mode" => "layered",
      "danger_tags" => ["fs"]
    }

    assert {:ok, %DecideResponse{decision: "allow", proof_id: "proof-001", danger_tags: ["fs"]}} =
             TrustForge.decide(req, http_fun: ok(body))
  end

  test "decide/2 maps 4xx to Error" do
    req = %DecideRequest{action: "fs.read", trace_id: "tf-abc"}

    fun = ok(%{"decision" => "deny", "reason" => "bad"}, 403)

    assert {:error, %Error{status: 403, message: msg}} =
             TrustForge.decide(req, http_fun: fun)

    assert msg =~ "403"
  end

  test "decide/2 maps network errors to Error with status 0" do
    req = %DecideRequest{action: "fs.read", trace_id: "tf-abc"}

    assert {:error, %Error{status: 0, message: msg}} =
             TrustForge.decide(req, http_fun: http_error(:nxdomain))

    assert msg =~ "network error"
  end

  test "decide/2 sends correctly shaped JSON and headers" do
    req = %DecideRequest{
      action: "fs.read",
      trace_id: "tf-xyz",
      target: "/etc/hosts",
      host_token: "abc.def.ghi",
      host_token_kind: "oauth-jwt"
    }

    {:ok, _} =
      TrustForge.decide(req,
        admin_token: "ADMIN",
        daemon_url: "http://127.0.0.1:8787/",
        http_fun: capture(self())
      )

    assert_receive {:request, {url, headers, content_type, body}}
    assert to_string(url) == "http://127.0.0.1:8787/v1/decide"
    assert content_type == ~c"application/json"

    flat_headers = for {k, v} <- headers, do: {to_string(k), to_string(v)}
    assert {"accept", "application/json"} in flat_headers
    assert {"authorization", "Bearer ADMIN"} in flat_headers

    decoded = Jason.decode!(body)
    assert decoded["action"] == "fs.read"
    assert decoded["trace_id"] == "tf-xyz"
    assert decoded["target"] == "/etc/hosts"
    assert decoded["host_token"] == "abc.def.ghi"
    assert decoded["host_token_kind"] == "oauth-jwt"
    refute Map.has_key?(decoded, "actor")
  end

  test "evaluate/2 maps each decision verb" do
    req = %DecideRequest{action: "x", trace_id: "tf-1"}

    cases = [
      {"allow", :allow},
      {"deny", :deny},
      {"approval-required", :approval_required},
      {"escalate", :approval_required},
      {"log-only", :log_only}
    ]

    for {verb, tag} <- cases do
      fun = ok(%{"decision" => verb, "proof_id" => "p"})
      assert {^tag, %DecideResponse{decision: ^verb}} = TrustForge.evaluate(req, http_fun: fun)
    end
  end

  test "evaluate/2 surfaces unknown decision verbs as deny" do
    req = %DecideRequest{action: "x", trace_id: "tf-1"}
    fun = ok(%{"decision" => "magic", "proof_id" => "p"})
    assert {:deny, %DecideResponse{decision: "magic"}} = TrustForge.evaluate(req, http_fun: fun)
  end

  test "DecideRequest.to_payload drops nils and empty defaults" do
    req = %DecideRequest{action: "x", trace_id: "tf-1"}
    payload = DecideRequest.to_payload(req)
    assert payload == %{action: "x", trace_id: "tf-1", context: %{}}
  end

  test "new_trace_id/0 produces a tf- prefixed id" do
    assert "tf-" <> rest = TrustForge.new_trace_id()
    assert byte_size(rest) == 16
  end
end
