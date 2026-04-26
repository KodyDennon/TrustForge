defmodule TrustForge.PlugTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias TrustForge.{DecideResponse, Error}

  defp decide_fun(response) do
    fn _req, _opts -> {:ok, response} end
  end

  defp error_fun(err) do
    fn _req, _opts -> {:error, err} end
  end

  defp call(conn, opts) do
    init = TrustForge.Plug.init(opts)
    TrustForge.Plug.call(conn, init)
  end

  test "init/1 raises without :action" do
    assert_raise ArgumentError, fn -> TrustForge.Plug.init([]) end
  end

  test "allows on decision allow and assigns response" do
    resp = %DecideResponse{decision: "allow", proof_id: "p-1"}

    conn =
      :get
      |> conn("/health")
      |> call(action: "http.get", decide_fun: decide_fun(resp))

    refute conn.halted
    assert conn.assigns[:trustforge] == resp
    assert is_binary(conn.assigns[:trustforge_trace_id])
  end

  test "denies with 403 on decision deny" do
    resp = %DecideResponse{decision: "deny", reason: "blocked", proof_id: "p-2"}

    conn =
      :post
      |> conn("/admin", "{}")
      |> put_req_header("authorization", "Bearer abc")
      |> call(action: "admin.write", decide_fun: decide_fun(resp))

    assert conn.halted
    assert conn.status == 403
    body = Jason.decode!(conn.resp_body)
    assert body["error"] == "denied"
    assert body["reason"] == "blocked"
    assert body["proof_id"] == "p-2"
  end

  test "approval-required produces 202 with x-tf-approval-id" do
    resp = %DecideResponse{decision: "approval-required", approval_id: "appr-9"}

    conn =
      :post
      |> conn("/refund", "{}")
      |> call(action: "billing.refund", decide_fun: decide_fun(resp))

    assert conn.halted
    assert conn.status == 202
    assert get_resp_header(conn, "x-tf-approval-id") == ["appr-9"]
  end

  test "503 on daemon error in enforce mode" do
    err = %Error{message: "boom", status: 0}

    conn =
      :get
      |> conn("/x")
      |> call(action: "x", decide_fun: error_fun(err))

    assert conn.halted
    assert conn.status == 503
  end

  test "observe-only allows through on deny" do
    resp = %DecideResponse{decision: "deny", reason: "would-block"}

    conn =
      :get
      |> conn("/x")
      |> call(action: "x", mode: :observe_only, decide_fun: decide_fun(resp))

    refute conn.halted
    assert conn.assigns[:trustforge].decision == "deny"
  end

  test "observe-only allows through on daemon error" do
    err = %Error{message: "boom"}

    conn =
      :get
      |> conn("/x")
      |> call(action: "x", mode: :observe_only, decide_fun: error_fun(err))

    refute conn.halted
    assert conn.assigns[:trustforge].decision == "log-only"
    assert "trustforge.daemon.error" in conn.assigns[:trustforge].danger_tags
  end

  test "uses x-tf-trace-id when supplied" do
    resp = %DecideResponse{decision: "allow"}
    parent = self()

    decide = fn req, _opts ->
      send(parent, {:req, req})
      {:ok, resp}
    end

    :get
    |> conn("/x")
    |> put_req_header("x-tf-trace-id", "tf-fixed-123")
    |> call(action: "x", decide_fun: decide)

    assert_receive {:req, req}
    assert req.trace_id == "tf-fixed-123"
  end

  test "extracts bearer token and target" do
    resp = %DecideResponse{decision: "allow"}
    parent = self()

    decide = fn req, _opts ->
      send(parent, {:req, req})
      {:ok, resp}
    end

    :post
    |> conn("/secret/path", "{}")
    |> put_req_header("authorization", "Bearer xyz")
    |> call(action: "do", target: "/canonical", decide_fun: decide)

    assert_receive {:req, req}
    assert req.host_token == "xyz"
    assert req.host_token_kind == "bearer-opaque"
    assert req.target == "/canonical"
    assert req.context["method"] == "POST"
  end

  test "target callable resolves" do
    resp = %DecideResponse{decision: "allow"}
    parent = self()

    decide = fn req, _opts ->
      send(parent, {:req, req})
      {:ok, resp}
    end

    target_fun = fn conn -> "func:" <> conn.request_path end

    :get
    |> conn("/abc")
    |> call(action: "do", target: target_fun, decide_fun: decide)

    assert_receive {:req, req}
    assert req.target == "func:/abc"
  end

  test "on_deny callback can override behavior" do
    resp = %DecideResponse{decision: "deny", reason: "nope"}

    on_deny = fn conn, r ->
      conn
      |> Plug.Conn.put_resp_content_type("text/plain")
      |> Plug.Conn.send_resp(418, "no:" <> r.reason)
      |> Plug.Conn.halt()
    end

    conn =
      :get
      |> conn("/x")
      |> call(action: "x", decide_fun: decide_fun(resp), on_deny: on_deny)

    assert conn.halted
    assert conn.status == 418
    assert conn.resp_body == "no:nope"
  end
end
