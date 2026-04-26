defmodule TrustForge.PhoenixTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn

  alias TrustForge.{DecideResponse, Error}

  defp decide_fun(resp), do: fn _req, _opts -> {:ok, resp} end
  defp error_fun(err), do: fn _req, _opts -> {:error, err} end

  describe "authorize/3" do
    test "returns {:ok, conn, resp} on allow" do
      resp = %DecideResponse{decision: "allow", proof_id: "p"}
      conn = conn(:get, "/refund")

      {:ok, conn_assigned, ^resp} =
        TrustForge.Phoenix.authorize(conn, "billing.refund", decide_fun: decide_fun(resp))

      assert conn_assigned.assigns[:trustforge] == resp
    end

    test "deny halts with 403" do
      resp = %DecideResponse{decision: "deny", reason: "no", proof_id: "p"}
      conn = conn(:post, "/refund")

      {:error, halted_conn} =
        TrustForge.Phoenix.authorize(conn, "x", decide_fun: decide_fun(resp))

      assert halted_conn.halted
      assert halted_conn.status == 403
    end

    test "approval-required halts with 202 + header" do
      resp = %DecideResponse{decision: "approval-required", approval_id: "appr-1"}
      conn = conn(:post, "/refund")

      {:error, halted_conn} =
        TrustForge.Phoenix.authorize(conn, "x", decide_fun: decide_fun(resp))

      assert halted_conn.halted
      assert halted_conn.status == 202
      assert get_resp_header(halted_conn, "x-tf-approval-id") == ["appr-1"]
    end

    test "daemon error halts with 503 in enforce" do
      err = %Error{message: "boom", status: 0}
      conn = conn(:get, "/x")

      {:error, halted_conn} =
        TrustForge.Phoenix.authorize(conn, "x", decide_fun: error_fun(err))

      assert halted_conn.status == 503
    end

    test "observe-only mode passes deny through" do
      resp = %DecideResponse{decision: "deny", reason: "no"}
      conn = conn(:get, "/x")

      {:ok, ok_conn, ^resp} =
        TrustForge.Phoenix.authorize(conn, "x",
          mode: :observe_only,
          decide_fun: decide_fun(resp)
        )

      refute ok_conn.halted
      assert ok_conn.assigns[:trustforge] == resp
    end
  end

  describe "controller_plug/1" do
    test "uses :phoenix_action and prefix to build action key" do
      resp = %DecideResponse{decision: "allow"}
      parent = self()

      decide = fn req, _opts ->
        send(parent, {:req, req})
        {:ok, resp}
      end

      conn =
        :get
        |> conn("/posts")
        |> Plug.Conn.put_private(:phoenix_action, :index)

      {mod, fun, [prefix, pass_through]} =
        TrustForge.Phoenix.controller_plug(action_prefix: "blog.", decide_fun: decide)

      out = apply(mod, fun, [conn, [], prefix, pass_through])
      refute out.halted
      assert_receive {:req, req}
      assert req.action == "blog.index"
    end

    test "missing :phoenix_action falls back to 'request'" do
      resp = %DecideResponse{decision: "allow"}
      parent = self()

      decide = fn req, _opts ->
        send(parent, {:req, req})
        {:ok, resp}
      end

      conn = conn(:get, "/")

      {mod, fun, [prefix, pass_through]} =
        TrustForge.Phoenix.controller_plug(action_prefix: "p.", decide_fun: decide)

      apply(mod, fun, [conn, [], prefix, pass_through])
      assert_receive {:req, req}
      assert req.action == "p.request"
    end
  end

  describe "channel_authorize/3" do
    test "allow returns {:ok, resp}" do
      resp = %DecideResponse{decision: "allow"}
      socket = %{assigns: %{tf_host_token: "abc", tf_trace_id: "tf-fixed"}}

      assert {:ok, ^resp} =
               TrustForge.Phoenix.channel_authorize(socket, "ch.join",
                 decide_fun: decide_fun(resp)
               )
    end

    test "deny returns {:error, reason}" do
      resp = %DecideResponse{decision: "deny", reason: "blocked"}
      socket = %{assigns: %{}}

      assert {:error, "blocked"} =
               TrustForge.Phoenix.channel_authorize(socket, "ch.join",
                 decide_fun: decide_fun(resp)
               )
    end

    test "approval-required returns {:error, 'approval-required'}" do
      resp = %DecideResponse{decision: "approval-required"}
      socket = %{assigns: %{}}

      assert {:error, "approval-required"} =
               TrustForge.Phoenix.channel_authorize(socket, "ch.join",
                 decide_fun: decide_fun(resp)
               )
    end

    test "daemon error surfaces" do
      err = %Error{message: "boom"}
      socket = %{assigns: %{}}

      assert {:error, msg} =
               TrustForge.Phoenix.channel_authorize(socket, "ch.join",
                 decide_fun: error_fun(err)
               )

      assert msg =~ "trustforge daemon error"
    end
  end
end
