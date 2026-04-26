"""Tests for trustforge_bottle.TrustforgePlugin."""

from __future__ import annotations

import json
from typing import Any, Callable

import bottle
import httpx
from webtest import TestApp

from trustforge_client import TrustForge as Client
from trustforge_bottle import TrustforgePlugin


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> Client:
    return Client(
        daemon_url="http://daemon.test",
        admin_token="t",
        transport=httpx.MockTransport(handler),
    )


def _ok(decision: str = "allow", **extra: Any) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": extra.get("reason", ""),
        "approval_id": extra.get("approval_id"),
        "proof_id": "p-1",
        "actor_resolved": "tf:actor:test",
        "trust_level": "T3",
        "authority_mode": "layered",
        "danger_tags": [],
    }


def _build_app(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    mode: str = "enforce",
) -> TestApp:
    app = bottle.Bottle()
    app.install(
        TrustforgePlugin(
            daemon_url="http://daemon.test",
            admin_token="t",
            mode=mode,
            client=_client(handler),
            route_actions={"/files": "file.read"},
        )
    )

    @app.get("/files")
    def read():
        decision = getattr(bottle.request, "tf_decision", None)
        bottle.response.content_type = "application/json"
        return json.dumps(
            {
                "ok": True,
                "decision": decision.decision if decision else None,
            }
        )

    return TestApp(app)


def test_allow_runs_view() -> None:
    seen: dict[str, Any] = {}

    def h(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    tc = _build_app(h)
    r = tc.get("/files", headers={"Authorization": "Bearer host-tok"})
    assert r.status_int == 200
    body = json.loads(r.body)
    assert body["ok"] is True
    assert body["decision"] == "allow"
    assert "host-tok" in seen["body"]
    assert "file.read" in seen["body"]


def test_deny_returns_403() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="negative-cap"))

    tc = _build_app(h)
    r = tc.get("/files", expect_errors=True)
    assert r.status_int == 403
    body = json.loads(r.body)
    assert body["error"] == "denied"
    assert body["reason"] == "negative-cap"


def test_approval_required_returns_202() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required", reason="quorum")
        body["approval_id"] = "appr-9"
        return httpx.Response(200, json=body)

    tc = _build_app(h)
    r = tc.get("/files", expect_errors=True)
    assert r.status_int == 202
    body = json.loads(r.body)
    assert body["approval_id"] == "appr-9"
    assert body["error"] == "approval-required"


def test_observe_only_passes_on_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    tc = _build_app(h, mode="observe-only")
    r = tc.get("/files")
    assert r.status_int == 200
    body = json.loads(r.body)
    assert body["ok"] is True
    assert body["decision"] == "deny"


def test_daemon_error_returns_503_in_enforce_mode() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    tc = _build_app(h)
    r = tc.get("/files", expect_errors=True)
    assert r.status_int == 503
    body = json.loads(r.body)
    assert body["error"] == "trustforge daemon error"
