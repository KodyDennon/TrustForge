"""Tests for trustforge_flask.TrustForge."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest
from flask import Flask, g

from trustforge_client import TrustForge as Client
from trustforge_flask import TrustForge


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


def _build_app(handler: Callable[[httpx.Request], httpx.Response], mode: str = "enforce") -> Flask:
    app = Flask(__name__)
    tf = TrustForge(
        daemon_url="http://daemon.test",
        admin_token="t",
        mode=mode,
        client=_client(handler),
        app=app,
    )

    @app.get("/files/<path:p>")
    @tf.require_cap("file.read")
    def read(p):
        return {"path": p, "decision": g.tf_decision.decision}

    return app


def test_allow_runs_view() -> None:
    seen: dict[str, Any] = {}

    def h(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    app = _build_app(h)
    c = app.test_client()
    r = c.get("/files/etc/hosts", headers={"Authorization": "Bearer host-tok"})
    assert r.status_code == 200
    assert r.json["decision"] == "allow"
    assert "host-tok" in seen["body"]


def test_deny_returns_403() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="neg-cap"))

    c = _build_app(h).test_client()
    r = c.get("/files/x")
    assert r.status_code == 403
    assert r.json["reason"] == "neg-cap"


def test_approval_required_returns_401() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required")
        body["approval_id"] = "a-7"
        return httpx.Response(200, json=body)

    c = _build_app(h).test_client()
    r = c.get("/files/x")
    assert r.status_code == 401
    assert r.json["approval_id"] == "a-7"


def test_observe_only_passes_on_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    c = _build_app(h, mode="observe-only").test_client()
    r = c.get("/files/x")
    assert r.status_code == 200
    assert r.json["decision"] == "deny"
