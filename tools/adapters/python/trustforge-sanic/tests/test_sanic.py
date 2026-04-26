"""Tests for trustforge_sanic middleware."""

from __future__ import annotations

import uuid
from typing import Any, Callable

import httpx
import pytest
from sanic import Sanic
from sanic.response import json as sanic_json

from trustforge_client import TrustForge as Client
from trustforge_sanic import attach_trustforge


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
) -> Sanic:
    # Sanic requires unique app names; use a uuid suffix.
    app = Sanic(f"tf-test-{uuid.uuid4().hex[:8]}")
    attach_trustforge(
        app,
        daemon_url="http://daemon.test",
        admin_token="t",
        mode=mode,
        client=_client(handler),
        route_actions={"/files": "file.read"},
    )

    @app.get("/files")
    async def read(request):
        decision = getattr(request.ctx, "tf_decision", None)
        return sanic_json(
            {
                "ok": True,
                "decision": decision.decision if decision else None,
            }
        )

    return app


def test_allow_runs_handler() -> None:
    seen: dict[str, Any] = {}

    def h(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    app = _build_app(h)
    _, response = app.test_client.get(
        "/files", headers={"Authorization": "Bearer host-tok"}
    )
    assert response.status == 200
    assert response.json["ok"] is True
    assert response.json["decision"] == "allow"
    assert "host-tok" in seen["body"]
    assert "file.read" in seen["body"]


def test_deny_returns_403() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="negative-cap"))

    app = _build_app(h)
    _, response = app.test_client.get("/files")
    assert response.status == 403
    assert response.json["error"] == "denied"
    assert response.json["reason"] == "negative-cap"


def test_approval_required_returns_202() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required", reason="quorum")
        body["approval_id"] = "appr-9"
        return httpx.Response(200, json=body)

    app = _build_app(h)
    _, response = app.test_client.get("/files")
    assert response.status == 202
    assert response.json["approval_id"] == "appr-9"
    assert response.json["error"] == "approval-required"


def test_observe_only_passes_on_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    app = _build_app(h, mode="observe-only")
    _, response = app.test_client.get("/files")
    assert response.status == 200
    assert response.json["ok"] is True
    # observe-only attaches the (deny) decision so handlers can inspect it
    assert response.json["decision"] == "deny"


def test_daemon_error_returns_503_in_enforce_mode() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    app = _build_app(h)
    _, response = app.test_client.get("/files")
    assert response.status == 503
    assert response.json["error"] == "trustforge daemon error"
