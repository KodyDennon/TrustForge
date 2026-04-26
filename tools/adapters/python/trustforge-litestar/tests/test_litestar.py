"""Tests for trustforge_litestar.TrustforgeMiddleware."""

from __future__ import annotations

from typing import Any, Callable, Optional

import httpx
from litestar import Litestar, get
from litestar.middleware.base import DefineMiddleware
from litestar.testing import TestClient

from trustforge_client import DecideResponse, TrustForge as Client
from trustforge_litestar import TrustforgeMiddleware


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


@get("/files")
async def read_files(request: Any) -> dict[str, Any]:
    state = request.scope.get("state") or {}
    decision: Optional[DecideResponse] = (
        state.get("tf_decision") if isinstance(state, dict) else getattr(state, "tf_decision", None)
    )
    return {
        "ok": True,
        "decision": decision.decision if decision else None,
    }


def _build_app(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    mode: str = "enforce",
) -> Litestar:
    return Litestar(
        route_handlers=[read_files],
        middleware=[
            DefineMiddleware(
                TrustforgeMiddleware,
                client=_client(handler),
                mode=mode,
                route_actions={"/files": "file.read"},
            )
        ],
    )


def test_allow_runs_handler() -> None:
    seen: dict[str, Any] = {}

    def h(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    with TestClient(app=_build_app(h)) as tc:
        r = tc.get("/files", headers={"Authorization": "Bearer host-tok"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["decision"] == "allow"
    assert "host-tok" in seen["body"]
    assert "file.read" in seen["body"]


def test_deny_returns_403() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="negative-cap"))

    with TestClient(app=_build_app(h)) as tc:
        r = tc.get("/files")
    assert r.status_code == 403
    assert r.json()["error"] == "denied"
    assert r.json()["reason"] == "negative-cap"


def test_approval_required_returns_202() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required", reason="quorum")
        body["approval_id"] = "appr-9"
        return httpx.Response(200, json=body)

    with TestClient(app=_build_app(h)) as tc:
        r = tc.get("/files")
    assert r.status_code == 202
    assert r.json()["approval_id"] == "appr-9"
    assert r.json()["error"] == "approval-required"


def test_observe_only_passes_on_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    with TestClient(app=_build_app(h, mode="observe-only")) as tc:
        r = tc.get("/files")
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"


def test_daemon_error_returns_503_in_enforce_mode() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    with TestClient(app=_build_app(h)) as tc:
        r = tc.get("/files")
    assert r.status_code == 503
    assert r.json()["error"] == "trustforge daemon error"
