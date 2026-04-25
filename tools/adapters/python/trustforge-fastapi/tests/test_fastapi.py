"""Tests for trustforge_fastapi.TrustForge.require dependency."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest
from fastapi import Depends, FastAPI

from trustforge_client import TrustForge as Client
from trustforge_fastapi import TrustForge


def _mock(handler: Callable[[httpx.Request], httpx.Response]) -> Client:
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


def _build_app(client: Client, mode: str = "enforce") -> FastAPI:
    tf = TrustForge(
        daemon_url="http://daemon.test", admin_token="t", mode=mode, client=client
    )
    app = FastAPI()

    @app.get("/files/{path:path}")
    async def read(path: str, decision=Depends(tf.require("file.read"))):
        return {"path": path, "decision": decision.decision}

    return app


@pytest.mark.asyncio
async def test_allow_invokes_handler() -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    app = _build_app(_mock(handler))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://app.test"
    ) as ac:
        resp = await ac.get(
            "/files/etc/hosts", headers={"authorization": "Bearer host-tok"}
        )
    assert resp.status_code == 200
    assert resp.json() == {"path": "etc/hosts", "decision": "allow"}
    assert "host-tok" in seen["body"]


@pytest.mark.asyncio
async def test_deny_returns_403() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="negative-cap"))

    app = _build_app(_mock(handler))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://app.test"
    ) as ac:
        resp = await ac.get("/files/secret")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "negative-cap"


@pytest.mark.asyncio
async def test_approval_required_returns_401() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required", reason="quorum")
        body["approval_id"] = "appr-9"
        return httpx.Response(200, json=body)

    app = _build_app(_mock(handler))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://app.test"
    ) as ac:
        resp = await ac.get("/files/x")
    assert resp.status_code == 401
    assert resp.headers["x-tf-approval-id"] == "appr-9"


@pytest.mark.asyncio
async def test_observe_only_passes_on_deny() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    app = _build_app(_mock(handler), mode="observe-only")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://app.test"
    ) as ac:
        resp = await ac.get("/files/x")
    # observe-only forwards through and the route handler runs
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"
