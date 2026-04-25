"""Tests for trustforge_starlette.TrustForgeMiddleware."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from trustforge_client import TrustForge as Client
from trustforge_starlette import TrustForgeMiddleware


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


def _build_app(handler: Callable[[httpx.Request], httpx.Response]) -> Starlette:
    async def hello(request: Any) -> JSONResponse:
        return JSONResponse({"ok": True})

    return Starlette(
        middleware=[
            Middleware(
                TrustForgeMiddleware,
                client=_client(handler),
                route_actions={"/files": "file.read"},
            )
        ],
        routes=[Route("/files", hello)],
    )


@pytest.mark.asyncio
async def test_allow() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("allow"))

    app = _build_app(h)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://app.test"
    ) as ac:
        r = await ac.get("/files", headers={"Authorization": "Bearer x"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


@pytest.mark.asyncio
async def test_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="np"))

    app = _build_app(h)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://app.test"
    ) as ac:
        r = await ac.get("/files")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_approval() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required")
        body["approval_id"] = "a-1"
        return httpx.Response(200, json=body)

    app = _build_app(h)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://app.test"
    ) as ac:
        r = await ac.get("/files")
    assert r.status_code == 401
    assert r.json()["approval_id"] == "a-1"
