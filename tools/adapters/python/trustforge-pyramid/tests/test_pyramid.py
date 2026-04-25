"""Tests for trustforge_pyramid."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest
from pyramid.config import Configurator
from pyramid.response import Response
from webtest import TestApp

from trustforge_client import TrustForge as Client
from trustforge_pyramid import set_client_for_tests


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> Client:
    c = Client(
        daemon_url="http://daemon.test",
        admin_token="t",
        transport=httpx.MockTransport(handler),
    )
    set_client_for_tests(c)
    return c


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


def _build(handler: Callable[[httpx.Request], httpx.Response]) -> TestApp:
    _client(handler)

    def view(request):
        return Response(json_body={"ok": True})

    cfg = Configurator(settings={"trustforge.daemon_url": "http://daemon.test"})
    cfg.add_route("hello", "/files")
    cfg.add_view(view, route_name="hello")
    cfg.add_tween("trustforge_pyramid.trustforge_tween_factory")
    return TestApp(cfg.make_wsgi_app())


def test_allow() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("allow"))

    app = _build(h)
    r = app.get("/files", headers={"Authorization": "Bearer host-tok"})
    assert r.status_code == 200
    assert r.json == {"ok": True}


def test_deny() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="x"))

    r = _build(h).get("/files", expect_errors=True)
    assert r.status_code == 403


def test_approval() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required")
        body["approval_id"] = "a-1"
        return httpx.Response(200, json=body)

    r = _build(h).get("/files", expect_errors=True)
    assert r.status_code == 401
    assert r.json["approval_id"] == "a-1"
