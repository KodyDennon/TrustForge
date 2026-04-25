"""Tests for trustforge_django."""

from __future__ import annotations

import os
from typing import Any, Callable

import django
import httpx
import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
django.setup()

from django.test import RequestFactory  # noqa: E402

from trustforge_client import TrustForge as Client  # noqa: E402
from trustforge_django import _set_client  # noqa: E402
from tests.urls import read_file  # noqa: E402


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> Client:
    c = Client(
        daemon_url="http://daemon.test",
        admin_token="t",
        transport=httpx.MockTransport(handler),
    )
    _set_client(c)
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


def test_allow_runs_view() -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["body"] = req.content.decode()
        return httpx.Response(200, json=_ok("allow"))

    _client(handler)
    rf = RequestFactory()
    resp = read_file(
        rf.get("/files/etc", HTTP_AUTHORIZATION="Bearer host-tok"), path="etc"
    )
    assert resp.status_code == 200
    assert b"allow" in resp.content
    assert "host-tok" in seen["body"]


def test_deny_returns_403() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok("deny", reason="neg-cap"))

    _client(handler)
    rf = RequestFactory()
    resp = read_file(rf.get("/files/etc"), path="etc")
    assert resp.status_code == 403
    assert b"neg-cap" in resp.content


def test_approval_returns_401() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        body = _ok("approval-required")
        body["approval_id"] = "a-1"
        return httpx.Response(200, json=body)

    _client(handler)
    rf = RequestFactory()
    resp = read_file(rf.get("/files/etc"), path="etc")
    assert resp.status_code == 401
    assert b"a-1" in resp.content


def test_daemon_error_returns_503() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"err": "x"})

    _client(handler)
    rf = RequestFactory()
    resp = read_file(rf.get("/files/etc"), path="etc")
    assert resp.status_code == 503
