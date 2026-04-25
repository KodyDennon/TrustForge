"""Tests for trustforge_tornado."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest
import tornado.testing
import tornado.web

from trustforge_client import TrustForge as Client
from trustforge_tornado import TrustForge


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


def _make_app(daemon_handler: Callable[[httpx.Request], httpx.Response]) -> tornado.web.Application:
    tf = TrustForge(
        daemon_url="http://daemon.test", client=_client(daemon_handler)
    )

    class FilesHandler(tornado.web.RequestHandler):
        @tf.require("file.read")
        async def get(self):
            self.write({"ok": True})

    return tornado.web.Application([(r"/files", FilesHandler)])


class TestAllow(tornado.testing.AsyncHTTPTestCase):
    def get_app(self):
        def h(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_ok("allow"))

        return _make_app(h)

    def test_allow(self):
        r = self.fetch("/files", headers={"Authorization": "Bearer host-tok"})
        assert r.code == 200
        assert b'"ok": true' in r.body


class TestDeny(tornado.testing.AsyncHTTPTestCase):
    def get_app(self):
        def h(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_ok("deny", reason="np"))

        return _make_app(h)

    def test_deny(self):
        r = self.fetch("/files")
        assert r.code == 403


class TestApproval(tornado.testing.AsyncHTTPTestCase):
    def get_app(self):
        def h(req: httpx.Request) -> httpx.Response:
            body = _ok("approval-required")
            body["approval_id"] = "a-1"
            return httpx.Response(200, json=body)

        return _make_app(h)

    def test_approval(self):
        r = self.fetch("/files")
        assert r.code == 401
        assert b"a-1" in r.body
