"""Mock-transport tests for `trustforge_client.TrustForge.decide`."""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from trustforge_client import (
    DecideRequest,
    DecideResponse,
    TrustForge,
    TrustForgeError,
)


def _mock_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _ok_response(decision: str = "allow", **extra: Any) -> dict[str, Any]:
    body = {
        "decision": decision,
        "reason": extra.get("reason", "ok"),
        "approval_id": extra.get("approval_id"),
        "proof_id": extra.get("proof_id", "p-1"),
        "actor_resolved": extra.get("actor_resolved", "tf:actor:test"),
        "trust_level": extra.get("trust_level", "T3"),
        "authority_mode": extra.get("authority_mode", "layered"),
        "danger_tags": extra.get("danger_tags", []),
    }
    return body


@pytest.mark.asyncio
async def test_decide_allow_round_trip() -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["method"] = req.method
        seen["body"] = json.loads(req.content.decode())
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json=_ok_response("allow"))

    tf = TrustForge(
        "http://daemon.test",
        admin_token="tok",
        transport=_mock_transport(handler),
    )
    resp = await tf.decide(
        DecideRequest(action="file.read", trace_id="t-1", target="/tmp/x")
    )
    assert isinstance(resp, DecideResponse)
    assert resp.decision == "allow"
    assert seen["method"] == "POST"
    assert seen["url"].endswith("/v1/decide")
    assert seen["auth"] == "Bearer tok"
    assert seen["body"]["action"] == "file.read"
    assert seen["body"]["trace_id"] == "t-1"
    # `actor` defaults to None and `host_token` is unset → both omitted
    assert "actor" not in seen["body"]
    assert "host_token" not in seen["body"]


@pytest.mark.asyncio
async def test_decide_deny() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=_ok_response("deny", reason="negative-cap")
        )

    tf = TrustForge(
        "http://daemon.test/", transport=_mock_transport(lambda r: handler(r))
    )
    resp = await tf.decide(DecideRequest(action="shell.exec", trace_id="t-2"))
    assert resp.decision == "deny"
    assert resp.reason == "negative-cap"


@pytest.mark.asyncio
async def test_decide_approval_required() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        body = _ok_response("approval-required")
        body["approval_id"] = "appr-42"
        return httpx.Response(200, json=body)

    tf = TrustForge("http://x.test", transport=_mock_transport(handler))
    resp = await tf.decide(DecideRequest(action="net.write", trace_id="t-3"))
    assert resp.decision == "approval-required"
    assert resp.approval_id == "appr-42"


@pytest.mark.asyncio
async def test_decide_500_raises() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    tf = TrustForge("http://x.test", transport=_mock_transport(handler))
    with pytest.raises(TrustForgeError) as ei:
        await tf.decide(DecideRequest(action="x.y", trace_id="t-4"))
    assert ei.value.status == 500
    assert ei.value.body == {"error": "boom"}


@pytest.mark.asyncio
async def test_decide_network_error_wrapped() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    tf = TrustForge("http://x.test", transport=_mock_transport(handler))
    with pytest.raises(TrustForgeError) as ei:
        await tf.decide(DecideRequest(action="x.y", trace_id="t-5"))
    assert ei.value.status == 0


@pytest.mark.asyncio
async def test_decide_omits_admin_token_when_unset() -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json=_ok_response("allow"))

    tf = TrustForge("http://x.test", transport=_mock_transport(handler))
    await tf.decide(DecideRequest(action="x.y", trace_id="t-6"))
    assert seen["auth"] is None
