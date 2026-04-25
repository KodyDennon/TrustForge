"""Pyramid tween for TrustForge tf-daemon."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Callable, Optional

from pyramid.httpexceptions import HTTPException
from pyramid.request import Request
from pyramid.response import Response

from trustforge_client import (
    DecideRequest,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["trustforge_tween_factory", "set_client_for_tests"]


_client_override: Optional[_Client] = None


def set_client_for_tests(client: _Client) -> None:
    """Override the daemon client used by the tween (test-only)."""
    global _client_override
    _client_override = client


def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.cookies.get("tf_session")


def trustforge_tween_factory(handler: Callable[[Request], Response], registry: Any) -> Callable[[Request], Response]:
    """Pyramid tween factory. Reads daemon settings from registry.settings."""

    settings = registry.settings or {}
    daemon_url = settings.get("trustforge.daemon_url", "http://127.0.0.1:7616")
    admin_token = settings.get("trustforge.admin_token")
    mode = settings.get("trustforge.mode", "enforce")
    default_action = settings.get("trustforge.action", "http.request")

    def _client() -> _Client:
        if _client_override is not None:
            return _client_override
        return _Client(daemon_url=daemon_url, admin_token=admin_token)

    def tween(request: Request) -> Response:
        action = request.headers.get("x-tf-action", default_action)
        req = DecideRequest(
            actor=None,
            host_token=_bearer(request),
            action=action,
            target=request.path,
            context={"method": request.method},
            trace_id=request.headers.get(
                "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
            ),
        )
        try:
            resp = asyncio.run(_client().decide(req))
        except TrustForgeError as exc:
            if mode == "observe-only":
                return handler(request)
            return Response(
                json_body={"error": "trustforge daemon error", "detail": str(exc)},
                status=503,
            )
        if mode != "observe-only":
            if resp.decision == "deny":
                return Response(
                    json_body={"error": "denied", "reason": resp.reason}, status=403
                )
            if resp.decision in ("approval-required", "escalate"):
                return Response(
                    json_body={
                        "error": "approval-required",
                        "approval_id": resp.approval_id,
                        "reason": resp.reason,
                    },
                    status=401,
                )
        request.tf_decision = resp  # type: ignore[attr-defined]
        return handler(request)

    return tween
