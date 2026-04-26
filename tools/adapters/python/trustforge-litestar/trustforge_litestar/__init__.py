"""Litestar integration for TrustForge tf-daemon.

Provides:

- `TrustforgeMiddleware`: an ASGI middleware (`MiddlewareProtocol`) that calls
  `/v1/decide` before each HTTP request reaches a route handler. On `allow` it
  stores the resolved `DecideResponse` in `scope["state"]["tf_decision"]` so it
  can be injected into handlers via `provide_tf_decision`. On `deny` it
  returns 403 JSON; on `approval-required` it returns 202 JSON.
- `provide_tf_decision`: a DI provider that pulls `tf_decision` out of the
  ASGI scope state.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from litestar.connection import Request
from litestar.middleware.base import MiddlewareProtocol
from litestar.types import ASGIApp, Message, Receive, Scope, Send

from trustforge_client import (
    DecideRequest,
    DecideResponse,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustforgeMiddleware", "provide_tf_decision"]


def _bearer(headers: dict[str, str], cookies: dict[str, str]) -> Optional[str]:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return cookies.get("tf_session")


async def _send_json(send: Send, status: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload, "more_body": False})


class TrustforgeMiddleware(MiddlewareProtocol):
    """ASGI middleware that authorises every HTTP request against tf-daemon."""

    __slots__ = (
        "app",
        "client",
        "mode",
        "route_actions",
        "default_action",
    )

    def __init__(
        self,
        app: ASGIApp,
        daemon_url: str = "http://127.0.0.1:8787",
        admin_token: Optional[str] = None,
        *,
        mode: str = "enforce",
        timeout: float = 5.0,
        route_actions: Optional[dict[str, str]] = None,
        default_action: str = "http.request",
        client: Optional[_Client] = None,
    ) -> None:
        self.app = app
        self.mode = mode
        self.route_actions = route_actions or {}
        self.default_action = default_action
        self.client = client or _Client(
            daemon_url=daemon_url, admin_token=admin_token, timeout=timeout
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request: Request[Any, Any, Any] = Request(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cookies = dict(request.cookies)

        action = (
            headers.get("x-tf-action")
            or self.route_actions.get(scope.get("path", ""))
            or self.default_action
        )
        req = DecideRequest(
            actor=None,
            host_token=_bearer(headers, cookies),
            action=action,
            target=scope.get("path", ""),
            context={"method": scope.get("method", "")},
            trace_id=headers.get(
                "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
            ),
        )

        try:
            resp = await self.client.decide(req)
        except TrustForgeError as exc:
            if self.mode == "observe-only":
                _set_state(scope, "tf_decision", None)
                await self.app(scope, receive, send)
                return
            await _send_json(
                send,
                503,
                {"error": "trustforge daemon error", "detail": str(exc)},
            )
            return

        if self.mode != "observe-only":
            if resp.decision == "deny":
                await _send_json(
                    send,
                    403,
                    {"error": "denied", "reason": resp.reason},
                )
                return
            if resp.decision in ("approval-required", "escalate"):
                await _send_json(
                    send,
                    202,
                    {
                        "error": "approval-required",
                        "approval_id": resp.approval_id,
                        "reason": resp.reason,
                    },
                )
                return

        _set_state(scope, "tf_decision", resp)
        await self.app(scope, receive, send)


def _set_state(scope: Scope, key: str, value: Any) -> None:
    state = scope.setdefault("state", {})
    try:
        if isinstance(state, dict):
            state[key] = value
        else:
            setattr(state, key, value)
    except Exception:
        pass


async def provide_tf_decision(scope: Scope) -> Optional[DecideResponse]:
    """Litestar DI provider returning the cached `DecideResponse`, if any."""
    state = scope.get("state") if isinstance(scope, dict) else None
    if isinstance(state, dict):
        return state.get("tf_decision")
    return getattr(state, "tf_decision", None)
