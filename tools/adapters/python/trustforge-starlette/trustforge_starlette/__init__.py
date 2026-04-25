"""Starlette ASGI middleware for TrustForge tf-daemon."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from trustforge_client import (
    DecideRequest,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForgeMiddleware"]


class TrustForgeMiddleware:
    """ASGI middleware that calls `/v1/decide` before each HTTP request."""

    def __init__(
        self,
        app: ASGIApp,
        daemon_url: str = "http://127.0.0.1:7616",
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
            return await self.app(scope, receive, send)

        request = Request(scope, receive)
        action = (
            request.headers.get("x-tf-action")
            or self.route_actions.get(request.url.path)
            or self.default_action
        )
        host_token = _bearer(request)
        req = DecideRequest(
            actor=None,
            host_token=host_token,
            action=action,
            target=request.url.path,
            context={"method": request.method},
            trace_id=request.headers.get(
                "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
            ),
        )
        try:
            resp = await self.client.decide(req)
        except TrustForgeError as exc:
            if self.mode == "observe-only":
                return await self.app(scope, receive, send)
            return await JSONResponse(
                {"error": "trustforge daemon error", "detail": str(exc)},
                status_code=503,
            )(scope, receive, send)

        if self.mode != "observe-only":
            if resp.decision == "deny":
                return await JSONResponse(
                    {"error": "denied", "reason": resp.reason}, status_code=403
                )(scope, receive, send)
            if resp.decision in ("approval-required", "escalate"):
                return await JSONResponse(
                    {
                        "error": "approval-required",
                        "approval_id": resp.approval_id,
                        "reason": resp.reason,
                    },
                    status_code=401,
                )(scope, receive, send)

        scope.setdefault("state", {})
        if hasattr(scope.get("state"), "__dict__") or isinstance(scope.get("state"), dict):
            try:
                scope["state"]["tf_decision"] = resp  # type: ignore[index]
            except Exception:
                pass
        await self.app(scope, receive, send)


def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.cookies.get("tf_session")
