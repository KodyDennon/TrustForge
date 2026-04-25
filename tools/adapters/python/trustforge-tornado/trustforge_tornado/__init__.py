"""Tornado integration for TrustForge tf-daemon."""

from __future__ import annotations

import json
import uuid
from functools import wraps
from typing import Any, Awaitable, Callable, Optional

from tornado.web import RequestHandler

from trustforge_client import (
    DecideRequest,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForge"]


class TrustForge:
    """Tornado helper that exposes a `.require(action)` method decorator."""

    def __init__(
        self,
        daemon_url: str,
        admin_token: Optional[str] = None,
        *,
        mode: str = "enforce",
        timeout: float = 5.0,
        client: Optional[_Client] = None,
    ) -> None:
        self.mode = mode
        self.client = client or _Client(
            daemon_url=daemon_url, admin_token=admin_token, timeout=timeout
        )

    def require(self, action: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Decorator for `RequestHandler` async methods."""

        def decorator(method: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            @wraps(method)
            async def wrapper(self_h: RequestHandler, *args: Any, **kwargs: Any) -> Any:
                req = DecideRequest(
                    actor=None,
                    host_token=_bearer(self_h),
                    action=action,
                    target=self_h.request.path,
                    context={"method": self_h.request.method or ""},
                    trace_id=self_h.request.headers.get(
                        "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
                    ),
                )
                try:
                    resp = await self.client.decide(req)
                except TrustForgeError as exc:
                    if self.mode == "observe-only":
                        return await method(self_h, *args, **kwargs)
                    self_h.set_status(503)
                    self_h.set_header("content-type", "application/json")
                    self_h.write(json.dumps({"error": "trustforge daemon error", "detail": str(exc)}))
                    return
                if self.mode != "observe-only":
                    if resp.decision == "deny":
                        self_h.set_status(403)
                        self_h.set_header("content-type", "application/json")
                        self_h.write(json.dumps({"error": "denied", "reason": resp.reason}))
                        return
                    if resp.decision in ("approval-required", "escalate"):
                        self_h.set_status(401)
                        self_h.set_header("content-type", "application/json")
                        self_h.write(
                            json.dumps(
                                {
                                    "error": "approval-required",
                                    "approval_id": resp.approval_id,
                                    "reason": resp.reason,
                                }
                            )
                        )
                        return
                self_h.tf_decision = resp  # type: ignore[attr-defined]
                return await method(self_h, *args, **kwargs)

            return wrapper

        return decorator


def _bearer(handler: RequestHandler) -> Optional[str]:
    auth = handler.request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return handler.get_cookie("tf_session")
