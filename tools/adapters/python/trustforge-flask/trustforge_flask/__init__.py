"""Flask extension for TrustForge tf-daemon."""

from __future__ import annotations

import asyncio
import uuid
from functools import wraps
from typing import Any, Callable, Optional

from flask import Flask, g, jsonify, request

from trustforge_client import (
    DecideRequest,
    DecideResponse,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForge"]


class TrustForge:
    """Flask extension wrapping `trustforge_client.TrustForge`."""

    def __init__(
        self,
        daemon_url: str,
        admin_token: Optional[str] = None,
        *,
        mode: str = "enforce",
        timeout: float = 5.0,
        client: Optional[_Client] = None,
        app: Optional[Flask] = None,
    ) -> None:
        self.mode = mode
        self.client = client or _Client(
            daemon_url=daemon_url, admin_token=admin_token, timeout=timeout
        )
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.extensions = getattr(app, "extensions", {})
        app.extensions["trustforge"] = self

    def require_cap(self, action: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that authorises `action` against tf-daemon."""

        def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                req = DecideRequest(
                    actor=None,
                    host_token=_bearer(),
                    action=action,
                    target=request.path,
                    context={"method": request.method},
                    trace_id=request.headers.get(
                        "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
                    ),
                )
                try:
                    resp = asyncio.run(self.client.decide(req))
                except TrustForgeError as exc:
                    if self.mode == "observe-only":
                        g.tf_decision = None
                        return view(*args, **kwargs)
                    return jsonify(
                        {"error": "trustforge daemon error", "detail": str(exc)}
                    ), 503
                if self.mode != "observe-only":
                    if resp.decision == "deny":
                        return jsonify({"error": "denied", "reason": resp.reason}), 403
                    if resp.decision in ("approval-required", "escalate"):
                        return (
                            jsonify(
                                {
                                    "error": "approval-required",
                                    "approval_id": resp.approval_id,
                                    "reason": resp.reason,
                                }
                            ),
                            401,
                        )
                g.tf_decision = resp
                return view(*args, **kwargs)

            return wrapper

        return decorator


def _bearer() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.cookies.get("tf_session")
