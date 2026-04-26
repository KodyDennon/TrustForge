"""Bottle plugin for TrustForge tf-daemon.

Bottle is a synchronous WSGI framework. The plugin calls the async daemon
client via `asyncio.run` per request. It implements the Bottle Plugin API
(api=2) — `setup`, `apply`, `close` — so it can be installed via
`app.install(TrustforgePlugin(...))`.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from functools import wraps
from typing import Any, Callable, Optional

import bottle

from trustforge_client import (
    DecideRequest,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustforgePlugin"]


class TrustforgePlugin:
    """Bottle plugin (api=2) that authorises every route via tf-daemon."""

    api = 2
    name = "trustforge"

    def __init__(
        self,
        daemon_url: str = "http://127.0.0.1:8787",
        admin_token: Optional[str] = None,
        *,
        mode: str = "enforce",
        timeout: float = 5.0,
        route_actions: Optional[dict[str, str]] = None,
        default_action: str = "http.request",
        client: Optional[_Client] = None,
    ) -> None:
        self.mode = mode
        self.route_actions = route_actions or {}
        self.default_action = default_action
        self.client = client or _Client(
            daemon_url=daemon_url, admin_token=admin_token, timeout=timeout
        )
        self._app: Optional[bottle.Bottle] = None

    def setup(self, app: bottle.Bottle) -> None:
        """Called by Bottle when the plugin is installed onto an `app`.

        Detects duplicate installs by checking other plugins on the app.
        """
        for other in app.plugins:
            if other is self:
                continue
            if isinstance(other, TrustforgePlugin):
                raise bottle.PluginError(
                    "Found another TrustforgePlugin already installed"
                )
        self._app = app

    def apply(self, callback: Callable[..., Any], route: Any) -> Callable[..., Any]:
        """Wrap each route callback with a synchronous /v1/decide check."""

        @wraps(callback)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            request = bottle.request
            response = bottle.response

            action = (
                request.headers.get("X-TF-Action")
                or self.route_actions.get(request.path)
                or self.default_action
            )
            req = DecideRequest(
                actor=None,
                host_token=_bearer(request),
                action=action,
                target=request.path,
                context={"method": request.method or ""},
                trace_id=request.headers.get(
                    "X-TF-Trace-Id", f"tf-{uuid.uuid4().hex[:16]}"
                ),
            )

            try:
                resp = asyncio.run(self.client.decide(req))
            except TrustForgeError as exc:
                if self.mode == "observe-only":
                    setattr(request, "tf_decision", None)
                    return callback(*args, **kwargs)
                return _json_response(
                    response,
                    503,
                    {"error": "trustforge daemon error", "detail": str(exc)},
                )

            if self.mode != "observe-only":
                if resp.decision == "deny":
                    return _json_response(
                        response,
                        403,
                        {"error": "denied", "reason": resp.reason},
                    )
                if resp.decision in ("approval-required", "escalate"):
                    return _json_response(
                        response,
                        202,
                        {
                            "error": "approval-required",
                            "approval_id": resp.approval_id,
                            "reason": resp.reason,
                        },
                    )

            setattr(request, "tf_decision", resp)
            return callback(*args, **kwargs)

        return wrapper

    def close(self) -> None:
        """Called by Bottle when the plugin is uninstalled."""
        self._app = None


def _bearer(request: bottle.BaseRequest) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.cookies.get("tf_session")


def _json_response(response: bottle.BaseResponse, status: int, body: dict[str, Any]) -> str:
    response.status = status
    response.content_type = "application/json"
    return json.dumps(body)
