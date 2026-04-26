"""Sanic integration for TrustForge tf-daemon.

Registers a `request` middleware that calls `/v1/decide` before each handler
runs. On `allow`, attaches the resolved `DecideResponse` to
`request.ctx.tf_decision` and lets the handler run. On `deny`, returns a 403
JSON response. On `approval-required` / `escalate`, returns a 202 JSON
response. When the daemon is unreachable and mode is `observe-only`, the
request continues with `request.ctx.tf_decision = None`.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sanic import Sanic
from sanic.request import Request
from sanic.response import HTTPResponse, json

from trustforge_client import (
    DecideRequest,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForge", "attach_trustforge"]


class TrustForge:
    """Sanic helper around `trustforge_client.TrustForge`.

    Use `.attach(app)` (or the module-level `attach_trustforge` shortcut) to
    register the request middleware on a Sanic app.
    """

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

    def attach(self, app: Sanic) -> None:
        """Register the `request` middleware on `app`."""

        async def decide(request: Request) -> Optional[HTTPResponse]:
            action = (
                request.headers.get("x-tf-action")
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
                    "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
                ),
            )
            try:
                resp = await self.client.decide(req)
            except TrustForgeError as exc:
                if self.mode == "observe-only":
                    request.ctx.tf_decision = None
                    return None
                return json(
                    {"error": "trustforge daemon error", "detail": str(exc)},
                    status=503,
                )

            if self.mode != "observe-only":
                if resp.decision == "deny":
                    return json(
                        {"error": "denied", "reason": resp.reason},
                        status=403,
                    )
                if resp.decision in ("approval-required", "escalate"):
                    return json(
                        {
                            "error": "approval-required",
                            "approval_id": resp.approval_id,
                            "reason": resp.reason,
                        },
                        status=202,
                    )

            request.ctx.tf_decision = resp
            return None

        app.register_middleware(decide, attach_to="request")


def attach_trustforge(
    app: Sanic,
    daemon_url: str = "http://127.0.0.1:8787",
    admin_token: Optional[str] = None,
    *,
    mode: str = "enforce",
    timeout: float = 5.0,
    route_actions: Optional[dict[str, str]] = None,
    default_action: str = "http.request",
    client: Optional[_Client] = None,
) -> TrustForge:
    """Convenience: build a `TrustForge` and register its middleware on `app`."""
    tf = TrustForge(
        daemon_url=daemon_url,
        admin_token=admin_token,
        mode=mode,
        timeout=timeout,
        route_actions=route_actions,
        default_action=default_action,
        client=client,
    )
    tf.attach(app)
    return tf


def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.cookies.get("tf_session")
