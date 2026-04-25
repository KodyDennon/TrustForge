"""FastAPI binding for TrustForge `/v1/decide`."""

from __future__ import annotations

import uuid
from typing import Any, Awaitable, Callable, Optional

from fastapi import HTTPException, Request
from trustforge_client import (
    DecideRequest,
    DecideResponse,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForge"]


class TrustForge:
    """FastAPI helper around `trustforge_client.TrustForge`.

    Exposes `.require(action)` which returns an async dependency suitable
    for use with `Depends(...)`.
    """

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

    def require(
        self, action: str
    ) -> Callable[[Request], Awaitable[DecideResponse]]:
        """Return an async dependency that authorises `action`."""

        async def dependency(request: Request) -> DecideResponse:
            host_token = _extract_bearer(request)
            req = DecideRequest(
                actor=None,
                host_token=host_token,
                action=action,
                target=str(request.url.path),
                context={
                    "method": request.method,
                    "client": request.client.host if request.client else "",
                },
                trace_id=request.headers.get(
                    "x-tf-trace-id", f"tf-{uuid.uuid4().hex[:16]}"
                ),
            )
            try:
                resp = await self.client.decide(req)
            except TrustForgeError as exc:
                if self.mode == "observe-only":
                    return _observe_only_fallback(action, str(exc))
                raise HTTPException(
                    status_code=503,
                    detail=f"trustforge daemon error: {exc}",
                )
            if self.mode == "observe-only":
                return resp
            if resp.decision == "deny":
                raise HTTPException(status_code=403, detail=resp.reason or "denied")
            if resp.decision in ("approval-required", "escalate"):
                raise HTTPException(
                    status_code=401,
                    detail=resp.reason or "approval required",
                    headers={"x-tf-approval-id": resp.approval_id or ""},
                )
            return resp

        dependency.__name__ = f"trustforge_require_{action.replace('.', '_')}"
        return dependency


def _extract_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    cookie = request.cookies.get("tf_session")
    return cookie or None


def _observe_only_fallback(action: str, reason: str) -> DecideResponse:
    return DecideResponse(
        decision="log-only",
        reason=f"observe-only: {reason}",
        approval_id=None,
        proof_id="",
        actor_resolved="",
        trust_level="T0",
        authority_mode="layered",
        danger_tags=[action],
    )
