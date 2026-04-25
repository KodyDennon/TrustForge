"""Django integration for TrustForge tf-daemon."""

from __future__ import annotations

import asyncio
import uuid
from functools import wraps
from typing import Any, Callable, Optional

from asgiref.sync import async_to_sync
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from trustforge_client import (
    DecideRequest,
    DecideResponse,
    TrustForge as _Client,
    TrustForgeError,
)

__all__ = ["TrustForgeMiddleware", "require_capability", "get_client"]


_client: Optional[_Client] = None


def get_client() -> _Client:
    """Return a process-wide tf-daemon client built from `settings.TRUSTFORGE`."""
    global _client
    if _client is not None:
        return _client
    cfg = getattr(settings, "TRUSTFORGE", {}) or {}
    daemon_url = cfg.get("daemon_url", "http://127.0.0.1:7616")
    admin_token = cfg.get("admin_token")
    timeout = float(cfg.get("timeout", 5.0))
    transport = cfg.get("transport")  # tests inject httpx.MockTransport
    _client = _Client(
        daemon_url=daemon_url,
        admin_token=admin_token,
        timeout=timeout,
        transport=transport,
    )
    return _client


def _set_client(client: _Client) -> None:
    """Override the cached client (used by tests)."""
    global _client
    _client = client


def _mode() -> str:
    return getattr(settings, "TRUSTFORGE", {}).get("mode", "enforce")


def _bearer(request: HttpRequest) -> Optional[str]:
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.COOKIES.get("tf_session")


async def _decide(action: str, request: HttpRequest) -> DecideResponse:
    req = DecideRequest(
        actor=None,
        host_token=_bearer(request),
        action=action,
        target=request.path,
        context={"method": request.method},
        trace_id=request.META.get(
            "HTTP_X_TF_TRACE_ID", f"tf-{uuid.uuid4().hex[:16]}"
        ),
    )
    return await get_client().decide(req)


class TrustForgeMiddleware:
    """Tags `request.tf_action` and resolves a decision when it is set.

    By default the middleware is a no-op unless the view sets `tf_action`
    via the `@require_capability` decorator. This keeps it safe to install
    globally without breaking unrelated routes.
    """

    sync_capable = True
    async_capable = False

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        return self.get_response(request)


def require_capability(action: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """View decorator that authorises `action` against tf-daemon."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            try:
                resp = async_to_sync(_decide)(action, request)
            except TrustForgeError as exc:
                if _mode() == "observe-only":
                    request.tf_decision = None  # type: ignore[attr-defined]
                    return view(request, *args, **kwargs)
                return JsonResponse(
                    {"error": "trustforge daemon error", "detail": str(exc)},
                    status=503,
                )
            if _mode() != "observe-only":
                if resp.decision == "deny":
                    return JsonResponse(
                        {"error": "denied", "reason": resp.reason}, status=403
                    )
                if resp.decision in ("approval-required", "escalate"):
                    return JsonResponse(
                        {
                            "error": "approval-required",
                            "approval_id": resp.approval_id,
                            "reason": resp.reason,
                        },
                        status=401,
                    )
            request.tf_decision = resp  # type: ignore[attr-defined]
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
