"""trustforge-client — async HTTP client for tf-daemon's `/v1/decide`.

The wire contract MUST stay byte-compatible with
`conformance/decide-protocol-vectors.yaml` and the TS SDK in
`tools/adapters/ts/sdk/`. Field names, casing and required-ness are pinned.
"""

from __future__ import annotations

from typing import Any, Literal, Mapping, Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "TrustForge",
    "TrustForgeError",
    "DecideRequest",
    "DecideResponse",
    "AdapterMode",
    "DecisionVerb",
    "AuthorityMode",
    "HostTokenKind",
]

AdapterMode = Literal["enforce", "observe-only"]
DecisionVerb = Literal[
    "allow", "deny", "escalate", "approval-required", "log-only"
]
AuthorityMode = Literal["layered", "co-equal", "replace"]
HostTokenKind = Literal[
    "auto",
    "oauth-jwt",
    "clerk-session",
    "next-auth-jwt",
    "better-auth-session",
    "webauthn-assertion",
    "mtls-cert-pem",
    "spiffe-svid",
    "session-cookie",
    "bearer-opaque",
]


class DecideRequest(BaseModel):
    """Wire-format request for `POST /v1/decide`."""

    model_config = ConfigDict(extra="forbid")

    actor: Optional[str] = None
    host_token: Optional[str] = None
    host_token_kind: Optional[HostTokenKind] = None
    action: str
    target: Optional[str] = None
    context: dict[str, Any] = Field(default_factory=dict)
    trace_id: str


class DecideResponse(BaseModel):
    """Wire-format response from `POST /v1/decide`."""

    model_config = ConfigDict(extra="ignore")

    decision: DecisionVerb
    reason: str = ""
    approval_id: Optional[str] = None
    proof_id: str = ""
    actor_resolved: str = ""
    trust_level: str = ""
    authority_mode: AuthorityMode = "layered"
    danger_tags: list[str] = Field(default_factory=list)


class TrustForgeError(RuntimeError):
    """Raised when tf-daemon returns a non-2xx HTTP status."""

    def __init__(self, message: str, status: int, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class TrustForge:
    """Thin async client over the tf-daemon HTTP API.

    Only `/v1/decide` is implemented in the shared client; framework adapters
    only need that endpoint. Other endpoints (proofs, credentials) are added
    on demand.
    """

    def __init__(
        self,
        daemon_url: str,
        admin_token: Optional[str] = None,
        *,
        timeout: float = 5.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not daemon_url:
            raise ValueError("TrustForge: daemon_url is required")
        self.daemon_url = daemon_url.rstrip("/")
        self.admin_token = admin_token
        self.timeout = timeout
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self.admin_token:
            headers["authorization"] = f"Bearer {self.admin_token}"
        return httpx.AsyncClient(
            base_url=self.daemon_url,
            headers=headers,
            timeout=self.timeout,
            transport=self._transport,
        )

    async def decide(self, req: DecideRequest) -> DecideResponse:
        """POST /v1/decide. Returns parsed `DecideResponse`."""
        payload = req.model_dump(exclude_none=True, mode="json")
        async with self._client() as client:
            try:
                resp = await client.post("/v1/decide", json=payload)
            except httpx.HTTPError as exc:
                raise TrustForgeError(
                    f"tf-daemon /v1/decide network error: {exc}", 0, None
                ) from exc
        body: Any
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        if resp.status_code >= 400:
            raise TrustForgeError(
                f"tf-daemon /v1/decide returned {resp.status_code}",
                resp.status_code,
                body,
            )
        if not isinstance(body, Mapping):
            raise TrustForgeError(
                "tf-daemon /v1/decide returned non-object body",
                resp.status_code,
                body,
            )
        return DecideResponse.model_validate(body)
