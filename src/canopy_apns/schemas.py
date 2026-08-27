"""The relay's wire contract.

Small on purpose.  An instance sends a device token, two lines of text and an
opaque blob; it gets back one word saying what became of it.

``extra="forbid"`` throughout: a field an instance thinks it is sending and the
relay is silently ignoring is the worst kind of bug to have between two
separately-deployed services, so an unrecognised key is a 422 with its name in
it rather than a push that quietly did something else.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from .config import MAX_BODY_LENGTH, MAX_DATA_BYTES, MAX_TITLE_LENGTH


class PushRequest(BaseModel):
    """``POST /v1/push`` — one notification for one device.

    Deliberately *not* an APNs payload.  An instance cannot set ``aps`` fields
    directly, because ``content-available`` and ``mutable-content`` are how a
    push becomes a silent background wake, and the relay operator's signing key
    is what would be authorising it.  Text in, alert out; see
    :func:`canopy_apns.apns.build_payload`.
    """

    model_config = ConfigDict(extra="forbid")

    device_token: str = Field(min_length=1, max_length=200, pattern=r"^[0-9a-fA-F]+$")
    """Hex, as Apple issues it. The relay never stores this — it is a
    parameter of the forward and is gone when the request ends."""

    environment: Literal["sandbox", "production"] = "production"
    """A property of the token, not a preference: a token minted by a
    development build only works against Apple's sandbox host. The instance
    knows which its app is; the relay has no way to tell by looking."""

    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    """The bold first line."""

    body: str | None = Field(
        default=None,
        max_length=MAX_BODY_LENGTH,
        validation_alias=AliasChoices("body", "subtitle"),
    )
    """The regular-weight second line.

    Called ``subtitle`` until it turned out that iOS bolds an alert's subtitle
    as well as its title, so every Canopy+ notification arrived as two bold
    lines while Messages and Mail put their second line in ``body`` and got
    normal weight.  The field is ``body`` now, for the APNs key it becomes.

    ``subtitle`` stays accepted as an alias rather than being removed, because
    ``extra="forbid"`` means dropping it would turn every push from a client
    that has not been redeployed yet into a 422 — and the two services deploy
    separately.  Either name sets the same field and produces the same alert.
    """

    badge: int | None = Field(default=None, ge=0)
    """The number on the app icon, or ``None`` to leave it alone.

    A badge is a count of state on the instance, not a property of this
    notification, and APNs has no increment — you send an absolute number and
    the last one wins.  So the instance computes it and the relay forwards it
    verbatim.  The relay could not compute it even if it wanted to: that would
    mean tracking a count per device, which is precisely the device→instance
    mapping the isolation model exists in order not to have.

    ``None`` and ``0`` are different and both meaningful.  ``None`` (the
    default, and what every client sending no badge at all gets) omits ``badge``
    from the payload entirely, leaving whatever the icon already showed.  ``0``
    is sent, and clears it.
    """

    data: dict[str, Any] | None = None
    """Opaque to the relay, forwarded under a ``canopy`` key for the app to
    read on tap. Size-capped so it cannot push the notification past Apple's
    4KB limit or turn the relay into a general-purpose message bus."""

    collapse_id: str | None = Field(default=None, max_length=64)
    """Apple replaces an undelivered notification with a later one carrying the
    same collapse id. Optional, and meaningful only to the instance."""

    @field_validator("data")
    @classmethod
    def _data_fits(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        try:
            encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("data must be JSON-serialisable") from exc
        if len(encoded) > MAX_DATA_BYTES:
            raise ValueError(
                f"data is {len(encoded)} bytes; the limit is {MAX_DATA_BYTES}"
            )
        return value


class PushResponse(BaseModel):
    """What became of one push.

    ``unregistered`` is the field this endpoint exists to return honestly: the
    relay stores no device tokens, so only the instance can act on a dead one,
    and it can only do that if it is told.
    """

    result: Literal["delivered", "unregistered", "failed"]
    reason: str | None = None
    """Apple's machine-readable reason, when they gave one. For the instance's
    log; nothing should branch on it beyond ``result``."""

    apns_id: str | None = None
    """Apple's id for the push, for correlating with their delivery console."""


class EnrollResponse(BaseModel):
    """``POST /v1/instances`` — a freshly issued identity.

    The only time the relay ever discloses an API key. There is no way to read
    one back afterwards, because there is nowhere it was written down: a caller
    that loses its key enrolls again and gets a new identity, which costs
    nothing but the old id lingering in a revocation list nobody will ever need
    to write.

    Takes no request body. There is nothing an enrolling instance could tell
    the relay that the relay would have any way to verify, and asking for a name
    or a URL would only create a field that lies.
    """

    instance_id: str
    """Shown in the instance's admin UI and in this relay's logs, so a support
    conversation has something to name. Not a secret."""

    api_key: str
    """Send as ``Authorization: Bearer``. Store it; it is not recoverable."""

    bundle_id: str | None = None
    """The topic this relay pushes to, so the caller can display it without a
    second round trip to ``/v1/verify``."""

    ready: bool = True
    """False when the relay has no signing key of its own yet. The enrollment
    still succeeded and the key is still good — there is simply nothing behind
    it until the operator finishes setting the relay up."""


class VerifyResponse(BaseModel):
    """``GET /v1/verify`` — what an instance's admin page needs to show.

    Answers "is my key good and is this relay actually able to send", which are
    two different failures with two different fixes and are worth separating
    before anyone goes looking for a lost notification.
    """

    ok: bool
    instance: str
    bundle_id: str | None = None
    """The topic this relay pushes to. An instance whose app has a different
    bundle id would get every push rejected by Apple, so it is worth showing."""

    ready: bool = True
    """False when the relay authenticated the key but has no signing key of its
    own — the instance is set up correctly and the relay is not."""

    rate_limit_per_minute: int = 0


class HealthResponse(BaseModel):
    """``GET /health`` — unauthenticated, and says nothing an attacker wants."""

    status: Literal["ok"] = "ok"
    apns: Literal["configured", "unconfigured"]


class ErrorResponse(BaseModel):
    """The body of every non-2xx the relay produces itself."""

    detail: str


__all__ = [
    "EnrollResponse",
    "ErrorResponse",
    "HealthResponse",
    "PushRequest",
    "PushResponse",
    "VerifyResponse",
]
