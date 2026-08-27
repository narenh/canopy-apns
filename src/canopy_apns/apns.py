"""Talking to Apple: provider-token signing and the HTTP/2 push.

Provider *tokens*, not certificates: a single ``.p8`` signing key plus a team
id and a key id, from which a short-lived ES256 JWT is minted and sent as a
bearer token on every push.  That is Apple's current scheme and the reason
nothing here deals in client certificates or a TLS keypair.

Three things about APNs shape this module:

* **It is HTTP/2 only.**  A plain HTTP/1.1 client gets a protocol error, not a
  helpful message, so the client is created with ``http2=True``.
* **The provider token is reusable and rate-limited.**  Apple refuses a token
  minted more than once in 20 minutes and rejects one older than an hour, so it
  must be cached across pushes rather than signed per request — see
  :class:`ProviderTokenCache`.
* **A 410 is a fact, not an error.**  It means the app is gone from that device
  and the token will never work again.  The relay does not store device tokens
  and so cannot act on that itself; it reports it back to the instance, which
  can, as its own outcome rather than folded in with failures.

Nothing here knows about instances, API keys or rate limits.  It is handed
credentials and a device token and reports what happened.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from .config import ApnsCredentials

logger = logging.getLogger(__name__)

PRODUCTION_HOST = "https://api.push.apple.com"
SANDBOX_HOST = "https://api.sandbox.push.apple.com"

#: Apple rejects a provider token older than one hour and refuses to mint a new
#: one more often than every 20 minutes.  Renewing at 45 leaves room on both
#: sides: comfortably inside the hour, comfortably past the 20-minute floor.
PROVIDER_TOKEN_LIFETIME_SECONDS = 45 * 60

#: Reasons that mean "this device token is dead, stop using it".  Apple returns
#: ``Unregistered`` with 410 for an uninstalled app and ``BadDeviceToken`` with
#: 400 for one that was never valid for this topic (commonly a sandbox token
#: sent to production).  Both are permanent for the token as presented.
DEAD_TOKEN_REASONS = frozenset({"Unregistered", "BadDeviceToken", "DeviceTokenNotForTopic"})

#: Statuses worth one more attempt.  429 is Apple throttling, 500 and 503 are
#: Apple having a bad moment; everything else is a request we got wrong and
#: would get wrong again.
RETRYABLE_STATUSES = frozenset({429, 500, 503})

#: Signed with a stale provider token — the one 403 that is worth retrying,
#: after minting a fresh one.
EXPIRED_TOKEN_REASON = "ExpiredProviderToken"


class ApnsConfigError(Exception):
    """The configured signing key is missing or unusable.

    Raised when the ``.p8`` will not parse or is not an elliptic-curve key.
    The expected cause is the wrong file in the environment variable, so the
    message is written to be read by whoever set it.
    """


class SendOutcome(StrEnum):
    """What became of one push."""

    DELIVERED = "delivered"

    UNREGISTERED = "unregistered"
    """Apple says this device token is dead. The instance should delete it."""

    FAILED = "failed"


@dataclass(frozen=True)
class SendResult:
    """The outcome of one push, with enough detail to log it usefully."""

    outcome: SendOutcome
    status_code: int | None = None
    reason: str | None = None
    """Apple's own machine-readable reason string, when it gave one."""

    apns_id: str | None = None
    """Apple's id for the push, for correlating with their delivery console."""

    @property
    def delivered(self) -> bool:
        return self.outcome is SendOutcome.DELIVERED


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _load_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """Parse a ``.p8`` into a signing key, with a message an operator can act on."""
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise ApnsConfigError(
            "The APNs key could not be read. CANOPY_APNS_PRIVATE_KEY must hold "
            "the contents of the .p8 file, including the BEGIN and END lines "
            "(escaped newlines and base64 of the whole file are also accepted)."
        ) from exc

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ApnsConfigError(
            "The APNs key is not an elliptic-curve key. Apple's push keys are "
            "ES256 .p8 files — this looks like a different kind of key."
        )
    return key


def validate_private_key(pem: str) -> None:
    """Raise :class:`ApnsConfigError` unless ``pem`` is a usable ES256 key.

    Called at startup so a mis-pasted environment variable is one line in the
    deployment log rather than something discovered later as notifications
    quietly not arriving.
    """
    _load_key(pem)


def sign_provider_token(
    credentials: ApnsCredentials, *, issued_at: int | None = None
) -> str:
    """Mint one ES256 provider token (a JWT) for ``credentials``.

    Hand-rolled rather than pulled from a JWT library because the whole of it
    is two base64url segments and a signature, and because ES256 has one trap
    worth being explicit about: ``cryptography`` signs to a DER structure,
    while JWS wants the raw ``r || s`` pair, fixed-width. Emitting the DER
    bytes straight into the token produces something that looks like a JWT and
    that Apple rejects as malformed.
    """
    now = int(time.time()) if issued_at is None else issued_at
    header = {"alg": "ES256", "kid": credentials.key_id}
    claims = {"iss": credentials.team_id, "iat": now}

    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = ".".join(segments).encode("ascii")

    key = _load_key(credentials.private_key_pem)
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    # P-256: each half is exactly 32 bytes, left-padded. Trimming a leading
    # zero here is what makes an occasional token fail and the rest work.
    size = (key.curve.key_size + 7) // 8
    signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")

    segments.append(_b64url(signature))
    return ".".join(segments)


class ProviderTokenCache:
    """One cached provider token, renewed on a timer.

    Apple treats a provider token as a reusable bearer credential and will
    refuse to mint them faster than one per 20 minutes, so signing per push is
    not merely wasteful — it earns a ``TooManyProviderTokenUpdates``.  Since
    the relay signs every instance's pushes with the same key, this cache is
    shared across all of them, which is exactly what keeps a hundred instances
    from looking to Apple like a hundred token mints.

    Keyed by credential all the same, so that a key swap takes effect on the
    next push rather than at the end of the current token's life.
    """

    def __init__(self) -> None:
        self._tokens: dict[tuple[str, str, str], tuple[str, float]] = {}

    @staticmethod
    def _key(credentials: ApnsCredentials) -> tuple[str, str, str]:
        return (credentials.team_id, credentials.key_id, credentials.private_key_pem)

    def get(self, credentials: ApnsCredentials, *, now: float | None = None) -> str:
        """The current token for ``credentials``, minting one if it has aged out."""
        moment = time.time() if now is None else now
        cache_key = self._key(credentials)

        cached = self._tokens.get(cache_key)
        if cached is not None:
            token, issued_at = cached
            if moment - issued_at < PROVIDER_TOKEN_LIFETIME_SECONDS:
                return token

        token = sign_provider_token(credentials, issued_at=int(moment))
        self._tokens[cache_key] = (token, moment)
        return token

    def invalidate(self, credentials: ApnsCredentials) -> None:
        """Drop the cached token, so the next push signs a fresh one.

        Called when Apple says the token expired — which can happen despite the
        timer if the process was suspended, or the clock moved.
        """
        self._tokens.pop(self._key(credentials), None)


def build_payload(
    *, title: str, body: str | None, data: dict[str, Any] | None
) -> dict[str, Any]:
    """The APNs JSON body for one notification.

    The relay builds this rather than forwarding whatever an instance sent, so
    that no instance can reach into ``aps`` and set ``content-available``,
    ``mutable-content`` or a background push type using the relay operator's
    signing key.  An instance supplies text and its own opaque ``data``; the
    shape around them is not negotiable.

    The second line goes in ``body``, not ``subtitle``.  iOS renders an alert's
    title *and* subtitle in bold and only ``body`` in regular weight, so a
    notification built from title+subtitle arrives as two bold lines and reads
    as shouting next to every other app on the lock screen — Messages, Mail and
    the rest all put the sender in ``title`` and the content in ``body``.
    ``subtitle`` is for a middle line between the two, which the relay's
    two-line contract has no use for.

    ``data`` rides under a ``canopy`` key alongside ``aps`` rather than inside
    it — that is the documented place for app-specific fields, and it keeps a
    malformed one from being an APNs rejection.
    """
    alert: dict[str, Any] = {"title": title}
    if body:
        alert["body"] = body

    payload: dict[str, Any] = {"aps": {"alert": alert, "sound": "default"}}
    if data:
        payload["canopy"] = data
    return payload


class ApnsClient:
    """Sends one notification to one device token.

    Deliberately not a fan-out: the relay is a per-push forwarder, the calling
    instance owns the device list, and a per-device outcome is the only thing
    APNs gives back anyway.
    """

    def __init__(
        self,
        credentials: ApnsCredentials,
        *,
        client: httpx.AsyncClient,
        tokens: ProviderTokenCache,
        production_host: str = PRODUCTION_HOST,
        sandbox_host: str = SANDBOX_HOST,
    ) -> None:
        self.credentials = credentials
        self._client = client
        self._tokens = tokens
        self._production_host = production_host
        self._sandbox_host = sandbox_host

    def _host(self, environment: str) -> str:
        return self._sandbox_host if environment == "sandbox" else self._production_host

    async def send(
        self,
        *,
        device_token: str,
        title: str,
        body: str | None = None,
        data: dict[str, Any] | None = None,
        environment: str = "production",
        collapse_id: str | None = None,
    ) -> SendResult:
        """Push to one device, retrying once where it helps.

        One retry, not a loop: the two things worth retrying are a stale
        provider token (mint a new one, try again) and Apple throttling or
        faulting (try again). Anything still failing after that is either our
        bug or Apple being down, and hammering it helps neither.
        """
        payload = build_payload(title=title, body=body, data=data)
        url = f"{self._host(environment)}/3/device/{device_token}"

        result = await self._attempt(url, payload, collapse_id=collapse_id)

        should_retry = result.status_code in RETRYABLE_STATUSES or (
            result.status_code == 403 and result.reason == EXPIRED_TOKEN_REASON
        )
        if result.outcome is SendOutcome.FAILED and should_retry:
            if result.reason == EXPIRED_TOKEN_REASON:
                self._tokens.invalidate(self.credentials)
            result = await self._attempt(url, payload, collapse_id=collapse_id)

        return result

    async def _attempt(
        self, url: str, payload: dict[str, Any], *, collapse_id: str | None
    ) -> SendResult:
        headers = {
            "authorization": f"bearer {self._tokens.get(self.credentials)}",
            "apns-topic": self.credentials.bundle_id,
            "apns-push-type": "alert",
            # 10 = deliver now. These are user-visible alerts about something
            # that just happened; there is nothing to coalesce or defer.
            "apns-priority": "10",
            # 0 = do not store and retry. A notification about a request filed
            # ten minutes ago is not worth waking a phone for later.
            "apns-expiration": "0",
        }
        if collapse_id is not None:
            headers["apns-collapse-id"] = collapse_id

        try:
            response = await self._client.post(url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("APNs request failed: %s", exc)
            return SendResult(outcome=SendOutcome.FAILED, reason=str(exc))

        apns_id = response.headers.get("apns-id")
        if response.status_code == 200:
            return SendResult(
                outcome=SendOutcome.DELIVERED, status_code=200, apns_id=apns_id
            )

        reason = _reason_of(response)
        if response.status_code == 410 or reason in DEAD_TOKEN_REASONS:
            return SendResult(
                outcome=SendOutcome.UNREGISTERED,
                status_code=response.status_code,
                reason=reason,
                apns_id=apns_id,
            )

        logger.warning(
            "APNs rejected a push: status=%s reason=%s", response.status_code, reason
        )
        return SendResult(
            outcome=SendOutcome.FAILED,
            status_code=response.status_code,
            reason=reason,
            apns_id=apns_id,
        )


def _reason_of(response: httpx.Response) -> str | None:
    """Apple's ``reason`` string, if the error body was the JSON they document."""
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        reason = body.get("reason")
        if isinstance(reason, str):
            return reason
    return None


__all__ = [
    "PRODUCTION_HOST",
    "SANDBOX_HOST",
    "ApnsClient",
    "ApnsConfigError",
    "ProviderTokenCache",
    "SendOutcome",
    "SendResult",
    "build_payload",
    "sign_provider_token",
    "validate_private_key",
]
