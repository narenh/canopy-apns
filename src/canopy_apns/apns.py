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

#: The same, for Live Activity pushes — minus ``BadDeviceToken``.  An activity
#: token is short-lived and its caller is usually juggling sandbox and
#: production builds, so a ``BadDeviceToken`` here is far more often an
#: environment mismatch than a dead token; reporting it as ``unregistered``
#: would tell the caller to delete a token that works against the other host.
LIVE_ACTIVITY_DEAD_TOKEN_REASONS = frozenset({"Unregistered", "DeviceTokenNotForTopic"})

#: Appended to the app's bundle id to form a Live Activity push's topic.
LIVE_ACTIVITY_TOPIC_SUFFIX = ".push-type.liveactivity"

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
    *,
    title: str,
    body: str | None,
    badge: int | None = None,
    data: dict[str, Any] | None,
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

    ``badge`` is tested against ``None`` rather than for truthiness, because
    ``0`` is a real instruction — it clears the icon — and a falsiness check
    would silently drop exactly the value that does the clearing.  Omitted
    entirely when ``None``, which leaves whatever the icon already showed and
    keeps the payload byte-identical to one from a client that has never heard
    of badges.

    ``data`` rides under a ``canopy`` key alongside ``aps`` rather than inside
    it — that is the documented place for app-specific fields, and it keeps a
    malformed one from being an APNs rejection.
    """
    alert: dict[str, Any] = {"title": title}
    if body:
        alert["body"] = body

    aps: dict[str, Any] = {"alert": alert, "sound": "default"}
    if badge is not None:
        # A sibling of `alert`, not a child of it. Nested inside, Apple ignores
        # it and the icon silently never changes.
        aps["badge"] = badge

    payload: dict[str, Any] = {"aps": aps}
    if data:
        payload["canopy"] = data
    return payload


def build_live_activity_payload(
    *,
    event: str,
    timestamp: int,
    content_state: dict[str, Any],
    attributes_type: str | None = None,
    attributes: dict[str, Any] | None = None,
    alert: dict[str, str] | None = None,
    stale_date: int | None = None,
    dismissal_date: int | None = None,
    relevance_score: float | None = None,
) -> dict[str, Any]:
    """The APNs JSON body for one Live Activity start, update or end.

    Unlike :func:`build_payload`, the caller's ``content_state`` and
    ``attributes`` go *inside* ``aps`` — that is where ActivityKit reads them,
    and they are decoded into the app's own ``ContentState`` and attributes
    types, so the relay cannot own their shape.  What it still owns is every
    other key: an instance cannot reach ``content-available``, ``sound`` or
    anything else through this endpoint, only the fields named here.

    The snake_case request fields become Apple's hyphenated keys.  Optional
    fields are omitted rather than sent as ``null``, which ActivityKit would
    read as a value.
    """
    aps: dict[str, Any] = {
        "timestamp": timestamp,
        "event": event,
        "content-state": content_state,
    }
    if attributes_type is not None:
        aps["attributes-type"] = attributes_type
    if attributes is not None:
        aps["attributes"] = attributes
    if alert is not None:
        aps["alert"] = alert
    if stale_date is not None:
        aps["stale-date"] = stale_date
    if dismissal_date is not None:
        aps["dismissal-date"] = dismissal_date
    if relevance_score is not None:
        aps["relevance-score"] = relevance_score
    return {"aps": aps}


def encoded_payload_size(payload: dict[str, Any]) -> int:
    """The size in bytes of ``payload`` as it goes on the wire.

    Encoded exactly as ``httpx`` encodes a ``json=`` body — compact separators,
    UTF-8 rather than ``\\u`` escapes — so the number checked against Apple's
    limit is the number Apple sees.  A test pins the two together.
    """
    return len(
        json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    )


def live_activity_topic(bundle_id: str) -> str:
    """The ``apns-topic`` for a Live Activity push to ``bundle_id``'s app."""
    return f"{bundle_id}{LIVE_ACTIVITY_TOPIC_SUFFIX}"


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
        badge: int | None = None,
        data: dict[str, Any] | None = None,
        environment: str = "production",
        collapse_id: str | None = None,
    ) -> SendResult:
        """Push one alert to one device, to the relay's own bundle id.

        What ``/v1/push`` sends, and nothing about it is the caller's choice
        beyond the text: see :func:`build_payload` for the body and
        :meth:`deliver` for the retry.
        """
        payload = build_payload(title=title, body=body, badge=badge, data=data)
        return await self.deliver(
            device_token=device_token,
            payload=payload,
            environment=environment,
            push_type="alert",
            topic=self.credentials.bundle_id,
            # 10 = deliver now. These are user-visible alerts about something
            # that just happened; there is nothing to coalesce or defer.
            priority=10,
            # 0 = do not store and retry. A notification about a request filed
            # ten minutes ago is not worth waking a phone for later.
            expiration=0,
            collapse_id=collapse_id,
        )

    async def send_live_activity(
        self,
        *,
        device_token: str,
        payload: dict[str, Any],
        bundle_id: str,
        environment: str = "production",
        priority: int = 10,
        expiration: int = 0,
    ) -> SendResult:
        """Push one Live Activity start, update or end to one token.

        ``payload`` is from :func:`build_live_activity_payload`, built by the
        caller so it can check the size first.  ``bundle_id`` names the app;
        the topic suffix is added here, so whether a caller is *allowed* that
        app is the caller's question, not this one's.
        """
        return await self.deliver(
            device_token=device_token,
            payload=payload,
            environment=environment,
            push_type="liveactivity",
            topic=live_activity_topic(bundle_id),
            priority=priority,
            expiration=expiration,
            dead_token_reasons=LIVE_ACTIVITY_DEAD_TOKEN_REASONS,
        )

    async def deliver(
        self,
        *,
        device_token: str,
        payload: dict[str, Any],
        environment: str,
        push_type: str,
        topic: str,
        priority: int,
        expiration: int,
        collapse_id: str | None = None,
        dead_token_reasons: frozenset[str] = DEAD_TOKEN_REASONS,
    ) -> SendResult:
        """Push ``payload`` to one device, retrying once where it helps.

        One retry, not a loop: the two things worth retrying are a stale
        provider token (mint a new one, try again) and Apple throttling or
        faulting (try again). Anything still failing after that is either our
        bug or Apple being down, and hammering it helps neither.
        """
        url = f"{self._host(environment)}/3/device/{device_token}"
        headers = {
            "apns-topic": topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
            "apns-expiration": str(expiration),
        }
        if collapse_id is not None:
            headers["apns-collapse-id"] = collapse_id

        result = await self._attempt(url, payload, headers, dead_token_reasons)

        should_retry = result.status_code in RETRYABLE_STATUSES or (
            result.status_code == 403 and result.reason == EXPIRED_TOKEN_REASON
        )
        if result.outcome is SendOutcome.FAILED and should_retry:
            if result.reason == EXPIRED_TOKEN_REASON:
                self._tokens.invalidate(self.credentials)
            result = await self._attempt(url, payload, headers, dead_token_reasons)

        return result

    async def _attempt(
        self,
        url: str,
        payload: dict[str, Any],
        push_headers: dict[str, str],
        dead_token_reasons: frozenset[str],
    ) -> SendResult:
        # Authorization first and re-read per attempt, so a retry after an
        # expired provider token carries the freshly minted one.
        headers = {
            "authorization": f"bearer {self._tokens.get(self.credentials)}",
            **push_headers,
        }

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
        if response.status_code == 410 or reason in dead_token_reasons:
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
    "LIVE_ACTIVITY_DEAD_TOKEN_REASONS",
    "LIVE_ACTIVITY_TOPIC_SUFFIX",
    "PRODUCTION_HOST",
    "SANDBOX_HOST",
    "ApnsClient",
    "ApnsConfigError",
    "ProviderTokenCache",
    "SendOutcome",
    "SendResult",
    "build_live_activity_payload",
    "build_payload",
    "encoded_payload_size",
    "live_activity_topic",
    "sign_provider_token",
    "validate_private_key",
]
