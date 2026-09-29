"""The relay application.

Four endpoints and no database.  The whole of the service is: check the API
key, spend a rate-limit token, build an alert payload, sign a JWT, POST it to
Apple, report what happened.

The one thing worth stating loudly, because the whole isolation story rests on
it: **the relay never stores a device token and never learns which instance a
device belongs to.**  A push is a forward of ``(token, text)`` and nothing
survives the request.  An instance can only send to devices whose tokens it
already holds, and it only holds tokens its own logged-in users gave it.  So
"instance A cannot notify instance B's users" is true because A has never seen
B's tokens — not because anything here is enforcing a routing rule.  There is
no routing table to get wrong, and adding one would make the guarantee weaker,
not stronger.

Deliberately absent, for the same reason: any endpoint that lists tokens,
looks one up, or reports whether one is known.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse

from .apns import (
    ApnsClient,
    ApnsConfigError,
    ProviderTokenCache,
    validate_private_key,
)
from .config import Settings, load_settings
from .keys import Instance, InvalidKey, generate_instance_id, mint, verify
from .landing import render_landing, wants_html
from .ratelimit import RateLimiter
from .schemas import (
    EnrollResponse,
    HealthResponse,
    PushRequest,
    PushResponse,
    VerifyResponse,
)

logger = logging.getLogger(__name__)

VERSION = "1.0.0"


@dataclass
class RelayState:
    """Long-lived objects created once in the lifespan."""

    settings: Settings
    http: httpx.AsyncClient
    """The one outbound client. HTTP/2 because APNs speaks nothing else."""

    tokens: ProviderTokenCache = field(default_factory=ProviderTokenCache)

    limiter: RateLimiter | None = None
    """Pushes, bucketed per instance."""

    enrollment_limiter: RateLimiter | None = None
    """Enrollments, bucketed per source address.

    A separate limiter with a separate key space, because the two are limiting
    different things against different identities: one caps what an instance we
    know may do, the other caps how many instances a stranger may become."""


def _state(request: Request) -> RelayState:
    return request.app.state.relay  # type: ignore[no-any-return]


StateDep = Annotated[RelayState, Depends(_state)]


def _bearer(request: Request) -> str:
    """The API key from the ``Authorization`` header.

    Bearer only. An ``X-Api-Key`` alternative would be one more thing to get
    subtly different between the two services for no benefit — instances are
    talking to exactly one relay and it is this one.
    """
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Send your relay API key as `Authorization: Bearer <key>`.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return value.strip()


def authenticate(request: Request, state: StateDep) -> Instance:
    """Resolve the caller's API key to an instance, or refuse.

    Every refusal is the same flat 401 with the same message, whether the key
    was malformed, forged, or revoked. A caller who is legitimately set up
    knows which of those they are; one who is probing should not be told.
    """
    api_key = _bearer(request)
    try:
        instance = verify(api_key, secret=state.settings.signing_secret)
    except InvalidKey:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "This relay API key is not valid.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    if state.settings.is_revoked(instance.id):
        logger.warning("refused a push from revoked instance %s", instance.id)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "This relay API key is not valid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return instance


InstanceDep = Annotated[Instance, Depends(authenticate)]


def create_app(*, settings: Settings | None = None) -> FastAPI:
    """Build the relay.

    ``settings`` lets tests inject their own; production passes nothing and the
    environment is read in the lifespan. Reading it there rather than at import
    time is what makes the module importable by the CLI, which has no
    credentials and needs none.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        active = settings if settings is not None else load_settings()

        http = httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(active.apns_timeout_seconds, connect=5.0),
        )
        app.state.relay = RelayState(
            settings=active,
            http=http,
            limiter=RateLimiter(
                per_minute=active.rate_limit_per_minute, burst=active.rate_burst
            ),
            enrollment_limiter=RateLimiter.per_hour(
                active.enrollment_per_hour, burst=active.enrollment_burst
            ),
        )

        if active.apns is None:
            # Not fatal. A relay with no signing key still answers /health and
            # still tells an instance exactly what is wrong on /v1/verify,
            # which beats a crash loop with the answer buried in a log.
            logger.warning(
                "no APNs credentials in the environment; pushes will be refused "
                "with 503 until CANOPY_APNS_TEAM_ID, CANOPY_APNS_KEY_ID, "
                "CANOPY_APNS_BUNDLE_ID and CANOPY_APNS_PRIVATE_KEY are set"
            )
        else:
            # Parse the key once, now, so a mis-pasted .p8 is one line in the
            # deployment log instead of every push failing identically later.
            validate_private_key(active.apns.private_key_pem)
            logger.info(
                "relay ready: topic=%s team=%s key=%s",
                active.apns.bundle_id,
                active.apns.team_id,
                active.apns.key_id,
            )

        try:
            yield
        finally:
            await http.aclose()

    app = FastAPI(
        title="canopy-apns",
        description=(
            "A stateless APNs forwarder for self-hosted Canopy+ instances. "
            "Holds the signing key so instances do not have to; stores nothing."
        ),
        version=VERSION,
        lifespan=lifespan,
    )

    @app.get("/health", response_model=HealthResponse, tags=["meta"])
    async def health(state: StateDep) -> HealthResponse:
        """Liveness, plus whether a signing key is present.

        Unauthenticated, and says nothing useful to anyone but the operator:
        that a push relay has push credentials is not a secret.
        """
        return HealthResponse(
            apns="configured" if state.settings.configured else "unconfigured"
        )

    @app.post(
        "/v1/instances",
        response_model=EnrollResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["relay"],
    )
    async def enroll(request: Request, state: StateDep) -> EnrollResponse:
        """Issue a fresh instance identity and API key. **Unauthenticated.**

        This endpoint exists because the alternative was worse. Making an
        instance admin obtain a key out of band and paste it into a settings
        form put a credential in front of someone whose actual intent was "I
        would like notifications", and every one of them would have had to be
        handed a key by a human. Nobody was going to run their own relay, so
        the key was pure friction protecting nothing they had chosen.

        It stays stateless: a random id, its derived key, nothing written. See
        :mod:`canopy_apns.keys`.

        **The honest trade.** Keys being free means a per-key rate limit is a
        speed bump rather than a wall — anyone refused can enroll again and get
        a fresh bucket. What actually holds the line is the per-address
        enrollment limit here, revocation by instance id, and
        ``CANOPY_APNS_ENROLLMENT_ENABLED=false`` as the switch to close the door
        entirely if this is ever abused. That is a deliberate trade of a weaker
        abuse boundary for an admin experience that does not involve credentials
        at all.
        """
        if not state.settings.enrollment_enabled:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "This relay is not issuing new keys. Ask its operator for one.",
            )

        limiter = state.enrollment_limiter
        if limiter is not None:
            # Keyed on the source address. Behind a proxy this is only the real
            # client because uvicorn is run with proxy headers trusted; see
            # `__main__`. Without that it would bucket the whole internet
            # together under the proxy's own address.
            source = request.client.host if request.client else "unknown"
            decision = limiter.check(f"enroll:{source}")
            if not decision.allowed:
                logger.warning("rate-limited enrollment from %s", source)
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Too many enrollments from this address. Try again shortly.",
                    headers={"Retry-After": str(decision.retry_after_seconds)},
                )

        instance_id = generate_instance_id()
        api_key = mint(instance_id, secret=state.settings.signing_secret)
        apns = state.settings.apns

        # The id, never the key. A log line carrying the credential it just
        # issued would undo the point of never storing one.
        logger.info("enrolled instance %s", instance_id)

        return EnrollResponse(
            instance_id=instance_id,
            api_key=api_key,
            bundle_id=apns.bundle_id if apns else None,
            ready=apns is not None,
        )

    @app.get("/v1/verify", response_model=VerifyResponse, tags=["relay"])
    async def verify_key(instance: InstanceDep, state: StateDep) -> VerifyResponse:
        """Confirm an API key works, for an instance's settings page.

        Separates the two failures that look identical from the far end — "your
        key is wrong" (401) and "your key is fine, this relay has no signing
        key" (200 with ``ready: false``) — because they have different owners
        and different fixes.

        Not rate-limited against the push bucket: a settings page that costs an
        admin their notification budget to load is a bad settings page.
        """
        apns = state.settings.apns
        return VerifyResponse(
            ok=True,
            instance=instance.id,
            bundle_id=apns.bundle_id if apns else None,
            ready=apns is not None,
            rate_limit_per_minute=state.settings.rate_limit_per_minute,
        )

    @app.post("/v1/push", response_model=PushResponse, tags=["relay"])
    async def push(
        notification: PushRequest, instance: InstanceDep, state: StateDep
    ) -> PushResponse:
        """Forward one notification to one device.

        **Always 200 when Apple answered**, whatever Apple said — including a
        rejection. The relay's job is to forward, and "Apple refused this
        token" is a successful forward with a definitive answer in it. Reserve
        non-2xx for the relay's own problems, so a caller can read
        ``response.status_code`` and know whether the *relay* worked without
        parsing anything.

        That split matters most for ``unregistered``. The relay stores no
        device tokens, so it cannot delete a dead one; only the instance can,
        and burying that answer in a 502 alongside genuine faults is how a
        table fills up with tokens Apple stopped accepting months ago.
        """
        limiter = state.limiter
        if limiter is not None:
            decision = limiter.check(instance.id)
            if not decision.allowed:
                logger.info("rate-limited instance %s", instance.id)
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Too many notifications. Slow down and try again shortly.",
                    headers={"Retry-After": str(decision.retry_after_seconds)},
                )

        credentials = state.settings.apns
        if credentials is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "This relay has no APNs signing key configured yet. Nothing is "
                "wrong with your API key; the relay operator has to fix this.",
            )

        client = ApnsClient(credentials, client=state.http, tokens=state.tokens)
        try:
            result = await client.send(
                device_token=notification.device_token,
                title=notification.title,
                body=notification.body,
                badge=notification.badge,
                data=notification.data,
                environment=notification.environment,
                collapse_id=notification.collapse_id,
            )
        except ApnsConfigError as exc:
            # The key parsed at startup, so reaching here means it changed
            # underneath us. Every push would fail the same way; say so.
            logger.error("APNs credentials are unusable: %s", exc)
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "This relay's APNs signing key is not usable. The relay "
                "operator has to fix this.",
            ) from exc

        # Instance id and outcome, never the device token or the text. The
        # relay is a forwarder; a log that reconstructs what was forwarded
        # would be a store of exactly what this service promises not to keep.
        logger.info(
            "push instance=%s env=%s result=%s reason=%s",
            instance.id,
            notification.environment,
            result.outcome.value,
            result.reason or "-",
        )

        return PushResponse(
            result=result.outcome.value,
            reason=result.reason,
            apns_id=result.apns_id,
        )

    @app.get("/", include_in_schema=False)
    async def root(request: Request, state: StateDep) -> Response:
        """What the relay is, and what it saw of your request.

        A browser gets HTML — see :mod:`canopy_apns.landing`, which is there to
        make a TLS-termination problem visible in one page load instead of one
        log dive. Anything else gets the JSON it always got, so a health-check
        or a script pointed at ``/`` is unaffected.
        """
        if wants_html(request):
            return HTMLResponse(
                render_landing(
                    request,
                    version=VERSION,
                    apns_configured=state.settings.configured,
                    enrollment_enabled=state.settings.enrollment_enabled,
                    rate_limit_per_minute=state.settings.rate_limit_per_minute,
                )
            )
        return JSONResponse(
            {
                "service": "canopy-apns",
                "description": (
                    "APNs forwarder for self-hosted Canopy+ instances. "
                    "Ask the operator for a relay API key."
                ),
                "docs": "/docs",
                "scheme": request.url.scheme,
            }
        )

    return app


__all__ = ["RelayState", "authenticate", "create_app"]
