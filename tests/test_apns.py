"""Provider-token signing, payload shape, and reading Apple's answers."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from canopy_apns.apns import (
    PRODUCTION_HOST,
    SANDBOX_HOST,
    ApnsClient,
    ApnsConfigError,
    ProviderTokenCache,
    SendOutcome,
    build_payload,
    sign_provider_token,
    validate_private_key,
)
from canopy_apns.config import ApnsCredentials

from .conftest import DEVICE_TOKEN


def _segment(raw: str) -> dict[str, object]:
    padded = raw + "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def test_provider_token_carries_the_key_id_and_team(
    credentials: ApnsCredentials,
) -> None:
    header, claims, signature = sign_provider_token(credentials, issued_at=1000).split(".")

    assert _segment(header) == {"alg": "ES256", "kid": credentials.key_id}
    assert _segment(claims) == {"iss": credentials.team_id, "iat": 1000}
    # Raw r||s for P-256, not DER: 64 bytes, which is 86 base64url characters.
    assert len(signature) == 86


def test_a_non_pem_key_is_refused_with_an_actionable_message() -> None:
    with pytest.raises(ApnsConfigError, match="could not be read"):
        validate_private_key("not a key")


def test_an_rsa_key_is_refused_as_the_wrong_kind() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("ascii")
    )
    with pytest.raises(ApnsConfigError, match="elliptic-curve"):
        validate_private_key(pem)


# ---------------------------------------------------------------------------
# Token caching
# ---------------------------------------------------------------------------


def test_the_provider_token_is_reused_within_its_lifetime(
    credentials: ApnsCredentials,
) -> None:
    """Apple refuses to mint one more than once per 20 minutes."""
    cache = ProviderTokenCache()
    first = cache.get(credentials, now=0.0)
    assert cache.get(credentials, now=60.0) == first


def test_the_provider_token_is_reminted_once_it_ages_out(
    credentials: ApnsCredentials,
) -> None:
    cache = ProviderTokenCache()
    first = cache.get(credentials, now=0.0)
    assert cache.get(credentials, now=46 * 60) != first


def test_invalidating_forces_a_fresh_mint(credentials: ApnsCredentials) -> None:
    cache = ProviderTokenCache()
    first = cache.get(credentials, now=0.0)
    cache.invalidate(credentials)
    assert cache.get(credentials, now=1.0) != first


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def test_payload_is_a_plain_alert() -> None:
    payload = build_payload(title="A Title", body="A second line", data=None)
    assert payload == {
        "aps": {"alert": {"title": "A Title", "body": "A second line"}, "sound": "default"}
    }


def test_the_second_line_is_body_so_ios_does_not_bold_it() -> None:
    """iOS bolds `title` and `subtitle` alike; only `body` is regular weight.

    Built as title+subtitle, every notification arrived as two bold lines and
    looked like shouting beside Messages and Mail on the same lock screen.
    """
    payload = build_payload(title="A Title", body="A second line", data=None)
    assert "subtitle" not in payload["aps"]["alert"]


def test_a_badge_is_a_sibling_of_alert_not_a_child() -> None:
    """Nested inside `alert`, Apple ignores it and the icon never changes."""
    payload = build_payload(title="T", body=None, badge=3, data=None)
    assert payload["aps"]["badge"] == 3
    assert "badge" not in payload["aps"]["alert"]


def test_a_zero_badge_is_sent_because_zero_is_what_clears_it() -> None:
    """The value a truthiness check would drop, and the only way to clear."""
    payload = build_payload(title="T", body=None, badge=0, data=None)
    assert payload["aps"]["badge"] == 0


def test_no_badge_leaves_the_payload_exactly_as_it_was() -> None:
    """cplus sends no badge today; its pushes must not change by one byte.

    An absent badge has to mean "leave the icon alone", which is a different
    instruction from `badge: 0`, and it must reach Apple as a payload with no
    `badge` key at all.
    """
    payload = build_payload(title="A Title", body="A second line", data=None)
    assert payload == {
        "aps": {"alert": {"title": "A Title", "body": "A second line"}, "sound": "default"}
    }


def test_instance_data_rides_beside_aps_not_inside_it() -> None:
    """So a malformed blob is the app's problem, never an APNs rejection."""
    payload = build_payload(title="T", body=None, data={"imdb_id": "tt1"})
    assert payload["canopy"] == {"imdb_id": "tt1"}
    assert "canopy" not in payload["aps"]


def test_an_absent_second_line_is_omitted_rather_than_empty() -> None:
    payload = build_payload(title="T", body=None, data=None)
    assert payload["aps"]["alert"] == {"title": "T"}


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


@pytest.fixture
async def sender(credentials: ApnsCredentials):
    async with httpx.AsyncClient() as http:
        yield ApnsClient(credentials, client=http, tokens=ProviderTokenCache())


@respx.mock
async def test_a_200_is_delivered(sender: ApnsClient) -> None:
    route = respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(200, headers={"apns-id": "abc-123"})
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.DELIVERED
    assert result.apns_id == "abc-123"
    headers = route.calls[0].request.headers
    assert headers["apns-topic"] == sender.credentials.bundle_id
    assert headers["apns-push-type"] == "alert"
    assert headers["authorization"].startswith("bearer ")


@respx.mock
async def test_sandbox_tokens_go_to_the_sandbox_host(sender: ApnsClient) -> None:
    route = respx.post(f"{SANDBOX_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(200)
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T", environment="sandbox")

    assert result.delivered
    assert route.called


@respx.mock
async def test_a_410_is_reported_as_unregistered(sender: ApnsClient) -> None:
    """Not a failure: the instance has to hear this to delete its dead token."""
    respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(410, json={"reason": "Unregistered"})
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.UNREGISTERED
    assert result.reason == "Unregistered"


@respx.mock
async def test_bad_device_token_is_also_unregistered(sender: ApnsClient) -> None:
    """Most often a sandbox token sent to production. Permanent either way."""
    respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(400, json={"reason": "BadDeviceToken"})
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.UNREGISTERED


@respx.mock
async def test_an_expired_provider_token_is_reminted_and_retried(
    sender: ApnsClient,
) -> None:
    route = respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        side_effect=[
            httpx.Response(403, json={"reason": "ExpiredProviderToken"}),
            httpx.Response(200),
        ]
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.delivered
    assert route.call_count == 2
    first = route.calls[0].request.headers["authorization"]
    second = route.calls[1].request.headers["authorization"]
    assert first != second


@respx.mock
async def test_throttling_earns_exactly_one_retry(sender: ApnsClient) -> None:
    route = respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(429, json={"reason": "TooManyRequests"})
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.FAILED
    assert route.call_count == 2


@respx.mock
async def test_a_bad_request_is_not_retried(sender: ApnsClient) -> None:
    """It would fail identically; the request is what is wrong."""
    route = respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(400, json={"reason": "BadTopic"})
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.FAILED
    assert route.call_count == 1


@respx.mock
async def test_a_transport_failure_is_a_failure_not_an_exception(
    sender: ApnsClient,
) -> None:
    respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        side_effect=httpx.ConnectError("apple is unreachable")
    )

    result = await sender.send(device_token=DEVICE_TOKEN, title="T")

    assert result.outcome is SendOutcome.FAILED
    assert "unreachable" in (result.reason or "")


@respx.mock
async def test_a_collapse_id_is_forwarded(sender: ApnsClient) -> None:
    route = respx.post(f"{PRODUCTION_HOST}/3/device/{DEVICE_TOKEN}").mock(
        return_value=httpx.Response(200)
    )

    await sender.send(device_token=DEVICE_TOKEN, title="T", collapse_id="req-7")

    assert route.calls[0].request.headers["apns-collapse-id"] == "req-7"
