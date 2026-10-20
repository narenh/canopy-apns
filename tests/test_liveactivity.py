"""``POST /v1/liveactivity``, end to end over ASGI with APNs mocked."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from httpx import AsyncClient

from canopy_apns.apns import (
    PRODUCTION_HOST,
    SANDBOX_HOST,
    build_live_activity_payload,
    encoded_payload_size,
)
from canopy_apns.config import (
    MAX_LIVE_ACTIVITY_PAYLOAD_BYTES,
    ApnsCredentials,
    Settings,
)
from canopy_apns.keys import mint

from .conftest import BUNDLE_ID, DEVICE_TOKEN, INSTANCE_ID, SIGNING_SECRET, _client_for

LA_BUNDLE = "com.canopysf.CanopyControl"
LA_TOPIC = f"{LA_BUNDLE}.push-type.liveactivity"

UPDATE = {
    "device_token": DEVICE_TOKEN,
    "bundle_id": LA_BUNDLE,
    "event": "update",
    "content_state": {"progress": 0.5, "label": "Downloading"},
    "timestamp": 1_700_000_000,
}

START = {
    "device_token": DEVICE_TOKEN,
    "bundle_id": LA_BUNDLE,
    "event": "start",
    "content_state": {"progress": 0.0},
    "attributes_type": "DownloadAttributes",
    "attributes": {"title": "The End of Oak Street"},
    "alert": {"title": "Download started", "body": "The End of Oak Street"},
    "timestamp": 1_700_000_000,
}


def _apns_route(host: str = PRODUCTION_HOST, token: str = DEVICE_TOKEN):
    return respx.post(f"{host}/3/device/{token}")


def _sent(route: respx.Route, index: int = 0) -> tuple[httpx.Headers, dict]:
    request = route.calls[index].request
    return request.headers, json.loads(request.read())


@pytest.fixture
def la_settings(credentials: ApnsCredentials) -> Settings:
    return Settings(
        apns=credentials,
        signing_secret=SIGNING_SECRET,
        live_activity_topics=frozenset({(INSTANCE_ID, LA_BUNDLE)}),
    )


@pytest.fixture
async def la_client(la_settings: Settings) -> AsyncIterator[AsyncClient]:
    async for value in _client_for(la_settings):
        yield value


# ---------------------------------------------------------------------------
# What reaches Apple
# ---------------------------------------------------------------------------


@respx.mock
async def test_headers_carry_the_liveactivity_type_and_topic_suffix(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(
        return_value=httpx.Response(200, headers={"apns-id": "la-1"})
    )

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.status_code == 200
    assert response.json() == {"result": "delivered", "reason": None, "apns_id": "la-1"}
    headers, _ = _sent(route)
    assert headers["apns-push-type"] == "liveactivity"
    assert headers["apns-topic"] == LA_TOPIC
    assert headers["apns-priority"] == "10"
    assert headers["apns-expiration"] == "0"
    assert headers["authorization"].startswith("bearer ")
    assert "apns-collapse-id" not in headers


@respx.mock
async def test_priority_and_expiration_are_forwarded(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "priority": 5, "expiration": 1_700_000_600},
        headers=auth,
    )

    headers, _ = _sent(route)
    assert headers["apns-priority"] == "5"
    assert headers["apns-expiration"] == "1700000600"


async def test_a_priority_other_than_5_or_10_is_refused(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, "priority": 7}, headers=auth
    )
    assert response.status_code == 422


@respx.mock
async def test_a_start_maps_every_field_to_its_hyphenated_aps_key(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity",
        json={**START, "stale_date": 1_700_003_600, "relevance_score": 75},
        headers=auth,
    )

    assert response.status_code == 200
    _, payload = _sent(route)
    assert payload == {
        "aps": {
            "timestamp": 1_700_000_000,
            "event": "start",
            "content-state": {"progress": 0.0},
            "attributes-type": "DownloadAttributes",
            "attributes": {"title": "The End of Oak Street"},
            "alert": {"title": "Download started", "body": "The End of Oak Street"},
            "stale-date": 1_700_003_600,
            "relevance-score": 75.0,
        }
    }


@respx.mock
async def test_an_update_omits_every_absent_optional(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    _, payload = _sent(route)
    assert payload == {
        "aps": {
            "timestamp": 1_700_000_000,
            "event": "update",
            "content-state": {"progress": 0.5, "label": "Downloading"},
        }
    }


@respx.mock
async def test_an_update_may_carry_an_alert(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "alert": {"title": "Halfway", "body": "50%"}},
        headers=auth,
    )

    _, payload = _sent(route)
    assert payload["aps"]["alert"] == {"title": "Halfway", "body": "50%"}


@respx.mock
async def test_an_end_carries_its_dismissal_date(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "event": "end", "dismissal_date": 1_700_000_900},
        headers=auth,
    )

    assert response.status_code == 200
    _, payload = _sent(route)
    assert payload == {
        "aps": {
            "timestamp": 1_700_000_000,
            "event": "end",
            "content-state": {"progress": 0.5, "label": "Downloading"},
            "dismissal-date": 1_700_000_900,
        }
    }


@respx.mock
async def test_the_timestamp_defaults_to_now(
    la_client: AsyncClient, auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("canopy_apns.app.time.time", lambda: 1_800_000_000.7)
    route = _apns_route().mock(return_value=httpx.Response(200))
    body = {key: value for key, value in UPDATE.items() if key != "timestamp"}

    await la_client.post("/v1/liveactivity", json=body, headers=auth)

    _, payload = _sent(route)
    assert payload["aps"]["timestamp"] == 1_800_000_000


@respx.mock
async def test_sandbox_and_production_go_to_their_own_hosts(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    sandbox = _apns_route(SANDBOX_HOST).mock(return_value=httpx.Response(200))
    production = _apns_route(PRODUCTION_HOST).mock(return_value=httpx.Response(200))

    await la_client.post(
        "/v1/liveactivity", json={**UPDATE, "environment": "sandbox"}, headers=auth
    )
    assert sandbox.call_count == 1 and production.call_count == 0

    await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)
    assert sandbox.call_count == 1 and production.call_count == 1


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["attributes_type", "attributes", "alert"])
async def test_a_start_requires_its_start_only_fields(
    la_client: AsyncClient, auth: dict[str, str], missing: str
) -> None:
    body = {key: value for key, value in START.items() if key != missing}
    response = await la_client.post("/v1/liveactivity", json=body, headers=auth)

    assert response.status_code == 422
    assert missing in json.dumps(response.json())


@respx.mock
async def test_a_start_accepts_empty_attributes(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity", json={**START, "attributes": {}}, headers=auth
    )

    assert response.status_code == 200
    _, payload = _sent(route)
    assert payload["aps"]["attributes"] == {}


@pytest.mark.parametrize(
    "extra",
    [{"attributes_type": "DownloadAttributes"}, {"attributes": {}}],
)
async def test_start_only_fields_are_refused_on_an_update(
    la_client: AsyncClient, auth: dict[str, str], extra: dict
) -> None:
    """ActivityKit would ignore them; extra="forbid" is here to surface that."""
    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, **extra}, headers=auth
    )
    assert response.status_code == 422


async def test_a_dismissal_date_is_only_for_end(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, "dismissal_date": 1}, headers=auth
    )
    assert response.status_code == 422


async def test_content_state_is_required(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    body = {key: value for key, value in UPDATE.items() if key != "content_state"}
    response = await la_client.post("/v1/liveactivity", json=body, headers=auth)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"device_token": "not-hex"},
        {"aps": {"content-available": 1}},
        {"event": "pause"},
        {"bundle_id": "not a bundle id"},
        {"alert": {"title": "T", "body": "B", "sound": "default"}},
        {"alert": {"title": "x" * 201, "body": "B"}},
    ],
)
async def test_malformed_requests_are_refused(
    la_client: AsyncClient, auth: dict[str, str], change: dict
) -> None:
    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, **change}, headers=auth
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"content_state": {"v": float("nan")}},
        {"attributes": {"v": float("inf")}},
        {"relevance_score": float("nan")},
    ],
)
async def test_non_finite_numbers_are_a_422_not_a_500(
    la_client: AsyncClient, auth: dict[str, str], change: dict
) -> None:
    """Python's json.loads accepts NaN; the encoder on the way to Apple does not."""
    body = json.dumps({**START, **change})
    response = await la_client.post(
        "/v1/liveactivity",
        content=body,
        headers={**auth, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "NaN" in response.json()["detail"]


# ---------------------------------------------------------------------------
# The 4KB limit
# ---------------------------------------------------------------------------


@respx.mock
async def test_a_payload_over_4kb_is_refused_before_apple_sees_it(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "content_state": {"blob": "x" * 4100}},
        headers=auth,
    )

    assert response.status_code == 422
    assert "4096" in response.json()["detail"]
    assert not route.called


@respx.mock
async def test_a_payload_of_exactly_4096_bytes_is_sent(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    """The limit is on the bytes Apple receives, and it is inclusive."""
    route = _apns_route().mock(return_value=httpx.Response(200))
    overhead = encoded_payload_size(
        build_live_activity_payload(
            event="update", timestamp=UPDATE["timestamp"], content_state={"blob": ""}
        )
    )
    blob = "x" * (MAX_LIVE_ACTIVITY_PAYLOAD_BYTES - overhead)

    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, "content_state": {"blob": blob}}, headers=auth
    )

    assert response.status_code == 200
    assert len(route.calls[0].request.content) == MAX_LIVE_ACTIVITY_PAYLOAD_BYTES

    over = await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "content_state": {"blob": blob + "x"}},
        headers=auth,
    )
    assert over.status_code == 422


@respx.mock
async def test_the_size_counts_utf8_bytes_not_characters(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    """1400 three-byte characters is 1400 characters and 4200 bytes."""
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "content_state": {"label": "…" * 1400}},
        headers=auth,
    )

    assert response.status_code == 422
    assert not route.called


# ---------------------------------------------------------------------------
# Who may push to which app
# ---------------------------------------------------------------------------


@respx.mock
async def test_an_unlisted_bundle_is_a_403(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity",
        json={**UPDATE, "bundle_id": "com.example.SomeoneElse"},
        headers=auth,
    )

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "CANOPY_APNS_LIVEACTIVITY_TOPICS" in detail
    assert f"{INSTANCE_ID}:com.example.SomeoneElse" in detail
    assert not route.called


@respx.mock
async def test_the_relays_own_bundle_is_not_implicitly_allowed(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    """/v1/push's topic is not an entry in the Live Activity list."""
    _apns_route().mock(return_value=httpx.Response(200))

    response = await la_client.post(
        "/v1/liveactivity", json={**UPDATE, "bundle_id": BUNDLE_ID}, headers=auth
    )

    assert response.status_code == 403


@respx.mock
async def test_another_instance_cannot_use_a_listed_bundle(
    la_client: AsyncClient,
) -> None:
    route = _apns_route().mock(return_value=httpx.Response(200))
    other = {"Authorization": f"Bearer {mint('someone-else', secret=SIGNING_SECRET)}"}

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=other)

    assert response.status_code == 403
    assert not route.called


@respx.mock
async def test_with_no_topics_configured_nobody_may_push(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    """The default `settings` fixture has an empty list."""
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.status_code == 403
    assert "any instance" in response.json()["detail"]
    assert not route.called


async def test_a_live_activity_push_without_a_key_is_a_401(
    la_client: AsyncClient,
) -> None:
    response = await la_client.post("/v1/liveactivity", json=UPDATE)
    assert response.status_code == 401


async def test_a_refused_topic_does_not_spend_the_push_budget(
    credentials: ApnsCredentials, auth: dict[str, str]
) -> None:
    settings = Settings(
        apns=credentials,
        signing_secret=SIGNING_SECRET,
        rate_limit_per_minute=60,
        rate_burst=1,
        live_activity_topics=frozenset({(INSTANCE_ID, LA_BUNDLE)}),
    )
    with respx.mock:
        _apns_route().mock(return_value=httpx.Response(200))
        async for client in _client_for(settings):
            for _ in range(3):
                refused = await client.post(
                    "/v1/liveactivity",
                    json={**UPDATE, "bundle_id": "com.example.Other"},
                    headers=auth,
                )
                assert refused.status_code == 403
            allowed = await client.post("/v1/liveactivity", json=UPDATE, headers=auth)
            limited = await client.post("/v1/push", json={
                "device_token": DEVICE_TOKEN, "title": "T"
            }, headers=auth)

    assert allowed.status_code == 200
    # One bucket for both endpoints: the live activity push spent the only token.
    assert limited.status_code == 429


async def test_an_unconfigured_relay_is_a_503(
    credentials: ApnsCredentials, auth: dict[str, str]
) -> None:
    settings = Settings(
        apns=None,
        signing_secret=SIGNING_SECRET,
        live_activity_topics=frozenset({(INSTANCE_ID, LA_BUNDLE)}),
    )
    async for client in _client_for(settings):
        response = await client.post("/v1/liveactivity", json=UPDATE, headers=auth)
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Apple's answers
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.parametrize(
    ("status", "reason"),
    [(410, "Unregistered"), (400, "DeviceTokenNotForTopic"), (410, None)],
)
async def test_dead_tokens_are_unregistered(
    la_client: AsyncClient, auth: dict[str, str], status: int, reason: str | None
) -> None:
    body = {"reason": reason} if reason else None
    _apns_route().mock(return_value=httpx.Response(status, json=body))

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.status_code == 200
    assert response.json()["result"] == "unregistered"
    assert response.json()["reason"] == reason


@respx.mock
async def test_bad_device_token_is_failed_not_unregistered(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    """Usually a sandbox/production mismatch: the token is fine on the other host."""
    route = _apns_route().mock(
        return_value=httpx.Response(400, json={"reason": "BadDeviceToken"})
    )

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.status_code == 200
    assert response.json() == {
        "result": "failed",
        "reason": "BadDeviceToken",
        "apns_id": None,
    }
    assert route.call_count == 1


@respx.mock
async def test_throttling_earns_exactly_one_retry(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(
        side_effect=[
            httpx.Response(429, json={"reason": "TooManyRequests"}),
            httpx.Response(200, headers={"apns-id": "la-2"}),
        ]
    )

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.json()["result"] == "delivered"
    assert route.call_count == 2
    headers, _ = _sent(route, 1)
    assert headers["apns-topic"] == LA_TOPIC


@respx.mock
async def test_an_expired_provider_token_is_reminted_and_retried(
    la_client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(
        side_effect=[
            httpx.Response(403, json={"reason": "ExpiredProviderToken"}),
            httpx.Response(200),
        ]
    )

    response = await la_client.post("/v1/liveactivity", json=UPDATE, headers=auth)

    assert response.json()["result"] == "delivered"
    first, _ = _sent(route, 0)
    second, _ = _sent(route, 1)
    assert first["authorization"] != second["authorization"]
