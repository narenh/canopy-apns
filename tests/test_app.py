"""The relay's endpoints, end to end over ASGI with APNs mocked."""

from __future__ import annotations

import json

import httpx
import respx
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from canopy_apns.apns import PRODUCTION_HOST, SANDBOX_HOST
from canopy_apns.app import create_app
from canopy_apns.config import ApnsCredentials, Settings
from canopy_apns.keys import mint

from .conftest import BUNDLE_ID, DEVICE_TOKEN, INSTANCE_ID, SIGNING_SECRET

PUSH = {"device_token": DEVICE_TOKEN, "title": "The End of Oak Street (2026)"}


def _apns_route(host: str = PRODUCTION_HOST, token: str = DEVICE_TOKEN):
    return respx.post(f"{host}/3/device/{token}")


# ---------------------------------------------------------------------------
# Health and discovery
# ---------------------------------------------------------------------------


async def test_health_is_open_and_reports_readiness(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "apns": "configured"}


async def test_health_says_so_when_no_signing_key_is_set(
    unconfigured_client: AsyncClient,
) -> None:
    response = await unconfigured_client.get("/health")
    assert response.status_code == 200
    assert response.json()["apns"] == "unconfigured"


async def test_the_root_explains_itself_rather_than_404ing(client: AsyncClient) -> None:
    response = await client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "canopy-apns"


async def test_a_browser_gets_the_diagnostic_page(client: AsyncClient) -> None:
    response = await client.get("/", headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "canopy-apns" in response.text


async def test_the_page_reports_the_scheme_and_forwarding_headers(
    client: AsyncClient,
) -> None:
    """The whole point of the page: what the relay thinks it was reached over."""
    response = await client.get(
        "/",
        headers={"Accept": "text/html", "X-Forwarded-Proto": "https"},
    )
    assert 'data-scheme="http"' in response.text
    # Named so the operator can see the header arrived even though the app
    # still resolved http — that gap is the bug this page is for.
    assert "X-Forwarded-Proto" in response.text or "x-forwarded-proto" in response.text
    assert "https" in response.text


async def test_the_page_escapes_header_values(client: AsyncClient) -> None:
    """Every value on the page came from a header, so none of it is trusted."""
    response = await client.get(
        "/",
        headers={"Accept": "text/html", "X-Forwarded-For": "<script>alert(1)</script>"},
    )
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


async def test_the_page_reports_an_unconfigured_relay(
    unconfigured_client: AsyncClient,
) -> None:
    response = await unconfigured_client.get("/", headers={"Accept": "text/html"})
    assert "not configured" in response.text


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def test_a_push_without_a_key_is_refused(client: AsyncClient) -> None:
    response = await client.post("/v1/push", json=PUSH)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_a_forged_key_is_refused(client: AsyncClient) -> None:
    forged = mint(INSTANCE_ID, secret="not-the-relays-secret")
    response = await client.post(
        "/v1/push", json=PUSH, headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 401


async def test_a_non_bearer_scheme_is_refused(
    client: AsyncClient, api_key: str
) -> None:
    response = await client.post(
        "/v1/push", json=PUSH, headers={"Authorization": f"Basic {api_key}"}
    )
    assert response.status_code == 401


async def test_every_refusal_reads_the_same(client: AsyncClient) -> None:
    """A prober must not learn whether an instance id exists or a key was close."""
    forged = mint(INSTANCE_ID, secret="wrong")
    malformed = await client.post(
        "/v1/push", json=PUSH, headers={"Authorization": "Bearer nonsense"}
    )
    bad_signature = await client.post(
        "/v1/push", json=PUSH, headers={"Authorization": f"Bearer {forged}"}
    )
    assert malformed.json() == bad_signature.json()


async def test_a_revoked_instance_is_refused_despite_a_valid_signature() -> None:
    """Per-instance revocation, without punishing everyone else with a rotation."""
    settings = Settings(
        apns=None,
        signing_secret=SIGNING_SECRET,
        revoked_instances=frozenset({INSTANCE_ID}),
    )
    app = create_app(settings=settings)
    key = mint(INSTANCE_ID, secret=SIGNING_SECRET)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            response = await client.get(
                "/v1/verify", headers={"Authorization": f"Bearer {key}"}
            )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


async def test_verify_reports_the_instance_and_the_topic(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.get("/v1/verify", headers=auth)

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["instance"] == INSTANCE_ID
    assert body["bundle_id"] == BUNDLE_ID
    assert body["ready"] is True


async def test_verify_separates_a_good_key_from_an_unready_relay(
    unconfigured_client: AsyncClient, auth: dict[str, str]
) -> None:
    """Two different failures with two different owners; 401 vs ready:false."""
    response = await unconfigured_client.get("/v1/verify", headers=auth)

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "instance": INSTANCE_ID,
        "bundle_id": None,
        "ready": False,
        "rate_limit_per_minute": 120,
    }


# ---------------------------------------------------------------------------
# Pushing
# ---------------------------------------------------------------------------


@respx.mock
async def test_a_push_is_forwarded_to_apple(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route().mock(
        return_value=httpx.Response(200, headers={"apns-id": "abc-123"})
    )

    response = await client.post(
        "/v1/push",
        json={**PUSH, "body": "Requested by Robin Example", "data": {"imdb_id": "tt1"}},
        headers=auth,
    )

    assert response.status_code == 200
    assert response.json() == {
        "result": "delivered",
        "reason": None,
        "apns_id": "abc-123",
    }

    payload = json.loads(route.calls[0].request.read())
    assert payload["aps"]["alert"] == {
        "title": PUSH["title"],
        "body": "Requested by Robin Example",
    }
    assert payload["canopy"] == {"imdb_id": "tt1"}


@respx.mock
async def test_the_old_subtitle_field_still_works(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    """`subtitle` was the field's name before iOS's bolding was noticed.

    The two services deploy separately and the schema forbids unknown fields,
    so removing the old name outright would turn every push from a client that
    has not been redeployed into a 422. It aliases onto `body` and produces the
    same alert.
    """
    route = _apns_route().mock(return_value=httpx.Response(200))

    response = await client.post(
        "/v1/push",
        json={**PUSH, "subtitle": "Requested by Robin Example"},
        headers=auth,
    )

    assert response.status_code == 200
    payload = json.loads(route.calls[0].request.read())
    assert payload["aps"]["alert"]["body"] == "Requested by Robin Example"
    assert "subtitle" not in payload["aps"]["alert"]


@respx.mock
async def test_a_sandbox_push_goes_to_the_sandbox_host(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    route = _apns_route(SANDBOX_HOST).mock(return_value=httpx.Response(200))

    response = await client.post(
        "/v1/push", json={**PUSH, "environment": "sandbox"}, headers=auth
    )

    assert response.json()["result"] == "delivered"
    assert route.called


@respx.mock
async def test_a_dead_token_comes_back_as_200_unregistered(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    """The relay stores no tokens, so only the instance can delete one.

    Burying that answer in a 5xx alongside genuine faults is how an instance
    ends up keeping tokens Apple stopped accepting months ago.
    """
    _apns_route().mock(return_value=httpx.Response(410, json={"reason": "Unregistered"}))

    response = await client.post("/v1/push", json=PUSH, headers=auth)

    assert response.status_code == 200
    assert response.json()["result"] == "unregistered"
    assert response.json()["reason"] == "Unregistered"


@respx.mock
async def test_apple_refusing_is_still_a_successful_forward(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    _apns_route().mock(return_value=httpx.Response(400, json={"reason": "BadTopic"}))

    response = await client.post("/v1/push", json=PUSH, headers=auth)

    assert response.status_code == 200
    assert response.json()["result"] == "failed"
    assert response.json()["reason"] == "BadTopic"


async def test_a_push_to_an_unconfigured_relay_is_a_503(
    unconfigured_client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await unconfigured_client.post("/v1/push", json=PUSH, headers=auth)

    assert response.status_code == 503
    assert "API key" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Payload constraints
# ---------------------------------------------------------------------------


async def test_an_instance_cannot_set_aps_fields_itself(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    """`content-available` under the operator's signing key is not on offer."""
    response = await client.post(
        "/v1/push",
        json={**PUSH, "aps": {"content-available": 1}},
        headers=auth,
    )
    assert response.status_code == 422


async def test_a_non_hex_device_token_is_refused(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.post(
        "/v1/push", json={**PUSH, "device_token": "not-hex"}, headers=auth
    )
    assert response.status_code == 422


async def test_an_empty_title_is_refused(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.post("/v1/push", json={**PUSH, "title": ""}, headers=auth)
    assert response.status_code == 422


async def test_an_oversized_data_blob_is_refused(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    """The relay is not a general-purpose message bus, and APNs caps at 4KB."""
    response = await client.post(
        "/v1/push", json={**PUSH, "data": {"blob": "x" * 2000}}, headers=auth
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@respx.mock
async def test_an_instance_over_its_limit_gets_a_429_with_retry_after(
    credentials: ApnsCredentials,
) -> None:
    _apns_route().mock(return_value=httpx.Response(200))
    settings = Settings(
        apns=credentials,
        signing_secret=SIGNING_SECRET,
        rate_limit_per_minute=60,
        rate_burst=2,
    )
    app = create_app(settings=settings)
    headers = {"Authorization": f"Bearer {mint(INSTANCE_ID, secret=SIGNING_SECRET)}"}

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            statuses = [
                (await client.post("/v1/push", json=PUSH, headers=headers)).status_code
                for _ in range(3)
            ]
            refused = await client.post("/v1/push", json=PUSH, headers=headers)

    assert statuses == [200, 200, 429]
    assert int(refused.headers["retry-after"]) >= 1


@respx.mock
async def test_verify_does_not_spend_the_push_budget(
    credentials: ApnsCredentials,
) -> None:
    """A settings page that costs an admin their notification budget is a bad one."""
    _apns_route().mock(return_value=httpx.Response(200))
    settings = Settings(
        apns=credentials,
        signing_secret=SIGNING_SECRET,
        rate_limit_per_minute=60,
        rate_burst=1,
    )
    app = create_app(settings=settings)
    headers = {"Authorization": f"Bearer {mint(INSTANCE_ID, secret=SIGNING_SECRET)}"}

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            for _ in range(5):
                assert (await client.get("/v1/verify", headers=headers)).status_code == 200
            pushed = await client.post("/v1/push", json=PUSH, headers=headers)

    assert pushed.status_code == 200


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------


async def test_enrolling_issues_a_working_key(client: AsyncClient) -> None:
    """The whole point: an instance gets a usable identity with no human in it."""
    response = await client.post("/v1/instances")

    assert response.status_code == 201
    body = response.json()
    assert body["instance_id"]
    assert body["api_key"].startswith(f"canopy_{body['instance_id']}_")
    assert body["bundle_id"] == BUNDLE_ID
    assert body["ready"] is True

    # The key it just handed out must actually authenticate.
    verified = await client.get(
        "/v1/verify", headers={"Authorization": f"Bearer {body['api_key']}"}
    )
    assert verified.status_code == 200
    assert verified.json()["instance"] == body["instance_id"]


async def test_enrolling_needs_no_authentication(client: AsyncClient) -> None:
    """A caller with no key is exactly who this endpoint is for."""
    assert (await client.post("/v1/instances")).status_code == 201


async def test_each_enrollment_is_a_distinct_instance(client: AsyncClient) -> None:
    first = (await client.post("/v1/instances")).json()
    second = (await client.post("/v1/instances")).json()

    assert first["instance_id"] != second["instance_id"]
    assert first["api_key"] != second["api_key"]


async def test_enrolling_against_an_unready_relay_still_issues_a_key(
    unconfigured_client: AsyncClient,
) -> None:
    """The key is good; the relay simply has nothing behind it yet.

    Failing here would make an instance's setup depend on the relay operator
    having finished theirs, for no gain — the key works the moment they do.
    """
    response = await unconfigured_client.post("/v1/instances")

    assert response.status_code == 201
    assert response.json()["ready"] is False
    assert response.json()["api_key"]


async def test_enrollment_can_be_switched_off(credentials: ApnsCredentials) -> None:
    """The door an operator can close in one redeploy if this is ever abused."""
    app = create_app(
        settings=Settings(
            apns=credentials,
            signing_secret=SIGNING_SECRET,
            enrollment_enabled=False,
        )
    )

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            response = await client.post("/v1/instances")

    assert response.status_code == 403
    assert "not issuing new keys" in response.json()["detail"]


async def test_enrollment_is_rate_limited_per_address(
    credentials: ApnsCredentials,
) -> None:
    """Keys are free, so this is what actually stops someone minting ten thousand."""
    app = create_app(
        settings=Settings(
            apns=credentials,
            signing_secret=SIGNING_SECRET,
            enrollment_per_hour=10,
            enrollment_burst=2,
        )
    )

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            statuses = [
                (await client.post("/v1/instances")).status_code for _ in range(3)
            ]
            refused = await client.post("/v1/instances")

    assert statuses == [201, 201, 429]
    assert int(refused.headers["retry-after"]) >= 1


@respx.mock
async def test_enrollment_does_not_spend_the_push_budget(
    credentials: ApnsCredentials,
) -> None:
    """Two limiters, two key spaces: enrolling must not cost anyone a push."""
    _apns_route().mock(return_value=httpx.Response(200))
    app = create_app(
        settings=Settings(
            apns=credentials,
            signing_secret=SIGNING_SECRET,
            rate_limit_per_minute=60,
            rate_burst=1,
        )
    )

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            enrolled = (await client.post("/v1/instances")).json()
            headers = {"Authorization": f"Bearer {enrolled['api_key']}"}
            pushed = await client.post("/v1/push", json=PUSH, headers=headers)

    assert pushed.status_code == 200
    assert pushed.json()["result"] == "delivered"
