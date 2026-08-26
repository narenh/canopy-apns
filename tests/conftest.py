"""Shared fixtures.

The APNs key here is generated once per test session rather than checked in.
A committed private key is a committed private key even when it is only ever
used against a mocked host, and a P-256 key takes microseconds to make.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient

from canopy_apns.app import create_app
from canopy_apns.config import ApnsCredentials, Settings
from canopy_apns.keys import mint

SIGNING_SECRET = "test-signing-secret"
INSTANCE_ID = "notcanopy"
BUNDLE_ID = "com.example.canopy"
DEVICE_TOKEN = "a" * 64


@pytest.fixture(scope="session")
def private_key_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture
def credentials(private_key_pem: str) -> ApnsCredentials:
    return ApnsCredentials(
        team_id="TEAM123456",
        key_id="KEY1234567",
        bundle_id=BUNDLE_ID,
        private_key_pem=private_key_pem,
    )


@pytest.fixture
def settings(credentials: ApnsCredentials) -> Settings:
    return Settings(apns=credentials, signing_secret=SIGNING_SECRET)


@pytest.fixture
def api_key() -> str:
    return mint(INSTANCE_ID, secret=SIGNING_SECRET)


@pytest.fixture
def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _client_for(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings=settings)
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://relay"
        ) as client:
            yield client


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[AsyncClient]:
    async for value in _client_for(settings):
        yield value


@pytest.fixture
async def unconfigured_client() -> AsyncIterator[AsyncClient]:
    """A relay with a valid signing secret but no APNs credentials.

    The state a fresh Coolify deployment is in before the .p8 is pasted in, and
    one the service is expected to survive rather than crash-loop through.
    """
    async for value in _client_for(Settings(apns=None, signing_secret=SIGNING_SECRET)):
        yield value
