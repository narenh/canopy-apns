"""Reading credentials out of the environment, including the awkward paths."""

from __future__ import annotations

import base64

import pytest

from canopy_apns.config import (
    ApnsCredentials,
    ConfigError,
    load_settings,
    normalise_private_key,
)

PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n"


def test_verbatim_pem_passes_through() -> None:
    assert normalise_private_key(PEM) == PEM.strip()


def test_escaped_newlines_are_restored() -> None:
    """What happens when a PEM is pasted through a shell or a JSON field."""
    escaped = PEM.strip().replace("\n", "\\n")
    assert normalise_private_key(escaped) == PEM.strip()


def test_base64_of_the_whole_file_is_accepted() -> None:
    """The shape someone reaches for after the other two have gone wrong."""
    encoded = base64.b64encode(PEM.encode("utf-8")).decode("ascii")
    assert normalise_private_key(encoded) == PEM.strip()


def test_wrapped_base64_is_accepted() -> None:
    encoded = base64.b64encode(PEM.encode("utf-8")).decode("ascii")
    wrapped = "\n".join(encoded[i : i + 16] for i in range(0, len(encoded), 16))
    assert normalise_private_key(wrapped) == PEM.strip()


def test_unrecognisable_input_is_left_alone() -> None:
    """Not this module's job to reject it — apns.validate_private_key says why."""
    assert normalise_private_key("nonsense") == "nonsense"


def test_credentials_are_all_or_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three fields out of four cannot send anything, so they are not 'configured'."""
    monkeypatch.setenv("CANOPY_APNS_TEAM_ID", "TEAM123456")
    monkeypatch.setenv("CANOPY_APNS_KEY_ID", "KEY1234567")
    monkeypatch.setenv("CANOPY_APNS_BUNDLE_ID", "com.example.canopy")
    monkeypatch.delenv("CANOPY_APNS_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("CANOPY_APNS_PRIVATE_KEY_FILE", raising=False)

    assert ApnsCredentials.from_env() is None

    monkeypatch.setenv("CANOPY_APNS_PRIVATE_KEY", PEM)
    credentials = ApnsCredentials.from_env()
    assert credentials is not None
    assert credentials.bundle_id == "com.example.canopy"


def test_key_file_is_read_when_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    path = tmp_path / "AuthKey.p8"  # type: ignore[operator]
    path.write_text(PEM, encoding="utf-8")

    monkeypatch.setenv("CANOPY_APNS_TEAM_ID", "TEAM123456")
    monkeypatch.setenv("CANOPY_APNS_KEY_ID", "KEY1234567")
    monkeypatch.setenv("CANOPY_APNS_BUNDLE_ID", "com.example.canopy")
    monkeypatch.setenv("CANOPY_APNS_PRIVATE_KEY_FILE", str(path))

    credentials = ApnsCredentials.from_env()
    assert credentials is not None
    assert credentials.private_key_pem == PEM.strip()


def test_an_unreadable_key_file_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANOPY_APNS_PRIVATE_KEY_FILE", "/nope/AuthKey.p8")
    with pytest.raises(ConfigError):
        ApnsCredentials.from_env()


def test_a_missing_signing_secret_stops_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without it no API key can be verified, so every request would 401 anyway."""
    monkeypatch.delenv("CANOPY_APNS_SIGNING_SECRET", raising=False)
    with pytest.raises(ConfigError):
        load_settings()


def test_a_missing_apns_key_does_not_stop_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh deployment waiting on its .p8 is a supported state, not a crash."""
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    for name in ("CANOPY_APNS_TEAM_ID", "CANOPY_APNS_PRIVATE_KEY"):
        monkeypatch.delenv(name, raising=False)

    settings = load_settings()
    assert not settings.configured


def test_revocations_are_parsed_and_lowercased(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    monkeypatch.setenv("CANOPY_APNS_REVOKED_INSTANCES", " Acme , ,beta ")

    settings = load_settings()
    assert settings.is_revoked("acme")
    assert settings.is_revoked("beta")
    assert not settings.is_revoked("gamma")


def test_a_nonsense_rate_limit_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    monkeypatch.setenv("CANOPY_APNS_RATE_LIMIT", "lots")
    with pytest.raises(ConfigError):
        load_settings()


def test_enrollment_is_on_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """An admin ticking a checkbox must not have to think about API keys."""
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    monkeypatch.delenv("CANOPY_APNS_ENROLLMENT_ENABLED", raising=False)

    assert load_settings().enrollment_enabled is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [("false", False), ("no", False), ("0", False), ("off", False),
     ("true", True), ("yes", True), ("1", True), ("on", True)],
)
def test_enrollment_flag_accepts_what_people_actually_write(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    """Someone writing `no` where the docs said `false` should get what they meant."""
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    monkeypatch.setenv("CANOPY_APNS_ENROLLMENT_ENABLED", value)

    assert load_settings().enrollment_enabled is expected


def test_a_nonsense_enrollment_flag_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silently picking a default would be picking a security posture by accident."""
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")
    monkeypatch.setenv("CANOPY_APNS_ENROLLMENT_ENABLED", "sometimes")

    with pytest.raises(ConfigError):
        load_settings()
