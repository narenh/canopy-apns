"""``python -m canopy_apns`` — the provisioning surface, such as it is."""

from __future__ import annotations

import pytest

from canopy_apns.__main__ import _setting, main
from canopy_apns.keys import mint, verify


def test_secret_prints_something_usable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["secret"]) == 0
    printed = capsys.readouterr().out.strip()
    assert len(printed) >= 40


def test_mint_prints_a_key_that_verifies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")

    assert main(["mint", "notcanopy"]) == 0

    printed = capsys.readouterr().out.strip()
    assert printed == mint("notcanopy", secret="s3cret")
    assert verify(printed, secret="s3cret").id == "notcanopy"


def test_mint_without_the_secret_says_where_to_get_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Minting with the wrong secret would print a key that silently 401s."""
    monkeypatch.delenv("CANOPY_APNS_SIGNING_SECRET", raising=False)

    assert main(["mint", "notcanopy"]) == 2
    assert "CANOPY_APNS_SIGNING_SECRET" in capsys.readouterr().err


def test_mint_refuses_an_unusable_instance_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CANOPY_APNS_SIGNING_SECRET", "s3cret")

    assert main(["mint", "Not Valid"]) == 2
    assert "instance id" in capsys.readouterr().err


def test_serve_settings_treat_blank_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deploy UI sends an untouched field as ``""``, not as absent.

    ``os.environ.get(name, default)`` only applies the default when the
    variable is missing, so an empty Coolify field used to reach uvicorn as
    ``log_level=""`` (``KeyError``) or ``port=int("")`` (``ValueError``) —
    a crash loop on deploy, produced by touching nothing.
    """
    for name in (
        "CANOPY_APNS_HOST",
        "CANOPY_APNS_PORT",
        "CANOPY_APNS_LOG_LEVEL",
        "CANOPY_APNS_FORWARDED_ALLOW_IPS",
    ):
        monkeypatch.setenv(name, "")

    assert _setting("CANOPY_APNS_HOST", "0.0.0.0") == "0.0.0.0"
    assert int(_setting("CANOPY_APNS_PORT", "9247")) == 9247
    assert _setting("CANOPY_APNS_LOG_LEVEL", "info") == "info"
    assert _setting("CANOPY_APNS_FORWARDED_ALLOW_IPS", "*") == "*"


def test_serve_settings_strip_and_honour_real_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whitespace-only is blank too, and a real value still wins."""
    monkeypatch.setenv("CANOPY_APNS_LOG_LEVEL", "   ")
    assert _setting("CANOPY_APNS_LOG_LEVEL", "info") == "info"

    monkeypatch.setenv("CANOPY_APNS_LOG_LEVEL", " debug ")
    assert _setting("CANOPY_APNS_LOG_LEVEL", "info") == "debug"

    monkeypatch.delenv("CANOPY_APNS_LOG_LEVEL")
    assert _setting("CANOPY_APNS_LOG_LEVEL", "info") == "info"
