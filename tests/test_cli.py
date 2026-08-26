"""``python -m canopy_apns`` — the provisioning surface, such as it is."""

from __future__ import annotations

import pytest

from canopy_apns.__main__ import main
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
