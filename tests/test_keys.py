"""Instance API keys: derivation, verification, and what must not verify."""

from __future__ import annotations

import pytest

from canopy_apns.keys import (
    InvalidKey,
    generate_secret,
    mint,
    normalise_instance_id,
    verify,
)

SECRET = "secret-one"
OTHER_SECRET = "secret-two"


def test_mint_is_deterministic() -> None:
    """The same id and secret always produce the same key.

    This is what lets an admin who lost their key be handed the same one again
    without the relay having stored anything.
    """
    assert mint("acme", secret=SECRET) == mint("acme", secret=SECRET)


def test_mint_embeds_the_instance_id() -> None:
    key = mint("acme", secret=SECRET)
    assert key.startswith("canopy_acme_")
    assert verify(key, secret=SECRET).id == "acme"


def test_ids_are_normalised_before_signing() -> None:
    """Case and surrounding whitespace do not make a second, different key."""
    assert mint("  ACME  ", secret=SECRET) == mint("acme", secret=SECRET)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "has_underscore",
        "-leading",
        "trailing-",
        "Uppercase!",
        "a" * 64,
    ],
)
def test_unusable_instance_ids_are_refused_at_mint(bad: str) -> None:
    """Refused when the key is issued, not when it fails to parse later."""
    with pytest.raises(ValueError):
        normalise_instance_id(bad)


def test_a_key_from_another_secret_does_not_verify() -> None:
    """Rotating the signing secret is the break-glass revocation."""
    key = mint("acme", secret=OTHER_SECRET)
    with pytest.raises(InvalidKey):
        verify(key, secret=SECRET)


def test_a_tampered_instance_id_does_not_verify() -> None:
    """The instance id is legible, so the signature is what has to hold."""
    key = mint("acme", secret=SECRET)
    _, _, signature = key.split("_")
    with pytest.raises(InvalidKey):
        verify(f"canopy_victim_{signature}", secret=SECRET)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-key",
        "canopy_acme",
        "canopy_acme_sig_extra",
        "wrongprefix_acme_sig",
        "canopy_has_underscore",
    ],
)
def test_malformed_keys_are_refused(bad: str) -> None:
    with pytest.raises(InvalidKey):
        verify(bad, secret=SECRET)


def test_generated_secrets_are_distinct_and_long() -> None:
    first, second = generate_secret(), generate_secret()
    assert first != second
    assert len(first) >= 40
