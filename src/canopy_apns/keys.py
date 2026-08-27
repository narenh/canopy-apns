"""Instance API keys, derived rather than stored.

An API key here is not a random string looked up in a table — there is no
table.  It is an instance id with a MAC over it:

``canopy_<instance-id>_<signature>``

The relay verifies a key by recomputing the signature from
``CANOPY_APNS_SIGNING_SECRET`` and comparing.  That is the whole mechanism, and
it is what lets the service be genuinely stateless: no database, no volume, no
migration, nothing to back up, and two replicas that cannot disagree about who
is allowed in.

What it buys and what it costs, plainly:

* **Issuing a key writes nothing.**  Whether it comes from
  ``python -m canopy_apns mint acme`` or from ``POST /v1/instances``, the key is
  computed, handed over, and forgotten.  That is what lets self-service
  enrollment exist at all without the relay growing a database: enrollment
  invents a random id (:func:`generate_instance_id`) and derives its key, with
  no allocation to record and no uniqueness check to serialise.
* **The instance id is legible in the key.**  Deliberate: it is what logs and
  rate-limit buckets are keyed on, and it means a key found in a bug report can
  be attributed without a lookup.  It is an identifier, not a secret; the
  signature is the secret part.
* **Revocation is a list, not a delete.**  A derived key cannot be un-derived,
  so revoking one means naming its instance in
  ``CANOPY_APNS_REVOKED_INSTANCES``.  Revoking *everything* means rotating the
  signing secret.  Both are redeploys, and both are the price of having no
  persistence at all.

The instance id's character set is constrained so that ``_`` stays an
unambiguous separator: ids may not contain one, so the key always splits into
exactly three parts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

KEY_PREFIX = "canopy"

#: Lowercase alphanumerics and internal hyphens.  No underscore — that is the
#: field separator — and no leading or trailing hyphen, so an id is always
#: something a human can read back over the phone.
INSTANCE_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

#: 16 bytes of HMAC-SHA256 output.  Truncating a MAC is safe and standard; 128
#: bits is far past forging range for a value an attacker can only test online
#: against a rate-limited endpoint.
SIGNATURE_BYTES = 16


class InvalidKey(Exception):
    """The presented key is not one this relay issued.

    Carries no detail about *why* on purpose — the caller gets one flat
    rejection, so a probing client learns nothing about whether the instance id
    exists, the signature was close, or the secret has been rotated.
    """


@dataclass(frozen=True)
class Instance:
    """A caller the relay has authenticated."""

    id: str


def _encode(raw: bytes) -> str:
    """Base32, lowercased, unpadded.

    Base64url would be shorter, but its alphabet includes ``_`` — which is the
    field separator, so a key would not reliably split into three parts. Base32
    keeps the whole key to ``[a-z0-9-]`` plus the separators: safe in a URL, in
    a shell, and in a double-click selection.
    """
    return base64.b32encode(raw).rstrip(b"=").decode("ascii").lower()


def normalise_instance_id(instance_id: str) -> str:
    """Lowercase and trim an id, or raise :class:`ValueError` if unusable.

    Applied at mint time so a key can never be issued for an id that
    :func:`verify` would then refuse to parse back out.
    """
    candidate = instance_id.strip().lower()
    if not INSTANCE_ID_PATTERN.match(candidate):
        raise ValueError(
            "An instance id is 1-63 characters of lowercase letters, digits and "
            "internal hyphens — no underscores, since that separates the parts "
            f"of a key. Got {instance_id!r}."
        )
    return candidate


def sign(instance_id: str, *, secret: str) -> str:
    """The signature half of ``instance_id``'s key."""
    mac = hmac.new(secret.encode("utf-8"), instance_id.encode("utf-8"), hashlib.sha256)
    return _encode(mac.digest()[:SIGNATURE_BYTES])


def mint(instance_id: str, *, secret: str) -> str:
    """The API key for ``instance_id``. Deterministic: same id, same key.

    Determinism is the point — an admin who has lost the key they were given
    can be handed the same one again without anything having to remember it.
    It also means minting twice is harmless rather than quietly orphaning the
    first key.
    """
    normalised = normalise_instance_id(instance_id)
    return f"{KEY_PREFIX}_{normalised}_{sign(normalised, secret=secret)}"


def verify(api_key: str, *, secret: str) -> Instance:
    """Authenticate ``api_key``, returning who it belongs to.

    Raises :class:`InvalidKey` for anything that is not a well-formed key
    carrying a correct signature.  Revocation is *not* checked here — that is
    :class:`~canopy_apns.config.Settings`' business, and keeping it out means
    this function stays a pure function of the key and the secret and can be
    tested as one.
    """
    parts = (api_key or "").strip().split("_")
    if len(parts) != 3:
        raise InvalidKey("malformed key")

    prefix, instance_id, signature = parts
    if prefix != KEY_PREFIX or not INSTANCE_ID_PATTERN.match(instance_id):
        raise InvalidKey("malformed key")

    # Constant-time, because the comparison is the only thing standing between
    # a guessed signature and a valid one.
    if not hmac.compare_digest(signature, sign(instance_id, secret=secret)):
        raise InvalidKey("bad signature")

    return Instance(id=instance_id)


def generate_secret() -> str:
    """A fresh signing secret, for `python -m canopy_apns secret`."""
    return secrets.token_urlsafe(48)


#: Bytes of randomness behind a self-enrolled instance id.  96 bits, which is
#: about collision-avoidance rather than secrecy: the id is not the secret half
#: of a key, and knowing one gets an attacker no closer to its signature.
INSTANCE_ID_BYTES = 12


def generate_instance_id() -> str:
    """A fresh random instance id, for self-service enrollment.

    Enrollment has to hand out an identity without storing one, so it invents a
    random id and derives the key from it exactly as :func:`mint` would.  That
    is the whole of what makes ``POST /v1/instances`` a stateless endpoint:
    there is no allocation to record and no uniqueness check to serialise,
    because 96 bits of randomness makes a collision not worth the code to
    prevent.

    Base32 keeps the result inside :data:`INSTANCE_ID_PATTERN` (lowercase
    letters and digits only) with no separator characters to trip over.
    """
    return _encode(secrets.token_bytes(INSTANCE_ID_BYTES))


__all__ = [
    "INSTANCE_ID_BYTES",
    "INSTANCE_ID_PATTERN",
    "KEY_PREFIX",
    "Instance",
    "InvalidKey",
    "generate_instance_id",
    "generate_secret",
    "mint",
    "normalise_instance_id",
    "sign",
    "verify",
]
