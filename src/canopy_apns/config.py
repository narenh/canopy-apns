"""Everything the relay is configured with, read once from the environment.

The relay holds exactly one secret worth stealing — the APNs signing key — and
one worth forging with — the instance-key signing secret.  Neither is ever
written to disk, entered through a UI, or stored in a database, because this
service has none of those things.  They arrive as environment variables, which
on Coolify means the deployment's secret variables and nothing else.

Two consequences fall out of that and are deliberate:

* **Configuration is process-wide and immutable.**  Changing a credential is a
  redeploy.  There is no admin page to get wrong and no config row to drift.
* **A missing credential is a startup-visible state, not a per-request
  surprise.**  :func:`load_settings` returns ``None`` for the APNs half when it
  is not set up yet, and the app reports that on ``/health`` and refuses pushes
  with a 503 rather than failing each one in a different way.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field

DEFAULT_RATE_LIMIT_PER_MINUTE = 120
DEFAULT_RATE_BURST = 30

#: Longest payload strings the relay will forward.  APNs caps the whole
#: notification at 4KB; these keep any one field from eating it, and keep the
#: relay from being used as a general-purpose message bus.
MAX_TITLE_LENGTH = 200
MAX_SUBTITLE_LENGTH = 200
MAX_DATA_BYTES = 1024


class ConfigError(Exception):
    """The environment is set up in a way the relay cannot run with.

    Raised only for a value that is present but unusable — a garbled key, a
    non-numeric rate limit.  *Absent* is not an error: see the module docstring.
    """


def _clean(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _int(name: str, default: int) -> int:
    raw = _clean(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {value}")
    return value


def normalise_private_key(raw: str) -> str:
    """Coax a ``.p8`` out of whatever an environment variable can carry.

    A PEM file is multi-line and most secret-variable editors are not, so the
    same key reaches this service in one of three shapes depending on how it was
    pasted.  All three are accepted rather than documenting one and rejecting
    the other two at 3am:

    * the PEM verbatim, real newlines and all;
    * the PEM with literal backslash-``n`` where the newlines were, which is
      what happens when a value is pasted through a shell or a JSON field;
    * base64 of the whole PEM file, which is what someone reaches for after the
      first two have gone wrong.

    Only the shape is fixed here.  Whether the result is a usable ES256 key is
    :func:`canopy_apns.apns.validate_private_key`'s question, and it is asked at
    startup.
    """
    text = raw.strip()
    if not text:
        return ""

    if "BEGIN" not in text:
        # No PEM armour anywhere: the only remaining candidate is base64 of the
        # file. Whitespace is stripped first because a wrapped base64 blob is
        # still valid base64 and a very common way to paste one.
        compact = "".join(text.split())
        try:
            decoded = base64.b64decode(compact, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return text
        text = decoded.strip()

    return text.replace("\\n", "\n")


@dataclass(frozen=True)
class ApnsCredentials:
    """The four values needed to sign and address a push.

    All four or none: three of them cannot send anything, and treating a
    half-filled environment as configured would turn a typo into a stream of
    delivery failures instead of one clear startup message.
    """

    team_id: str
    key_id: str
    bundle_id: str
    private_key_pem: str

    @classmethod
    def from_env(cls) -> ApnsCredentials | None:
        team_id = _clean("CANOPY_APNS_TEAM_ID")
        key_id = _clean("CANOPY_APNS_KEY_ID")
        bundle_id = _clean("CANOPY_APNS_BUNDLE_ID")

        key_path = _clean("CANOPY_APNS_PRIVATE_KEY_FILE")
        if key_path:
            try:
                with open(key_path, encoding="utf-8") as handle:
                    private_key_pem = normalise_private_key(handle.read())
            except OSError as exc:
                raise ConfigError(
                    f"CANOPY_APNS_PRIVATE_KEY_FILE points at {key_path!r}, "
                    f"which could not be read: {exc}"
                ) from exc
        else:
            private_key_pem = normalise_private_key(_clean("CANOPY_APNS_PRIVATE_KEY"))

        if not (team_id and key_id and bundle_id and private_key_pem):
            return None

        return cls(
            team_id=team_id,
            key_id=key_id,
            bundle_id=bundle_id,
            private_key_pem=private_key_pem,
        )


@dataclass(frozen=True)
class Settings:
    """The whole of the relay's configuration."""

    apns: ApnsCredentials | None
    """``None`` until the signing key is in the environment.  The service still
    starts, still serves ``/health``, and refuses pushes with a 503 that says
    so — which is a far better state to deploy into than a crash loop."""

    signing_secret: str
    """HMAC secret behind every instance API key.  Rotating it invalidates every
    key that has ever been issued, which is the break-glass revocation."""

    revoked_instances: frozenset[str] = frozenset()
    """Instance ids whose keys are refused despite carrying a valid signature.
    The per-instance revocation, for when one instance misbehaves and rotating
    the secret would punish everyone."""

    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE
    rate_burst: int = DEFAULT_RATE_BURST

    apns_timeout_seconds: float = 10.0

    extra: dict[str, str] = field(default_factory=dict)
    """Room for values a later version adds, so tests can build a Settings
    without every call site learning a new keyword."""

    @property
    def configured(self) -> bool:
        return self.apns is not None

    def is_revoked(self, instance_id: str) -> bool:
        return instance_id in self.revoked_instances


def load_settings() -> Settings:
    """Build :class:`Settings` from the process environment.

    Raises :class:`ConfigError` when the environment is unusable — which for
    the signing secret means *absent*, since without it no API key can be
    verified and every request would be rejected anyway.  Failing at startup
    with one sentence beats serving nothing but 401s.
    """
    signing_secret = _clean("CANOPY_APNS_SIGNING_SECRET")
    if not signing_secret:
        raise ConfigError(
            "CANOPY_APNS_SIGNING_SECRET is not set. Generate one with "
            "`python -m canopy_apns secret` and set it on the deployment; "
            "every instance API key is derived from it."
        )

    revoked = {
        part.strip().lower()
        for part in _clean("CANOPY_APNS_REVOKED_INSTANCES").split(",")
        if part.strip()
    }

    return Settings(
        apns=ApnsCredentials.from_env(),
        signing_secret=signing_secret,
        revoked_instances=frozenset(revoked),
        rate_limit_per_minute=_int("CANOPY_APNS_RATE_LIMIT", DEFAULT_RATE_LIMIT_PER_MINUTE),
        rate_burst=_int("CANOPY_APNS_RATE_BURST", DEFAULT_RATE_BURST),
    )


__all__ = [
    "DEFAULT_RATE_BURST",
    "DEFAULT_RATE_LIMIT_PER_MINUTE",
    "MAX_DATA_BYTES",
    "MAX_SUBTITLE_LENGTH",
    "MAX_TITLE_LENGTH",
    "ApnsCredentials",
    "ConfigError",
    "Settings",
    "load_settings",
    "normalise_private_key",
]
