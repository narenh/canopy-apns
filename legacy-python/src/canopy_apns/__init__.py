"""A stateless APNs forwarder for self-hosted Canopy+ instances.

The relay exists so that one Apple Developer account's signing key can serve
every self-hosted instance of the same app, without that key being copied onto
machines its owner does not run.

``config``
    Environment variables in, one frozen ``Settings`` out. The only place the
    process learns a credential.

``keys``
    Instance API keys, derived from an HMAC rather than stored. The reason
    there is no database.

``apns``
    Provider-token signing and the HTTP/2 push to Apple. Knows nothing about
    instances.

``ratelimit``
    A token bucket per instance, so one misconfigured caller cannot spend the
    operator's reputation with Apple.

``app``
    The four endpoints, and the isolation argument they rest on: a device token
    is a parameter of a forward and is never stored, so an instance can only
    reach devices it was already given.

``landing``
    What a browser gets at ``/``. Not a UI: a diagnostic that shows the scheme
    and forwarding headers the relay saw, so a TLS-termination problem is one
    page load rather than one log dive.
"""

from .keys import mint, verify

__all__ = ["mint", "verify"]
