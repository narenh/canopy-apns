"""``python -m canopy_apns`` — serve, or issue a key.

Three subcommands, because the relay has exactly three things anyone does with
it:

``serve`` (the default)
    Run the HTTP service. What the container entrypoint invokes.

``secret``
    Print a fresh signing secret, for first setup. Run once, put the output in
    ``CANOPY_APNS_SIGNING_SECRET``, never run it again — regenerating it
    invalidates every API key ever issued.

``mint <instance-id>``
    Print the API key for one instance. This is the whole of the provisioning
    flow: no database write, no HTTP call, nothing to keep in sync. Run it,
    send the key to whoever asked, forget it. Running it twice for the same id
    prints the same key, so a lost key is re-issued rather than replaced.

``mint`` is a local command on purpose. An HTTP endpoint that hands out keys is
an HTTP endpoint that hands out keys to anyone who finds it, and a rate limit
per key means nothing if keys are free.
"""

from __future__ import annotations

import argparse
import os
import sys

from .keys import generate_secret, mint


def _serve() -> int:
    import uvicorn

    from .app import create_app

    host = os.environ.get("CANOPY_APNS_HOST", "0.0.0.0")  # noqa: S104 - containerised
    port = int(os.environ.get("CANOPY_APNS_PORT", "9247"))
    log_level = os.environ.get("CANOPY_APNS_LOG_LEVEL", "info")
    # Enrollment is rate-limited per source address, so the app has to see the
    # real client rather than the proxy in front of it. Letting uvicorn apply
    # `X-Forwarded-For` means `request.client.host` is already correct and no
    # endpoint has to parse a header it could get wrong.
    #
    # `*` trusts whatever sent the header, which is right behind a proxy that
    # overwrites it and wrong if the port is reachable directly — a client
    # could then claim any address it liked and get a fresh bucket per request.
    # Narrow it to the proxy's address if this is ever exposed unproxied.
    forwarded_allow_ips = os.environ.get("CANOPY_APNS_FORWARDED_ALLOW_IPS", "*")

    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        log_level=log_level,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
    )
    return 0


def _mint(instance_id: str) -> int:
    secret = (os.environ.get("CANOPY_APNS_SIGNING_SECRET") or "").strip()
    if not secret:
        print(
            "CANOPY_APNS_SIGNING_SECRET is not set in this shell. Minting needs "
            "the same secret the relay runs with — copy it from the deployment's "
            "environment, or run this inside the running container.",
            file=sys.stderr,
        )
        return 2

    try:
        print(mint(instance_id, secret=secret))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="canopy-apns", description=__doc__)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="Run the relay (default).")
    sub.add_parser("secret", help="Print a fresh CANOPY_APNS_SIGNING_SECRET.")

    mint_parser = sub.add_parser("mint", help="Print one instance's API key.")
    mint_parser.add_argument(
        "instance_id",
        help="Short identifier for the instance, e.g. 'notcanopy'. Lowercase "
        "letters, digits and hyphens.",
    )

    args = parser.parse_args(argv)

    if args.command == "secret":
        print(generate_secret())
        return 0
    if args.command == "mint":
        return _mint(args.instance_id)
    return _serve()


if __name__ == "__main__":
    raise SystemExit(main())
