"""Allow ``python -m lupaxa.dns_blacklist_checker`` to run the CLI."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
