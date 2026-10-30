#!/usr/bin/env python3
"""
Fake authenticator app (stub for Google Authenticator / Authy) — standard library only.

Use it on any desktop OS to test the "Authenticator app" 2FA method without a phone:

    python scripts/fake_authenticator.py JBSW Y3DP EHPK 3PXP          # manual key from the setup page
    python scripts/fake_authenticator.py "otpauth://totp/...?secret=..." # or the otpauth URI
    python scripts/fake_authenticator.py <key> --watch                   # keep printing new codes
"""

import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _totp_loader import load_totp  # noqa: E402

totp = load_totp()


def extract_secret(args: list[str]) -> str:
    joined = "".join(a for a in args if not a.startswith("--")).strip()
    if joined.lower().startswith("otpauth://"):
        query = urllib.parse.urlparse(joined).query
        return urllib.parse.parse_qs(query)["secret"][0]
    return joined.replace(" ", "").upper()


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    secret = extract_secret(sys.argv[1:])
    watch = "--watch" in sys.argv
    try:
        while True:
            now = time.time()
            remaining = 30 - int(now) % 30
            print(f"code: {totp.totp(secret, now)}   (valid for {remaining:2d}s)", flush=True)
            if not watch:
                return 0
            time.sleep(remaining)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
