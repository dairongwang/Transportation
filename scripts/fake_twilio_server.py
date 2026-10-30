#!/usr/bin/env python3
"""
Fake Twilio REST API (stub for the SMS provider) — standard library only, any OS.

Implements POST /2010-04-01/Accounts/<sid>/Messages.json like Twilio does, validates
that Basic auth is present, prints every SMS and appends it to instance/auth_outbox.jsonl
so it shows up on the app's /dev/outbox page.

    python scripts/fake_twilio_server.py             # listen on 127.0.0.1:8089

Then run the app with:
    SMS_BACKEND=twilio TWILIO_API_BASE=http://127.0.0.1:8089
    TWILIO_ACCOUNT_SID=DUMMY_TWILIO_ACCOUNT_SID TWILIO_AUTH_TOKEN=DUMMY_TWILIO_AUTH_TOKEN TWILIO_FROM_NUMBER=+15550100000
"""

import json
import sys
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUTBOX = Path(__file__).resolve().parents[1] / "instance" / "auth_outbox.jsonl"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quieter
        pass

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self.path.startswith("/2010-04-01/Accounts/") or not self.path.endswith("/Messages.json"):
            return self._json(404, {"code": 20404, "message": "not found"})
        if not self.headers.get("Authorization", "").startswith("Basic "):
            return self._json(401, {"code": 20003, "message": "Authenticate"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        to, sender, body = form.get("To", [""])[0], form.get("From", [""])[0], form.get("Body", [""])[0]
        record = {"channel": "sms", "to": to, "subject": "sms", "body": body,
                  "sent_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}
        print("=" * 60)
        print(f"SMS FROM {sender}  TO {to}\n\n{body}")
        print("=" * 60, flush=True)
        OUTBOX.parent.mkdir(exist_ok=True)
        with OUTBOX.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        self._json(201, {"sid": "SMDUMMY0000000000000000000000000000", "status": "queued", "to": to, "from": sender})


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8089
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Fake Twilio API listening on http://{host}:{port}  (Ctrl+C to stop)")
        print(f"Run the app with: SMS_BACKEND=twilio TWILIO_API_BASE=http://{host}:{port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
