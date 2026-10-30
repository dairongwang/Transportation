#!/usr/bin/env python3
"""
Fake SMTP server (stub for a real mail provider) — standard library only, any OS.

Accepts mail on 127.0.0.1:2525, prints every message to the console and appends it to
instance/auth_outbox.jsonl so it also shows up on the app's /dev/outbox page.

    python scripts/fake_smtp_server.py              # listen on 127.0.0.1:2525
    python scripts/fake_smtp_server.py 0.0.0.0 2525 # listen on all interfaces

Then run the app with:  EMAIL_BACKEND=smtp SMTP_HOST=127.0.0.1 SMTP_PORT=2525
"""

import email
import json
import socketserver
import sys
from datetime import datetime, timezone
from pathlib import Path

OUTBOX = Path(__file__).resolve().parents[1] / "instance" / "auth_outbox.jsonl"


class Handler(socketserver.StreamRequestHandler):
    def reply(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        self.reply("220 fake-smtp ready")
        sender, rcpts, data = "", [], None
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            verb = line.split(" ", 1)[0].upper()
            if verb in ("HELO", "EHLO"):
                self.reply("250-fake-smtp")
                self.reply("250 AUTH PLAIN LOGIN")
            elif verb == "AUTH":
                self.reply("235 ok (auth ignored by fake server)")
            elif verb == "STARTTLS":
                self.reply("454 TLS not available on the fake server (set SMTP_USE_TLS=false)")
            elif verb == "MAIL":
                sender = line.split(":", 1)[1].strip()
                self.reply("250 ok")
            elif verb == "RCPT":
                rcpts.append(line.split(":", 1)[1].strip().strip("<>"))
                self.reply("250 ok")
            elif verb == "DATA":
                self.reply("354 end with <CRLF>.<CRLF>")
                lines = []
                while True:
                    l = self.rfile.readline().decode(errors="replace")
                    if l in (".\r\n", ".\n"):
                        break
                    lines.append(l[1:] if l.startswith("..") else l)
                data = "".join(lines)
                self.deliver(sender, rcpts, data)
                self.reply("250 queued")
                sender, rcpts = "", []
            elif verb == "QUIT":
                self.reply("221 bye")
                return
            elif verb in ("RSET", "NOOP"):
                self.reply("250 ok")
            else:
                self.reply("500 unrecognised")

    def deliver(self, sender: str, rcpts: list[str], data: str) -> None:
        msg = email.message_from_string(data)
        body = msg.get_payload(decode=True)
        body = body.decode(errors="replace") if isinstance(body, bytes) else str(msg.get_payload())
        record = {
            "channel": "email",
            "to": ", ".join(rcpts),
            "subject": msg.get("Subject", ""),
            "body": body.strip(),
            "sent_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        }
        print("=" * 60)
        print(f"FROM {sender}  TO {record['to']}\nSUBJECT {record['subject']}\n\n{record['body']}")
        print("=" * 60, flush=True)
        OUTBOX.parent.mkdir(exist_ok=True)
        with OUTBOX.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2525
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), Handler) as server:
        print(f"Fake SMTP server listening on {host}:{port}  (Ctrl+C to stop)")
        print("Run the app with: EMAIL_BACKEND=smtp SMTP_HOST=127.0.0.1 SMTP_PORT=%d SMTP_USE_TLS=false" % port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
