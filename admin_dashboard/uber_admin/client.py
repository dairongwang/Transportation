"""
Client for the ServiceUber Admin API (/admin-api/v1) - the dashboard's only link to the app.

Standard library only. Every request carries the bearer token; decisions also carry the
deciding manager in X-Admin-Actor so the app records who decided. Errors are mapped to:

  MainAppUnavailable   the app cannot be reached (down, wrong URL, timeout)
  MainAppError         the app answered with an error (401 bad token, 404, 409 not possible now, ...)
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request


class MainAppError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(message)


class MainAppUnavailable(MainAppError):
    def __init__(self, message: str) -> None:
        super().__init__(503, message)


class MainAppClient:
    def __init__(self, base_url: str, token: str, timeout: float = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ------------------------------------------------------------ transport
    def _request(self, method: str, path: str, params: dict | None = None, body: dict | None = None,
                 actor: str | None = None) -> dict:
        query = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        url = self.base_url + path + (("?" + urllib.parse.urlencode(query)) if query else "")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                   "User-Agent": "ServiceUber-Admin/1.0"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if actor:
            headers["X-Admin-Actor"] = actor
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - configured URL
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read().decode()).get("error") or exc.reason
            except (ValueError, AttributeError):
                message = str(exc.reason)
            raise MainAppError(exc.code, str(message)) from None
        except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
            reason = getattr(exc, "reason", exc)
            raise MainAppUnavailable(f"ServiceUber is not reachable at {self.base_url} ({reason}).") from None
        except ValueError:
            raise MainAppError(502, "ServiceUber returned an invalid response.") from None

    def open_events(self, read_timeout: float = 45):
        """
        Open ServiceUber's event stream (SSE) and return the streaming response (read it line by
        line). The server sends a keepalive every 15 s, so `read_timeout` detects a dead link.
        """
        req = urllib.request.Request(self.base_url + "/events", headers={
            "Authorization": f"Bearer {self.token}", "Accept": "text/event-stream", "User-Agent": "ServiceUber-Admin/1.0"})
        try:
            return urllib.request.urlopen(req, timeout=read_timeout)  # noqa: S310 - configured URL
        except urllib.error.HTTPError as exc:
            raise MainAppError(exc.code, "the event stream was refused" + (" (token)" if exc.code == 401 else "")) from None
        except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
            raise MainAppUnavailable(f"ServiceUber is not reachable at {self.base_url} ({getattr(exc, 'reason', exc)}).") from None

    # ------------------------------------------------------------ API
    def health(self) -> dict:
        return self._request("GET", "/health")

    def summary(self) -> dict:
        return self._request("GET", "/summary")

    def list_checks(self, status: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        return self._request("GET", "/background-checks", {"status": status, "q": q, "limit": limit, "offset": offset})

    def get_check(self, check_id: int) -> dict:
        return self._request("GET", f"/background-checks/{int(check_id)}")

    def decide_check(self, check_id: int, decision: str, note: str | None, actor: str) -> dict:
        return self._request("POST", f"/background-checks/{int(check_id)}/decision",
                             body={"decision": decision, "note": note}, actor=actor)

    def list_users(self, role: str | None = None, status: str | None = None, q: str | None = None,
                   min_age: int | None = None, max_age: int | None = None, sort: str | None = None,
                   limit: int = 50, offset: int = 0) -> dict:
        return self._request("GET", "/users", {"role": role, "status": status, "q": q, "min_age": min_age,
                                               "max_age": max_age, "sort": sort, "limit": limit, "offset": offset})

    def get_user(self, user_id: int) -> dict:
        return self._request("GET", f"/users/{int(user_id)}")

    def list_user_transactions(self, user_id: int, date_from: str | None = None, date_to: str | None = None,
                               method: str | None = None, ttype: str | None = None, limit: int = 50,
                               offset: int = 0) -> dict:
        return self._request("GET", f"/users/{int(user_id)}/transactions", {
            "date_from": date_from, "date_to": date_to, "method": method, "type": ttype, "limit": limit, "offset": offset})

    def get_transaction(self, tx_id: int) -> dict:
        return self._request("GET", f"/transactions/{int(tx_id)}")

    def refund_transaction(self, tx_id: int, amount: str, reason: str, actor: str) -> dict:
        return self._request("POST", f"/transactions/{int(tx_id)}/refund", body={"amount": amount, "reason": reason},
                             actor=actor)

    def list_disputes(self, status: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        return self._request("GET", "/disputes", {"status": status, "limit": limit, "offset": offset})

    def get_dispute(self, dispute_id: int) -> dict:
        return self._request("GET", f"/disputes/{int(dispute_id)}")

    def decide_dispute(self, dispute_id: int, decision: str, note: str | None, actor: str) -> dict:
        return self._request("POST", f"/disputes/{int(dispute_id)}/decision",
                             body={"decision": decision, "note": note}, actor=actor)
