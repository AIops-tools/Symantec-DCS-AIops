"""Bounded, tenant-scoped DCS transport. Only documented read requests are exposed."""

from __future__ import annotations

import os
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx


class DcsError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class DcsConnection:
    def __init__(self, client: httpx.Client | None = None) -> None:
        url = os.environ.get("SYMANTEC_DCS_URL", "").rstrip("/")
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise DcsError("Set SYMANTEC_DCS_URL to the API HTTPS origin")
        try:
            timeout = float(os.environ.get("SYMANTEC_DCS_TIMEOUT", "30"))
        except ValueError as exc:
            raise DcsError("SYMANTEC_DCS_TIMEOUT must be positive") from exc
        if timeout <= 0:
            raise DcsError("SYMANTEC_DCS_TIMEOUT must be positive")
        username = os.environ.get("SYMANTEC_DCS_USERNAME", "")
        password = os.environ.get("SYMANTEC_DCS_PASSWORD", "")
        if not username or not password:
            raise DcsError("Set SYMANTEC_DCS_USERNAME and SYMANTEC_DCS_PASSWORD")
        self._credentials = (username, password)
        verify = os.environ.get("SYMANTEC_DCS_CA_BUNDLE") or True
        self._client = client or httpx.Client(base_url=url, timeout=timeout, verify=verify)
        self._token: str | None = None
        self._expires_at = 0.0
        self._auth_retry_at = 0.0
        self._lock = threading.RLock()

    def close(self) -> None:
        self._client.close()

    def _authenticate(self) -> None:
        if time.monotonic() < self._auth_retry_at:
            raise DcsError("DCS login was rejected recently; wait before retrying credentials")
        try:
            response = self._client.post(
                "/sis-ui/api/v2/auth/token",
                json={
                    "username": self._credentials[0],
                    "password": self._credentials[1],
                    "smartcard": False,
                    "scope": "ENTERPRISE_MANAGER",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise DcsError("DCS login timed out; check URL and timeout") from exc
        except httpx.HTTPError as exc:
            raise DcsError("Cannot reach DCS login; check URL and TLS") from exc
        if response.status_code in (400, 401, 403):
            self._auth_retry_at = time.monotonic() + 30
            raise DcsError("DCS rejected credentials or client privileges")
        if response.status_code >= 400:
            raise DcsError(f"DCS login returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise DcsError("DCS login returned non-JSON data") from exc
        if not isinstance(data, dict):
            raise DcsError("DCS login returned an unexpected response")
        token = data.get("access_token")
        raw_expiry = data.get("expires_in")
        if not isinstance(token, str) or not token:
            raise DcsError("DCS login response has no token")
        if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, (int, str)):
            raise DcsError("DCS login response has invalid expires_in")
        try:
            expiry = int(raw_expiry)
        except ValueError as exc:
            raise DcsError("DCS login response has invalid expires_in") from exc
        if expiry <= 0:
            raise DcsError("DCS login response has invalid expires_in")
        self._token = token
        self._expires_at = time.monotonic() + max(1, expiry - 60)
        self._auth_retry_at = 0.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if path.startswith("//") or not (
            path.startswith("/sis-ui/api/v1/") or path.startswith("/sis-ui/api/v2/")
        ):
            raise ValueError("Undocumented DCS resource path")
        if method != "GET" and (method != "POST" or not (False)):
            raise ValueError("DCS transport only exposes documented read operations")
        if method == "POST" and not isinstance(payload, dict):
            raise ValueError("Query body must be an object")
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires_at:
                self._authenticate()
            for attempt in range(2):
                try:
                    response = self._client.request(
                        method,
                        path,
                        params=params,
                        json=payload,
                        headers={
                            "Authorization": f"JWT {self._token}",
                            "Accept": "application/json",
                        },
                    )
                except httpx.TimeoutException as exc:
                    raise DcsError(f"DCS timed out on {path}") from exc
                except httpx.HTTPError as exc:
                    raise DcsError(f"Cannot reach DCS on {path}; check URL and TLS") from exc
                if response.status_code == 401 and attempt == 0:
                    self._token = None
                    self._authenticate()
                    continue
                if response.status_code >= 400:
                    hint = "Check client privilege and resource ID."
                    if response.status_code == 429:
                        hint = "API quota exceeded; retry after the server limit resets."
                    elif response.status_code >= 500:
                        hint = "Check service health before retrying."
                    raise DcsError(
                        f"DCS returned HTTP {response.status_code} for {path}. {hint}",
                        status_code=response.status_code,
                    )
                if not response.content:
                    raise DcsError(f"DCS returned an empty response for {path}")
                try:
                    return response.json()
                except ValueError as exc:
                    raise DcsError(f"DCS returned non-JSON data for {path}") from exc
            raise DcsError("DCS authentication retry failed")

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def query(self, path: str, payload: dict[str, Any]) -> Any:
        return self._request("POST", path, payload=payload)


_connection: DcsConnection | None = None
_connection_lock = threading.Lock()


def get_connection() -> DcsConnection:
    global _connection
    with _connection_lock:
        if _connection is None:
            _connection = DcsConnection()
        return _connection
