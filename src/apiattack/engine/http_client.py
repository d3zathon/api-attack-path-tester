"""Thin wrapper around requests.Session that:
  - injects a Role's auth headers
  - times and logs every call as Evidence (for report generation)
  - applies a configurable delay between requests (be a considerate test client)
  - truncates response bodies to keep evidence readable/redacted
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests

from ..models import Evidence, Role

MAX_BODY_EXCERPT = 2000
REDACT_HEADERS = {"authorization", "cookie", "x-api-key"}


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in headers.items():
        out[k] = "***REDACTED***" if k.lower() in REDACT_HEADERS else v
    return out


class HttpClient:
    def __init__(self, base_url: str, rate_limit_delay_ms: int = 150, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.rate_limit_delay_ms = rate_limit_delay_ms
        self.timeout = timeout
        self.session = requests.Session()
        self._last_call = 0.0

    def _throttle(self):
        if self.rate_limit_delay_ms <= 0:
            return
        elapsed = time.time() - self._last_call
        wait = (self.rate_limit_delay_ms / 1000.0) - elapsed
        if wait > 0:
            time.sleep(wait)

    def request(
        self,
        method: str,
        path: str,
        role: Optional[Role] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        description: str = "",
    ) -> tuple[requests.Response, Evidence]:
        self._throttle()
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json"}
        if role:
            headers.update(role.auth_header)
        if extra_headers:
            headers.update(extra_headers)

        start = time.time()
        resp = self.session.request(
            method=method.upper(),
            url=url,
            json=json_body,
            params=params,
            headers=headers,
            timeout=self.timeout,
        )
        elapsed_ms = (time.time() - start) * 1000
        self._last_call = time.time()

        try:
            body_text = resp.text
        except Exception:  # noqa: BLE001
            body_text = "<unreadable body>"

        evidence = Evidence(
            description=description or f"{method.upper()} {path} as role={role.name if role else 'none'}",
            method=method.upper(),
            url=url,
            request_headers=_redact_headers(headers),
            request_body=json_body,
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body_excerpt=body_text[:MAX_BODY_EXCERPT],
            elapsed_ms=round(elapsed_ms, 2),
        )
        return resp, evidence
