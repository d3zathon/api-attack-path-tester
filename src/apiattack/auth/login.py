"""Optional helper for scan configs that would rather log in at scan time than hardcode
long-lived tokens in roles.yaml. Not required - static `auth_header` entries work fine
for CI/short-lived test tokens, which is the recommended default for authorized testing.
"""
from __future__ import annotations

from typing import Dict, Optional

import requests


def login_and_get_bearer(
    base_url: str,
    login_path: str,
    username: str,
    password: str,
    token_field: str = "token",
    username_field: str = "username",
    password_field: str = "password",
) -> Optional[Dict[str, str]]:
    """POST credentials to a login endpoint and return an Authorization header dict."""
    resp = requests.post(
        f"{base_url.rstrip('/')}{login_path}",
        json={username_field: username, password_field: password},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get(token_field)
    if not token:
        raise ValueError(f"Login response did not contain field '{token_field}': {data}")
    return {"Authorization": f"Bearer {token}"}
