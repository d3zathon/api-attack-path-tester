#!/usr/bin/env python3
"""Generate a ready-to-run APIAT config for the bundled demo lab.

Usage:
    python scripts/generate_lab_config.py http://localhost:8010

Environment overrides:
    APIAT_LAB_LOGIN_PATH   Authentication endpoint (default: /login)
    APIAT_LAB_AUTH_ENCODING json|form (default: json)
    APIAT_LAB_TOKEN_FIELD  Token response field (default: token)
    APIAT_LAB_USER_FIELD   Username request field (default: username)
    APIAT_LAB_PASS_FIELD   Password request field (default: password)

The bundled VulnAPI lab uses JSON POST /login and returns {"token": ...}.
These overrides keep the demo harness usable with other local lab APIs without
hardcoding AcmeFlow-specific credentials or authentication behavior.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urljoin

import requests
import yaml

BASE_URL = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8010").rstrip("/")
OUT_PATH = Path(__file__).parent.parent / "examples" / "roles_lab.yaml"

LOGIN_PATH = os.getenv("APIAT_LAB_LOGIN_PATH", "/login")
AUTH_ENCODING = os.getenv("APIAT_LAB_AUTH_ENCODING", "json").lower()
TOKEN_FIELD = os.getenv("APIAT_LAB_TOKEN_FIELD", "token")
USER_FIELD = os.getenv("APIAT_LAB_USER_FIELD", "username")
PASS_FIELD = os.getenv("APIAT_LAB_PASS_FIELD", "password")

CREDS = {
    "attacker_low_priv": ("attacker@example.com", "attacker-pass"),
    "victim_user": ("victim@example.com", "victim-pass"),
    "admin": ("admin@example.com", "admin-pass"),
}


def _url(path: str) -> str:
    return urljoin(f"{BASE_URL}/", path.lstrip("/"))


def login(username: str, password: str) -> str:
    payload = {USER_FIELD: username, PASS_FIELD: password}
    if AUTH_ENCODING in {"form", "urlencoded", "application/x-www-form-urlencoded"}:
        resp = requests.post(_url(LOGIN_PATH), data=payload, timeout=10)
    else:
        resp = requests.post(_url(LOGIN_PATH), json=payload, timeout=10)

    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        body = resp.text[:500]
        raise RuntimeError(
            f"Lab authentication failed at {resp.url}: HTTP {resp.status_code}. "
            f"Response: {body}"
        ) from exc

    try:
        body: Dict[str, Any] = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Lab authentication endpoint {resp.url} did not return JSON. "
            f"Response: {resp.text[:500]}"
        ) from exc

    token = body.get(TOKEN_FIELD)
    if not token:
        raise RuntimeError(
            f"Authentication succeeded at {resp.url}, but token field '{TOKEN_FIELD}' "
            f"was not present in the response. Available fields: {sorted(body)}"
        )
    return str(token)


def main():
    roles = []
    for role_name, (username, password) in CREDS.items():
        token = login(username, password)
        if role_name == "attacker_low_priv":
            roles.append({
                "name": role_name,
                "privilege_rank": 0,
                "auth_header": {"Authorization": f"Bearer {token}"},
                "owned_resources": {"user_id": ["2"], "order_id": ["ord_2"]},
                "metadata": {"identity_markers": ["attacker@example.com"]},
            })
        elif role_name == "victim_user":
            roles.append({
                "name": role_name,
                "privilege_rank": 1,
                "auth_header": {"Authorization": f"Bearer {token}"},
                "owned_resources": {"user_id": ["1"], "order_id": ["ord_1"]},
                "metadata": {"identity_markers": ["victim@example.com"]},
            })
        else:
            roles.append({
                "name": role_name,
                "privilege_rank": 9,
                "auth_header": {"Authorization": f"Bearer {token}"},
                "owned_resources": {},
                "metadata": {"identity_markers": ["admin@example.com"]},
            })

    config = {
        "base_url": BASE_URL,
        "roles": roles,
        "endpoint_role_requirements": {
            "GET /admin/users": ["admin"],
            "GET /admin/reports": ["admin"],
        },
        "sensitive_fields": ["price", "balance", "status", "discount"],
        "rate_limit_delay_ms": 100,
        "workflows": [
            {
                "name": "checkout",
                "description": "Cart checkout should require a completed payment step first.",
                "steps": [
                    {"name": "create_cart", "method": "POST", "path": "/cart", "body": {}},
                    {"name": "pay", "method": "POST", "path": "/cart/1/payment", "body": {"amount": 10}},
                    {"name": "checkout", "method": "POST", "path": "/cart/1/checkout", "body": {}},
                ],
                "skip_step_test": "pay",
            },
            {
                "name": "coupon_redeem",
                "description": "A coupon should only be redeemable once.",
                "steps": [
                    {"name": "redeem", "method": "POST", "path": "/coupons/apply", "body": {"code": "WELCOME10"}},
                ],
                "replay_step_test": "redeem",
            },
        ],
    }

    OUT_PATH.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
