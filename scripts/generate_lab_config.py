#!/usr/bin/env python3
"""Logs into the running VulnAPI lab as each seeded identity and writes out a ready-to-use
roles config (examples/roles_lab.yaml) with fresh bearer tokens - the lab's in-memory
tokens reset every time it restarts, so this is regenerated per run rather than hardcoded.
"""
from __future__ import annotations

import sys
from pathlib import Path

import requests
import yaml

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
OUT_PATH = Path(__file__).parent.parent / "examples" / "roles_lab.yaml"

CREDS = {
    "attacker_low_priv": ("attacker@example.com", "attacker-pass"),
    "victim_user": ("victim@example.com", "victim-pass"),
    "admin": ("admin@example.com", "admin-pass"),
}


def login(email: str, password: str) -> str:
    resp = requests.post(f"{BASE_URL}/login", json={"username": email, "password": password}, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]


def main():
    roles = []
    for role_name, (email, password) in CREDS.items():
        token = login(email, password)
        if role_name == "attacker_low_priv":
            roles.append({
                "name": role_name, "privilege_rank": 0,
                "auth_header": {"Authorization": f"Bearer {token}"},
                "owned_resources": {"user_id": ["2"], "order_id": ["ord_2"]},
                "metadata": {"identity_markers": ["attacker@example.com"]},
            })
        elif role_name == "victim_user":
            roles.append({
                "name": role_name, "privilege_rank": 1,
                "auth_header": {"Authorization": f"Bearer {token}"},
                "owned_resources": {"user_id": ["1"], "order_id": ["ord_1"]},
                "metadata": {"identity_markers": ["victim@example.com"]},
            })
        else:
            roles.append({
                "name": role_name, "privilege_rank": 9,
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

    OUT_PATH.write_text(yaml.dump(config, sort_keys=False), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
