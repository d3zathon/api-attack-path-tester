"""Loads scan configuration: roles (identities + tokens + owned resources), endpoint
authorization requirements, workflow definitions for business-logic checks, and
general scan scope/settings. This is the file that makes the tool authorized-testing-only:
you must explicitly provide credentials/tokens you are entitled to use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..models import Role


@dataclass
class WorkflowStep:
    name: str
    method: str
    path: str
    body: Optional[Dict[str, Any]] = None


@dataclass
class Workflow:
    name: str
    description: str
    steps: List[WorkflowStep]
    skip_step_test: Optional[str] = None  # name of step allowed to be skipped in the abuse test
    replay_step_test: Optional[str] = None  # name of step to test for unsafe replay


@dataclass
class ScanConfig:
    base_url: str
    roles: List[Role]
    endpoint_role_requirements: Dict[str, List[str]] = field(default_factory=dict)
    workflows: List[Workflow] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    rate_limit_delay_ms: int = 150
    scope_include: Optional[List[str]] = None
    scope_exclude: Optional[List[str]] = None

    def role_by_name(self, name: str) -> Role:
        for r in self.roles:
            if r.name == name:
                return r
        raise KeyError(f"Unknown role '{name}' referenced in config")


DEFAULT_SENSITIVE_FIELDS = [
    "role", "roles", "is_admin", "isAdmin", "admin", "permissions",
    "user_type", "account_type", "status", "balance", "price", "amount",
    "discount", "credit", "owner_id", "ownerId", "user_id", "verified",
    "is_verified", "email_verified",
]


def load_scan_config(path: str) -> ScanConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scan config not found: {path}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))

    roles = []
    for r in data.get("roles", []):
        roles.append(
            Role(
                name=r["name"],
                auth_header=r.get("auth_header", {}),
                owned_resources=r.get("owned_resources", {}),
                privilege_rank=r.get("privilege_rank", 0),
                metadata=r.get("metadata", {}),
            )
        )
    if len(roles) < 2:
        raise ValueError(
            "At least two roles are required (e.g. a low-privilege and a higher-privilege "
            "identity) to meaningfully test authorization boundaries."
        )

    workflows = []
    for w in data.get("workflows", []):
        steps = [WorkflowStep(**s) for s in w.get("steps", [])]
        workflows.append(
            Workflow(
                name=w["name"],
                description=w.get("description", ""),
                steps=steps,
                skip_step_test=w.get("skip_step_test"),
                replay_step_test=w.get("replay_step_test"),
            )
        )

    return ScanConfig(
        base_url=data["base_url"].rstrip("/"),
        roles=roles,
        endpoint_role_requirements=data.get("endpoint_role_requirements", {}),
        workflows=workflows,
        sensitive_fields=data.get("sensitive_fields", DEFAULT_SENSITIVE_FIELDS),
        rate_limit_delay_ms=data.get("rate_limit_delay_ms", 150),
        scope_include=data.get("scope_include"),
        scope_exclude=data.get("scope_exclude"),
    )
