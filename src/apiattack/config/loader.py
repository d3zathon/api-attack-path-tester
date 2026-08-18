"""Loads scan configuration: roles (identities + tokens + owned resources), endpoint
authorization requirements, workflow definitions for business-logic checks, and
general scan scope/settings. This is the file that makes the tool authorized-testing-only:
you must explicitly provide credentials/tokens you are entitled to use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
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
    skip_step_test: Optional[str] = None
    replay_step_test: Optional[str] = None


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


def _as_list(value: Any) -> list:
    """Return config collections as lists without changing their meaning."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    raise TypeError(f"Expected a list or mapping, got {type(value).__name__}")


def _login_role(base_url: str, auth: Dict[str, Any], username: str, password: str) -> Dict[str, str]:
    """Exchange a configured test user's credentials for the API bearer token."""
    token_url = str(auth.get("token_url", "/api/v1/auth/login"))
    if token_url.startswith("http://") or token_url.startswith("https://"):
        url = token_url
    else:
        url = f"{base_url.rstrip('/')}/{token_url.lstrip('/')}"

    encoding = str(auth.get("request_encoding", "form")).lower()
    payload = {"username": username, "password": password}
    if encoding in {"json", "application/json"}:
        response = requests.post(url, json=payload, timeout=15)
    else:
        response = requests.post(url, data=payload, timeout=15)

    response.raise_for_status()
    body = response.json()
    token_field = auth.get("response_token_field", "access_token")
    token = body.get(token_field)
    if not token:
        raise ValueError(
            f"Authentication succeeded for '{username}', but token field '{token_field}' "
            "was not present in the response"
        )

    header = str(auth.get("header", "Authorization"))
    scheme = str(auth.get("scheme", "Bearer")).strip()
    return {header: f"{scheme} {token}".strip()}


def _load_acmeflow_roles(data: Dict[str, Any], base_url: str) -> List[Role]:
    """Normalize AcmeFlow's role -> users configuration into APIAT Role objects."""
    auth = data.get("auth", {})
    role_map = data.get("roles", {})
    ownership = data.get("resource_ownership", {})

    if not isinstance(role_map, dict):
        raise TypeError("AcmeFlow 'roles' must be a mapping of role name -> users")

    users: Dict[int, Role] = {}
    user_role: Dict[int, str] = {}
    username_to_id: Dict[str, int] = {}

    privilege_by_role = {
        "employee": 0,
        "manager": 1,
        "finance": 2,
        "admin": 9,
    }

    for role_name, role_data in role_map.items():
        if not isinstance(role_data, dict):
            raise TypeError(f"Role '{role_name}' must be a mapping")
        for user in role_data.get("users", []):
            if not isinstance(user, dict):
                raise TypeError(f"User entry under role '{role_name}' must be a mapping")
            username = user["username"]
            user_id = int(user["user_id"])
            password = user.get("password")
            if not password:
                raise ValueError(f"Missing password for configured test user '{username}'")

            auth_header = _login_role(base_url, auth, username, password)
            role = Role(
                name=username,
                auth_header=auth_header,
                privilege_rank=privilege_by_role.get(str(role_name).lower(), 0),
                metadata={
                    "username": username,
                    "user_id": user_id,
                    "role": role_name,
                    "department": user.get("department"),
                },
            )
            users[user_id] = role
            user_role[user_id] = str(role_name).lower()
            username_to_id[username] = user_id

    # Build ownership information expected by BOLA: the key is the path parameter
    # name and the values are resource IDs belonging to this testing identity.
    for resource_type, resources in ownership.items():
        if not isinstance(resources, list):
            continue
        for resource in resources:
            if not isinstance(resource, dict) or "id" not in resource:
                continue
            rid = str(resource["id"])
            owner_id = None

            if resource_type == "users":
                owner_id = resource.get("id")
            elif resource_type == "expenses":
                owner_id = resource.get("owner_user_id")
            elif resource_type == "payments":
                expense_id = resource.get("expense_id")
                expense = next(
                    (e for e in ownership.get("expenses", [])
                     if isinstance(e, dict) and e.get("id") == expense_id),
                    None,
                )
                owner_id = expense.get("owner_user_id") if expense else None
            elif resource_type == "projects":
                owner_id = resource.get("manager_id")

            if owner_id is not None and int(owner_id) in users:
                role = users[int(owner_id)]
                role.owned_resources.setdefault("id", []).append(rid)
                role.owned_resources.setdefault(f"{resource_type}_id", []).append(rid)

    return list(users.values())


def _load_roles(data: Dict[str, Any], base_url: str) -> List[Role]:
    raw_roles = data.get("roles", [])

    # Native APIAT format: roles is a list of dictionaries with a required name.
    if isinstance(raw_roles, list):
        roles = []
        for r in raw_roles:
            if not isinstance(r, dict):
                raise TypeError("Each APIAT role must be a mapping")
            roles.append(
                Role(
                    name=r["name"],
                    auth_header=r.get("auth_header", {}),
                    owned_resources=r.get("owned_resources", {}),
                    privilege_rank=r.get("privilege_rank", 0),
                    metadata=r.get("metadata", {}),
                )
            )
        return roles

    # AcmeFlow format: roles is a mapping of role category -> users.
    if isinstance(raw_roles, dict):
        return _load_acmeflow_roles(data, base_url)

    raise TypeError("'roles' must be either an APIAT role list or a role mapping")


def _load_endpoint_requirements(data: Dict[str, Any]) -> Dict[str, List[str]]:
    """Support APIAT's map format and AcmeFlow's endpoint list format."""
    requirements = dict(data.get("endpoint_role_requirements", {}) or {})
    endpoints = data.get("endpoints", []) or []

    if isinstance(endpoints, list):
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            allowed = ep.get("allowed_roles")
            if not allowed or not isinstance(allowed, list):
                continue
            path = ep.get("path")
            method = ep.get("method")
            if path and method:
                # AcmeFlow uses role categories; APIAT roles are individual identities.
                # Expand each category to the corresponding usernames.
                role_names = []
                for role in data.get("roles", {}).keys() if isinstance(data.get("roles"), dict) else []:
                    role_names.extend(
                        user.get("username")
                        for user in data["roles"][role].get("users", [])
                        if role in {str(x).lower() for x in allowed}
                    )
                requirements[f"{str(method).upper()} {path}"] = role_names

    return requirements


def _load_workflows(data: Dict[str, Any]) -> List[Workflow]:
    raw = data.get("workflows", []) or []
    if isinstance(raw, list):
        return [
            Workflow(
                name=w["name"],
                description=w.get("description", ""),
                steps=[WorkflowStep(**s) for s in w.get("steps", [])],
                skip_step_test=w.get("skip_step_test"),
                replay_step_test=w.get("replay_step_test"),
            )
            for w in raw
        ]

    # AcmeFlow's state-machine workflow is richer than APIAT's simple workflow model.
    # Do not crash loading a scan that only needs role/endpoint/BOLA information.
    # Transition endpoints are still converted into simple one-step workflows.
    workflows: List[Workflow] = []
    if isinstance(raw, dict):
        for name, definition in raw.items():
            if not isinstance(definition, dict):
                continue
            steps = []
            for i, transition in enumerate(definition.get("transitions", [])):
                endpoint = str(transition.get("endpoint", ""))
                parts = endpoint.split(" ", 1)
                if len(parts) != 2:
                    continue
                method, path = parts
                steps.append(WorkflowStep(name=f"transition_{i + 1}", method=method, path=path))
            workflows.append(
                Workflow(
                    name=name,
                    description="AcmeFlow state-machine workflow",
                    steps=steps,
                )
            )
    return workflows


def load_scan_config(path: str) -> ScanConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scan config not found: {path}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise TypeError("Scan config root must be a YAML mapping")

    # Native APIAT configs put base_url at the root; AcmeFlow puts it under target.
    target = data.get("target", {}) or {}
    base_url = data.get("base_url") or target.get("base_url")
    if not base_url:
        raise ValueError("Missing 'base_url' (or 'target.base_url') in scan config")
    base_url = str(base_url).rstrip("/")

    roles = _load_roles(data, base_url)
    if len(roles) < 2:
        raise ValueError(
            "At least two roles are required (e.g. a low-privilege and a higher-privilege "
            "identity) to meaningfully test authorization boundaries."
        )

    return ScanConfig(
        base_url=base_url,
        roles=roles,
        endpoint_role_requirements=_load_endpoint_requirements(data),
        workflows=_load_workflows(data),
        sensitive_fields=data.get("sensitive_fields", DEFAULT_SENSITIVE_FIELDS),
        rate_limit_delay_ms=data.get("rate_limit_delay_ms", 150),
        scope_include=data.get("scope_include"),
        scope_exclude=data.get("scope_exclude"),
    )
