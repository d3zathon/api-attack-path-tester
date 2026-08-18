"""Loads scan configuration for APIAT and supported AcmeFlow lab configs."""
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


def _login_role(base_url: str, auth: Dict[str, Any], username: str, password: str) -> Dict[str, str]:
    token_url = str(auth.get("token_url", "/api/v1/auth/login"))
    url = token_url if token_url.startswith(("http://", "https://")) else f"{base_url.rstrip('/')}/{token_url.lstrip('/')}"
    payload = {"username": username, "password": password}
    encoding = str(auth.get("request_encoding", "form")).lower()
    response = requests.post(url, json=payload, timeout=15) if encoding in {"json", "application/json"} else requests.post(url, data=payload, timeout=15)
    response.raise_for_status()
    body = response.json()
    token_field = auth.get("response_token_field", "access_token")
    token = body.get(token_field)
    if not token:
        raise ValueError(f"Authentication succeeded for '{username}', but token field '{token_field}' was not present in the response")
    header = str(auth.get("header", "Authorization"))
    scheme = str(auth.get("scheme", "Bearer")).strip()
    return {header: f"{scheme} {token}".strip()}


def _load_acmeflow_roles(data: Dict[str, Any], base_url: str) -> List[Role]:
    """Convert AcmeFlow role categories/users into APIAT identities and ownership maps."""
    auth = data.get("auth", {})
    role_map = data.get("roles", {})
    ownership = data.get("resource_ownership", {})
    if not isinstance(role_map, dict):
        raise TypeError("AcmeFlow 'roles' must be a mapping of role name -> users")

    users: Dict[int, Role] = {}
    privilege_by_role = {"employee": 0, "manager": 1, "finance": 2, "admin": 9}

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

            users[user_id] = Role(
                name=username,
                auth_header=_login_role(base_url, auth, username, password),
                privilege_rank=privilege_by_role.get(str(role_name).lower(), 0),
                metadata={
                    "username": username,
                    "user_id": user_id,
                    "role": role_name,
                    "department": user.get("department"),
                },
            )

    # Keep ownership resource-specific. A generic "id" bucket is intentionally avoided:
    # AcmeFlow has /users/{id}, /expenses/{id}, /payments/{id}, and /projects/{id}, and the
    # same numeric ID can refer to completely different objects.
    for resource_type, resources in ownership.items():
        if not isinstance(resources, list):
            continue
        for resource in resources:
            if not isinstance(resource, dict) or "id" not in resource:
                continue

            owner_id = None
            if resource_type == "users":
                owner_id = resource.get("id")
            elif resource_type == "expenses":
                owner_id = resource.get("owner_user_id")
            elif resource_type == "payments":
                expense_id = resource.get("expense_id")
                expense = next((e for e in ownership.get("expenses", []) if isinstance(e, dict) and e.get("id") == expense_id), None)
                owner_id = expense.get("owner_user_id") if expense else None
            elif resource_type == "projects":
                owner_id = resource.get("manager_id")

            if owner_id is None or int(owner_id) not in users:
                continue

            role = users[int(owner_id)]
            # OpenAPI uses singular parameters such as {expense_id}; keep the
            # ownership key aligned with that schema rather than producing
            # plural keys such as expenses_id.
            key = f"{str(resource_type).rstrip('s')}_id"
            role.owned_resources.setdefault(key, []).append(str(resource["id"]))

    return list(users.values())


def _load_roles(data: Dict[str, Any], base_url: str) -> List[Role]:
    raw_roles = data.get("roles", [])
    if isinstance(raw_roles, list):
        return [
            Role(
                name=r["name"],
                auth_header=r.get("auth_header", {}),
                owned_resources=r.get("owned_resources", {}),
                privilege_rank=r.get("privilege_rank", 0),
                metadata=r.get("metadata", {}),
            )
            for r in raw_roles
        ]
    if isinstance(raw_roles, dict):
        return _load_acmeflow_roles(data, base_url)
    raise TypeError("'roles' must be either an APIAT role list or a role mapping")


def _load_endpoint_requirements(data: Dict[str, Any]) -> Dict[str, List[str]]:
    requirements = dict(data.get("endpoint_role_requirements", {}) or {})
    endpoints = data.get("endpoints", []) or []
    if isinstance(endpoints, list) and isinstance(data.get("roles"), dict):
        role_map = data["roles"]
        for ep in endpoints:
            if not isinstance(ep, dict) or not isinstance(ep.get("allowed_roles"), list):
                continue
            path, method = ep.get("path"), ep.get("method")
            if not path or not method:
                continue
            allowed = {str(x).lower() for x in ep["allowed_roles"]}
            role_names = [
                user.get("username")
                for category, category_data in role_map.items()
                if category.lower() in allowed
                for user in category_data.get("users", [])
                if isinstance(user, dict) and user.get("username")
            ]
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
    return []


def load_scan_config(path: str) -> ScanConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scan config not found: {path}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise TypeError("Scan config root must be a YAML mapping")

    target = data.get("target", {}) or {}
    base_url = data.get("base_url") or target.get("base_url")
    if not base_url:
        raise ValueError("Missing 'base_url' (or 'target.base_url') in scan config")
    base_url = str(base_url).rstrip("/")

    roles = _load_roles(data, base_url)
    if len(roles) < 2:
        raise ValueError("At least two roles are required (e.g. a low-privilege and a higher-privilege identity) to meaningfully test authorization boundaries.")

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
