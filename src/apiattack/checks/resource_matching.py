"""Helpers for mapping OpenAPI resource parameters to owned resource IDs."""
from __future__ import annotations

import re
from typing import List

from ..models import Role

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


def _normalize(name: str) -> str:
    s = _CAMEL_BOUNDARY.sub("_", name).lower()
    return s.replace("-", "_")


def _resource_candidates(param_name: str, endpoint_path: str | None = None) -> List[str]:
    """Return ownership keys that can represent a path parameter.

    A generic ``{id}`` is ambiguous, so endpoint context is used first. For example
    ``/expenses/{id}`` maps to ``expense_id`` while ``/payments/{id}`` maps to
    ``payment_id``.
    """
    target = _normalize(param_name)
    candidates: List[str] = []

    if target != "id":
        candidates.append(target)
    elif endpoint_path:
        parts = [p for p in endpoint_path.strip("/").split("/") if p and not p.startswith("{")]
        if parts:
            resource = _normalize(parts[-1])
            if resource.endswith("s"):
                resource = resource[:-1]
            candidates.append(f"{resource}_id")

    candidates.append(target)
    return list(dict.fromkeys(candidates))


def owned_ids_for_param(role: Role, param_name: str, endpoint_path: str | None = None) -> List[str]:
    """Return resource IDs owned by a role for a specific endpoint parameter."""
    for candidate in _resource_candidates(param_name, endpoint_path):
        for key, ids in role.owned_resources.items():
            if _normalize(key) == candidate:
                return [str(v) for v in ids]
    return []


def pick_two_roles_with_resource(
    roles: List[Role],
    param_name: str,
    endpoint_path: str | None = None,
):
    """Find (owner, attacker, resource_id) triples for one endpoint/resource type."""
    triples = []
    for owner in roles:
        owned = owned_ids_for_param(owner, param_name, endpoint_path)
        if not owned:
            continue
        for other in roles:
            if other.name == owner.name:
                continue
            other_owned = set(owned_ids_for_param(other, param_name, endpoint_path))
            for rid in owned:
                if rid not in other_owned:
                    triples.append((owner, other, rid))
    return triples
