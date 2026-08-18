"""Map OpenAPI path parameters to configured resource ownership IDs.

A generic ``{id}`` is never treated as globally unique: the same value can identify
unrelated resources. Resolution uses the parameter name first and the REST collection
immediately preceding the parameter second, so nested routes such as
``/expenses/{id}/approve`` still resolve to ``expense_id``.
"""
from __future__ import annotations

import re
from typing import List

from ..models import Role

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


def _normalize(name: str) -> str:
    s = _CAMEL_BOUNDARY.sub("_", str(name)).lower()
    return s.replace("-", "_")


def _singularize(resource: str) -> str:
    resource = _normalize(resource).strip("/")
    if resource.endswith("ies") and len(resource) > 3:
        return resource[:-3] + "y"
    if resource.endswith("ses") and len(resource) > 3:
        return resource[:-2]
    if resource.endswith("s") and not resource.endswith("ss"):
        return resource[:-1]
    return resource


def _resource_candidates(param_name: str, endpoint_path: str | None = None) -> List[str]:
    """Return ownership-key candidates from most to least specific."""
    target = _normalize(param_name)
    candidates: List[str] = []

    if target != "id":
        candidates.append(target)

    if endpoint_path:
        segments = [p for p in endpoint_path.strip("/").split("/") if p]
        try:
            param_index = next(
                i for i, segment in enumerate(segments)
                if segment.strip("{}") == str(param_name)
            )
        except StopIteration:
            param_index = -1

        # /expenses/{id}/approve -> expense_id, not approve_id.
        if param_index > 0:
            resource = segments[param_index - 1]
            if not resource.startswith("{"):
                candidates.append(f"{_singularize(resource)}_id")

    candidates.append(target)
    return list(dict.fromkeys(candidates))


def owned_ids_for_param(role: Role, param_name: str, endpoint_path: str | None = None) -> List[str]:
    """Return IDs owned by a role for a specific endpoint parameter."""
    candidates = set(_resource_candidates(param_name, endpoint_path))
    for key, ids in role.owned_resources.items():
        if _normalize(key) in candidates:
            return [str(v) for v in ids]
    return []


def pick_two_roles_with_resource(
    roles: List[Role],
    param_name: str,
    endpoint_path: str | None = None,
):
    """Find owner/attacker/resource triples with disjoint ownership."""
    triples = []
    for owner in roles:
        owned = owned_ids_for_param(owner, param_name, endpoint_path)
        if not owned:
            continue
        for other in roles:
            if other.name == owner.name:
                continue
            other_owned = set(owned_ids_for_param(other, param_name, endpoint_path))
            for resource_id in owned:
                if resource_id not in other_owned:
                    triples.append((owner, other, resource_id))
    return triples
