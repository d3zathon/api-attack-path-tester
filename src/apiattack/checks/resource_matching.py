"""Map OpenAPI path parameters to configured resource ownership IDs."""
from __future__ import annotations

import re
from typing import List, Tuple

from ..models import Role

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


def _normalize(name: str) -> str:
    s = _CAMEL_BOUNDARY.sub("_", str(name)).lower()
    return s.replace("-", "_")


def _singularize(resource: str) -> str:
    """Conservatively singularize common REST collection names."""
    resource = _normalize(resource).strip("/")
    if resource.endswith("ies") and len(resource) > 3:
        return resource[:-3] + "y"
    if resource.endswith("ses") and len(resource) > 3:
        if resource[:-2].endswith(("ss", "us")):
            return resource[:-2]
        if resource[:-1].endswith("se"):
            return resource[:-1]
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
    max_attackers_per_resource: int = 2,
) -> List[Tuple[Role, Role, str]]:
    """Return representative owner/attacker/resource triples.

    Exhaustively pairing every role against every owned object creates a large number of
    redundant requests. For BOLA, one or two attackers per resource are normally enough:
    the lowest-privilege non-owner establishes the horizontal boundary, while a second
    attacker can exercise a different privilege boundary when available. The admin role
    is skipped when it is the globally highest-privileged identity because administrative
    access is generally expected to bypass object ownership controls.
    """
    triples: List[Tuple[Role, Role, str]] = []
    max_rank = max((r.privilege_rank for r in roles), default=0)

    for owner in roles:
        owned = owned_ids_for_param(owner, param_name, endpoint_path)
        if not owned:
            continue

        for resource_id in owned:
            candidates = [
                other for other in roles
                if other.name != owner.name
                and other.privilege_rank < max_rank
                and str(resource_id) not in set(owned_ids_for_param(other, param_name, endpoint_path))
            ]
            candidates.sort(key=lambda r: (r.privilege_rank, r.name))

            for attacker in candidates[:max_attackers_per_resource]:
                triples.append((owner, attacker, resource_id))

    return triples
