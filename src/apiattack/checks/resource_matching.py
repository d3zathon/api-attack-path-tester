"""Helpers to map an OpenAPI path parameter (e.g. 'orderId', 'user_id') to a resource
identifier owned by a given Role, as declared in the scan config's owned_resources map.
"""
from __future__ import annotations

import re
from typing import List, Optional

from ..models import Role

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


def _normalize(name: str) -> str:
    # userId / user_id / UserID -> "user_id"
    s = _CAMEL_BOUNDARY.sub("_", name).lower()
    s = s.replace("-", "_")
    return s


def owned_ids_for_param(role: Role, param_name: str) -> List[str]:
    """Return candidate owned resource IDs for a given path parameter name."""
    target = _normalize(param_name)

    # exact match first
    for key, ids in role.owned_resources.items():
        if _normalize(key) == target:
            return ids

    # If the path param is just the generic word "id" and the role owns exactly one
    # resource type, it's reasonable to assume that's the one being referenced.
    if target == "id" and len(role.owned_resources) == 1:
        return next(iter(role.owned_resources.values()))

    # Otherwise require a meaningful (non-trivial) boundary-aligned match, e.g.
    # 'user_id' vs 'userId' -> both normalize to 'user_id' (handled above), or
    # 'order_id' vs 'orderId' path param on an 'order_id' owned-resource key.
    # We deliberately do NOT match on the bare trailing "id" token alone, since that
    # would spuriously match any *_id key against any other *_id param.
    for key, ids in role.owned_resources.items():
        nk = _normalize(key)
        if nk == target:
            return ids
    return []


def pick_two_roles_with_resource(roles: List[Role], param_name: str):
    """Find (owner_role, other_role, resource_id) triples where owner has a resource
    that 'other' does not own, for a given path parameter name.
    """
    triples = []
    for owner in roles:
        owned = owned_ids_for_param(owner, param_name)
        if not owned:
            continue
        for other in roles:
            if other.name == owner.name:
                continue
            other_owned = set(owned_ids_for_param(other, param_name))
            for rid in owned:
                if rid not in other_owned:
                    triples.append((owner, other, rid))
    return triples
