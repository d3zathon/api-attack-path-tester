"""Parses an OpenAPI 3.x spec into normalized Endpoint objects."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
import yaml

from .models import Endpoint

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_ID_PARAM_RE = re.compile(r"(id|uuid|key|slug)$", re.IGNORECASE)
_PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}")


class SpecParseError(Exception):
    pass


def _load_raw(source: str) -> Dict[str, Any]:
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        resp = requests.get(source, timeout=15)
        resp.raise_for_status()
        text = resp.text
    else:
        path = Path(source)
        if not path.exists():
            raise SpecParseError(f"OpenAPI spec not found: {source}")
        text = path.read_text(encoding="utf-8")

    text_stripped = text.lstrip()
    try:
        if text_stripped.startswith("{"):
            return json.loads(text)
        return yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        raise SpecParseError(f"Failed to parse OpenAPI spec as JSON/YAML: {exc}") from exc


def _resolve_ref(root: Dict[str, Any], ref: str) -> Dict[str, Any]:
    if not ref.startswith("#/"):
        return {}
    node: Any = root
    for part in ref.lstrip("#/").split("/"):
        node = node.get(part, {}) if isinstance(node, dict) else {}
    return node if isinstance(node, dict) else {}


def _extract_request_body_schema(root: Dict[str, Any], op: Dict[str, Any]) -> Dict[str, Any]:
    body = op.get("requestBody", {})
    if "$ref" in body:
        body = _resolve_ref(root, body["$ref"])
    content = body.get("content", {})
    json_content = content.get("application/json", {})
    schema = json_content.get("schema", {})
    if "$ref" in schema:
        schema = _resolve_ref(root, schema["$ref"])
    return schema or {}


def _extract_path_params(root: Dict[str, Any], path: str, path_item: Dict[str, Any], op: Dict[str, Any]) -> List[str]:
    """Extract path parameters from OpenAPI metadata, with a template-path fallback.

    A valid path template such as ``/expenses/{expense_id}`` is enough to identify the
    parameter even when a hand-authored/local OpenAPI document omitted the corresponding
    ``parameters`` entry. This keeps authorization checks from silently skipping an
    otherwise testable endpoint.
    """
    names: List[str] = []
    all_params = list(path_item.get("parameters", []) or []) + list(op.get("parameters", []) or [])

    for param in all_params:
        if not isinstance(param, dict):
            continue
        if "$ref" in param:
            param = _resolve_ref(root, param["$ref"])
        if param.get("in") == "path" and param.get("name"):
            names.append(str(param["name"]))

    # Fallback: infer names directly from {param} path-template segments.
    for name in _PATH_PARAM_RE.findall(path):
        if name not in names:
            names.append(name)

    return names


def parse_spec(source: str) -> List[Endpoint]:
    """Parse an OpenAPI spec into a flat list of Endpoint objects."""
    root = _load_raw(source)
    if not root or "paths" not in root:
        raise SpecParseError("Spec has no 'paths' section - is this a valid OpenAPI document?")

    endpoints: List[Endpoint] = []

    for path, path_item in root.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue

            path_params = _extract_path_params(root, path, path_item, op)
            required_roles = op.get("x-required-roles")

            ep = Endpoint(
                path=path,
                method=method.upper(),
                operation_id=op.get("operationId"),
                tags=op.get("tags", []),
                path_params=path_params,
                request_body_schema=_extract_request_body_schema(root, op) or None,
                required_roles=required_roles,
                is_id_bearing=any(_ID_PARAM_RE.search(p or "") for p in path_params),
                raw=op,
            )
            endpoints.append(ep)

    return endpoints


def summarize(endpoints: List[Endpoint]) -> Dict[str, Any]:
    return {
        "total_endpoints": len(endpoints),
        "id_bearing_endpoints": sum(1 for e in endpoints if e.is_id_bearing),
        "mutating_endpoints": sum(1 for e in endpoints if e.method in {"POST", "PUT", "PATCH", "DELETE"}),
        "methods": sorted({e.method for e in endpoints}),
    }
