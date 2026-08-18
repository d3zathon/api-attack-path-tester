"""Parses OpenAPI 3.x documents into normalized endpoint models.

The parser intentionally treats every path-template parameter as object-bearing for
authorization analysis. Restricting this to names ending in ``id``/``uuid`` misses
real-world APIs that use names such as ``accountNumber``, ``username`` or ``slug``.
The BOLA check then uses endpoint context plus the configured ownership map to decide
whether a parameter identifies a testable resource.
"""
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
        parsed_yaml = yaml.safe_load(text)
        if not isinstance(parsed_yaml, dict):
            raise TypeError("OpenAPI document root must be a mapping")
        return parsed_yaml
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
    if isinstance(body, dict) and "$ref" in body:
        body = _resolve_ref(root, body["$ref"])
    if not isinstance(body, dict):
        return {}

    content = body.get("content", {}) or {}
    # Prefer JSON but accept common vendor media types such as application/*+json.
    media = content.get("application/json")
    if not isinstance(media, dict):
        media = next(
            (value for key, value in content.items()
             if isinstance(key, str) and (key.endswith("+json") or key == "application/*")
             and isinstance(value, dict)),
            {},
        )
    schema = media.get("schema", {}) if isinstance(media, dict) else {}
    if isinstance(schema, dict) and "$ref" in schema:
        schema = _resolve_ref(root, schema["$ref"])
    return schema if isinstance(schema, dict) else {}


def _extract_path_params(
    root: Dict[str, Any], path: str, path_item: Dict[str, Any], op: Dict[str, Any]
) -> List[str]:
    """Extract path parameters from OpenAPI metadata plus the URI template.

    The template fallback is important for locally generated or hand-authored specs
    that omit the redundant ``parameters`` declaration. Parameter names are preserved
    exactly because they are also used when substituting concrete resource IDs.
    """
    names: List[str] = []
    all_params = list(path_item.get("parameters", []) or []) + list(op.get("parameters", []) or [])

    for param in all_params:
        if not isinstance(param, dict):
            continue
        if "$ref" in param:
            param = _resolve_ref(root, param["$ref"])
        if param.get("in") == "path" and param.get("name"):
            name = str(param["name"])
            if name not in names:
                names.append(name)

    for name in _PATH_PARAM_RE.findall(path):
        if name not in names:
            names.append(name)

    return names


def parse_spec(source: str) -> List[Endpoint]:
    """Parse an OpenAPI document into a flat list of endpoint objects."""
    root = _load_raw(source)
    paths = root.get("paths") if isinstance(root, dict) else None
    if not isinstance(paths, dict):
        raise SpecParseError("Spec has no valid 'paths' section - is this an OpenAPI document?")

    endpoints: List[Endpoint] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue

            path_params = _extract_path_params(root, str(path), path_item, op)
            endpoints.append(
                Endpoint(
                    path=str(path),
                    method=method.upper(),
                    operation_id=op.get("operationId"),
                    tags=op.get("tags", []),
                    path_params=path_params,
                    request_body_schema=_extract_request_body_schema(root, op) or None,
                    required_roles=op.get("x-required-roles"),
                    # Object-level authorization is not limited to IDs. Any path
                    # parameter can select an object and must therefore be eligible
                    # for BOLA analysis when ownership data can resolve it.
                    is_id_bearing=bool(path_params),
                    raw=op,
                )
            )
    return endpoints


def summarize(endpoints: List[Endpoint]) -> Dict[str, Any]:
    return {
        "total_endpoints": len(endpoints),
        "id_bearing_endpoints": sum(1 for e in endpoints if e.is_id_bearing),
        "mutating_endpoints": sum(1 for e in endpoints if e.method in {"POST", "PUT", "PATCH", "DELETE"}),
        "methods": sorted({e.method for e in endpoints}),
    }
