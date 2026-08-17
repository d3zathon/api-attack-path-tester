from __future__ import annotations

import dataclasses
import enum
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanResult

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _json_default(obj: Any):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def result_to_dict(result: ScanResult) -> dict:
    return json.loads(json.dumps(dataclasses.asdict(result), default=_json_default))


def write_json(result: ScanResult, path: str) -> None:
    Path(path).write_text(
        json.dumps(dataclasses.asdict(result), default=_json_default, indent=2),
        encoding="utf-8",
    )


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_findings(result: ScanResult):
    return sorted(
        result.findings,
        key=lambda f: (0 if f.confirmed else 1, SEVERITY_ORDER.get(f.severity.value, 9)),
    )


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_markdown(result: ScanResult, path: str) -> None:
    env = _env()
    tmpl = env.get_template("report.md.j2")
    content = tmpl.render(
        result=result,
        findings=_sorted_findings(result),
        confirmed=result.confirmed_findings,
        severity_order=SEVERITY_ORDER,
    )
    Path(path).write_text(content, encoding="utf-8")


def write_html(result: ScanResult, path: str) -> None:
    env = _env()
    tmpl = env.get_template("report.html.j2")
    content = tmpl.render(
        result=result,
        findings=_sorted_findings(result),
        confirmed=result.confirmed_findings,
        severity_order=SEVERITY_ORDER,
    )
    Path(path).write_text(content, encoding="utf-8")
