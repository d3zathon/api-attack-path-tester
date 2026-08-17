from __future__ import annotations

import time
from typing import List, Optional

from ..attack_path.graph import build_attack_paths
from ..checks import ALL_CHECKS
from ..config.loader import ScanConfig
from ..models import Endpoint, ScanResult
from ..spec_parser import parse_spec
from ..verification.verifier import Verifier
from .http_client import HttpClient


def _in_scope(ep: Endpoint, config: ScanConfig) -> bool:
    if config.scope_exclude and any(ep.path.startswith(p) for p in config.scope_exclude):
        return False
    if config.scope_include:
        return any(ep.path.startswith(p) for p in config.scope_include)
    return True


def run_scan(
    spec_source: str,
    config: ScanConfig,
    check_names: Optional[List[str]] = None,
    progress_cb=None,
) -> ScanResult:
    endpoints = parse_spec(spec_source)
    in_scope = [e for e in endpoints if _in_scope(e, config)]

    client = HttpClient(config.base_url, rate_limit_delay_ms=config.rate_limit_delay_ms)
    result = ScanResult(
        target=config.base_url,
        started_at=time.time(),
        roles_tested=[r.name for r in config.roles],
        endpoints_discovered=len(endpoints),
        endpoints_tested=len(in_scope),
    )

    names = check_names or list(ALL_CHECKS.keys())
    candidates = []
    for name in names:
        check_cls = ALL_CHECKS[name]
        check = check_cls(config, client)
        if progress_cb:
            progress_cb(f"Running check: {name} ({len(in_scope)} endpoints in scope)")
        found = check.run(in_scope)
        candidates.extend(found)

    result.raw_candidate_count = len(candidates)

    if progress_cb:
        progress_cb(f"Verifying {len(candidates)} candidate finding(s)...")
    verifier = Verifier(config, client)
    verified = verifier.verify_all(candidates)
    result.findings = verified

    if progress_cb:
        progress_cb("Building attack paths from confirmed findings...")
    result.attack_paths = build_attack_paths(verified)

    result.finished_at = time.time()
    return result
