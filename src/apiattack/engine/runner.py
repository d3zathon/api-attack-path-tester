from __future__ import annotations

import time
from collections import Counter
from typing import List, Optional

from ..attack_path.graph import build_attack_paths
from ..checks import ALL_CHECKS
from ..config.loader import ScanConfig
from ..models import Endpoint, ScanResult, VulnClass
from ..spec_parser import parse_spec
from ..verification.verifier import Verifier
from .http_client import HttpClient


def _in_scope(ep: Endpoint, config: ScanConfig) -> bool:
    if config.scope_exclude and any(ep.path.startswith(p) for p in config.scope_exclude):
        return False
    if config.scope_include:
        return any(ep.path.startswith(p) for p in config.scope_include)
    return True


def _bola_diagnostics(candidates, verified) -> tuple[str, str]:
    """Return compact status/reason diagnostics so verifier failures are actionable."""
    pairs = Counter()
    reasons = Counter()
    for f in candidates:
        if f.vuln_class != VulnClass.BOLA or len(f.evidence) < 2:
            continue
        pairs[(f.evidence[0].status_code, f.evidence[1].status_code)] += 1
        if f.verification_notes:
            reasons[f.verification_notes[-1]] += 1
    pair_text = ", ".join(
        f"owner={owner}/attacker={attacker}: {count}"
        for (owner, attacker), count in sorted(pairs.items())
    ) or "none"
    reason_text = "; ".join(
        f"{reason} ({count})" for reason, count in reasons.most_common(3)
    ) or "none"
    return pair_text, reason_text


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
        if progress_cb:
            progress_cb(f"Check {name}: {len(found)} candidate finding(s)")

    result.raw_candidate_count = len(candidates)

    if progress_cb:
        progress_cb(f"Verifying {len(candidates)} candidate finding(s)...")
    verifier = Verifier(config, client)
    verified = verifier.verify_all(candidates)
    result.findings = verified

    if progress_cb:
        progress_cb(
            f"Verification complete: {len(verified)} finding(s) retained, "
            f"{len(result.confirmed_findings)} confirmed"
        )
        bola_candidates = [f for f in candidates if f.vuln_class == VulnClass.BOLA]
        if bola_candidates:
            pairs, reasons = _bola_diagnostics(bola_candidates, verified)
            progress_cb(f"BOLA HTTP evidence: {pairs}")
            if not result.confirmed_findings:
                progress_cb(f"BOLA verification reasons: {reasons}")
        progress_cb("Building attack paths from confirmed findings...")
    result.attack_paths = build_attack_paths(verified)

    result.finished_at = time.time()
    return result