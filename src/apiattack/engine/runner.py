from __future__ import annotations

import base64
import json
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


class TargetIdentityMismatch(RuntimeError):
    """Configured role metadata does not match an active bearer JWT identity."""


def _in_scope(ep: Endpoint, config: ScanConfig) -> bool:
    if config.scope_exclude and any(ep.path.startswith(p) for p in config.scope_exclude):
        return False
    if config.scope_include:
        return any(ep.path.startswith(p) for p in config.scope_include)
    return True


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    raw = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _validate_configured_identities(config: ScanConfig, progress_cb=None) -> None:
    """Fail fast when configured identity metadata disagrees with bearer JWT claims.

    This is only applied to roles that explicitly define ``user_id`` metadata and use a
    JWT bearer token. Generic APIAT configs without those fields remain unaffected.
    """
    mismatches = []
    for role in config.roles:
        expected_id = role.metadata.get("user_id")
        expected_name = role.metadata.get("username") or role.name
        if expected_id is None:
            continue

        auth = next((v for k, v in role.auth_header.items() if k.lower() == "authorization"), "")
        if not auth.lower().startswith("bearer "):
            continue

        payload = _decode_jwt_payload(auth.split(None, 1)[1].strip())
        actual_id = payload.get("sub")
        actual_name = payload.get("username")

        if actual_id is not None and str(actual_id) != str(expected_id):
            mismatches.append(f"{role.name}: expected user_id={expected_id}, token sub={actual_id}")
        if actual_name is not None and str(actual_name) != str(expected_name):
            mismatches.append(f"{role.name}: expected username={expected_name}, token username={actual_name}")

    if mismatches:
        message = (
            "Target identity mismatch. The configured roles/resources do not match the "
            "currently authenticated target identities. Reset/reseed the target or update "
            "the scan configuration before running authorization checks: " + "; ".join(mismatches)
        )
        if progress_cb:
            progress_cb(f"ERROR: {message}")
        raise TargetIdentityMismatch(message)


def _bola_diagnostics(candidates) -> tuple[Counter, Counter]:
    pairs: Counter = Counter()
    reasons: Counter = Counter()
    for f in candidates:
        if f.vuln_class != VulnClass.BOLA:
            continue
        if len(f.evidence) >= 2:
            pairs[(f.actor_role, f.victim_role, f.endpoint, f.evidence[0].status_code, f.evidence[1].status_code)] += 1
        note = f.verification_notes[-1] if f.verification_notes else "no verification decision recorded"
        reasons[note] += 1
    return pairs, reasons


def _format_bola_pairs(pairs: Counter) -> str:
    return "; ".join(
        f"{endpoint} [{victim}->{actor}] owner={owner}/attacker={attacker}: {count}"
        for (actor, victim, endpoint, owner, attacker), count in pairs.most_common(12)
    ) or "none"


def run_scan(
    spec_source: str,
    config: ScanConfig,
    check_names: Optional[List[str]] = None,
    progress_cb=None,
) -> ScanResult:
    _validate_configured_identities(config, progress_cb=progress_cb)

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
            pairs, reasons = _bola_diagnostics(bola_candidates)
            progress_cb(f"BOLA HTTP evidence: {_format_bola_pairs(pairs)}")
            progress_cb(
                "BOLA decisions: "
                + "; ".join(f"{reason} ({count})" for reason, count in reasons.most_common(8))
            )
            for f in bola_candidates[:5]:
                if len(f.evidence) < 2:
                    progress_cb(f"BOLA probe: {f.endpoint} [{f.actor_role}->{f.victim_role}] missing evidence")
                    continue
                owner_ev, attacker_ev = f.evidence[0], f.evidence[1]
                progress_cb(
                    f"BOLA probe: {f.endpoint} [{f.actor_role}->{f.victim_role}] "
                    f"owner={owner_ev.status_code} attacker={attacker_ev.status_code} "
                    f"url={attacker_ev.url}"
                )

        progress_cb("Building attack paths from confirmed findings...")
    result.attack_paths = build_attack_paths(verified)
    result.finished_at = time.time()
    return result
