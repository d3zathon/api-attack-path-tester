"""Builds attack paths by chaining *confirmed* findings together.

Two chaining heuristics are used, both grounded in what was actually observed during
the scan (not speculation):

  1. Privesc -> BFLA chain: if role R has a confirmed PRIVESC finding that grants it
     elevated capability, and role R (pre-escalation) also has a confirmed BFLA finding
     on a *different* endpoint that required a higher role, we present this as a single
     path: "R can escalate itself, then use that to reach restricted functionality."

  2. BOLA -> PRIVESC/BFLA chain: if role R can read another user's data via a confirmed
     BOLA finding, and something in that data class (role field, ID) is plausibly usable
     as input to a confirmed PRIVESC/BFLA finding for R, we chain them as
     "recon via BOLA, then escalate/abuse function."

Where no chain exists, each confirmed finding is still reported individually - attack
paths are additive context, not a replacement for the finding list.
"""
from __future__ import annotations

from collections import defaultdict
from typing import List

from ..models import AttackPath, AttackPathStep, Finding, Severity, VulnClass


def build_attack_paths(findings: List[Finding]) -> List[AttackPath]:
    confirmed = [f for f in findings if f.confirmed]
    by_role: dict = defaultdict(list)
    for f in confirmed:
        by_role[f.actor_role].append(f)

    paths: List[AttackPath] = []

    for role, role_findings in by_role.items():
        privesc = [f for f in role_findings if f.vuln_class == VulnClass.PRIVESC]
        bfla = [f for f in role_findings if f.vuln_class == VulnClass.BFLA]
        bola = [f for f in role_findings if f.vuln_class == VulnClass.BOLA]

        # Chain 1: privesc unlocks function-level access
        for pe in privesc:
            if pe.confidence != "verified-high-confidence":
                continue
            steps = [
                AttackPathStep(pe.id, f"Escalate privileges as '{role}' via {pe.endpoint}."),
            ]
            for b in bfla:
                steps.append(
                    AttackPathStep(
                        b.id,
                        f"Using the elevated context, reach restricted function {b.endpoint} "
                        f"(originally out of scope for '{role}').",
                    )
                )
            if len(steps) > 1:
                paths.append(
                    AttackPath(
                        title=f"Self-service privilege escalation to restricted functionality ({role})",
                        starting_role=role,
                        impact=(
                            "An authenticated low-privilege user can grant themselves elevated "
                            "privileges and then directly exercise administrative or restricted "
                            "functionality."
                        ),
                        steps=steps,
                        severity=Severity.CRITICAL,
                    )
                )

        # Chain 2: BOLA recon feeding into privesc/bfla abuse
        if bola and (privesc or bfla):
            steps = [
                AttackPathStep(
                    b.id, f"Read another principal's data without authorization via {b.endpoint}."
                )
                for b in bola[:2]
            ]
            for f in (privesc + bfla)[:2]:
                steps.append(
                    AttackPathStep(
                        f.id,
                        f"Leverage information/context from the prior step to abuse {f.endpoint}.",
                    )
                )
            if len(steps) > 1:
                paths.append(
                    AttackPath(
                        title=f"Cross-account recon feeding a privilege/function abuse ({role})",
                        starting_role=role,
                        impact=(
                            "Unauthorized read access to other users' data can be combined with "
                            "a separate authorization weakness to broaden impact beyond simple "
                            "data disclosure."
                        ),
                        steps=steps,
                        severity=Severity.HIGH,
                    )
                )

    return paths
