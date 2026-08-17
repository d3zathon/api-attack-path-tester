"""Broken Object Level Authorization / IDOR check (OWASP API1:2023).

Strategy: for every ID-bearing endpoint (GET/PUT/PATCH/DELETE with a path parameter that
looks like a resource identifier), find pairs of roles where one role owns a resource the
other does not. Request the owner's resource while authenticated as the *other* role.

A candidate is only emitted when the cross-role request returns a successful status code.
The verification layer then confirms whether the response actually discloses/mutates the
victim's data (as opposed to e.g. a 200 with an empty/generic body), which is what
separates a real finding from a status-code false positive.
"""
from __future__ import annotations

from typing import List

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck
from .resource_matching import pick_two_roles_with_resource

MUTATING_ID_METHODS = {"GET", "PUT", "PATCH", "DELETE"}


class BolaCheck(BaseCheck):
    name = "bola"
    vuln_class = VulnClass.BOLA

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        candidates = [
            e for e in endpoints
            if e.is_id_bearing and e.method in MUTATING_ID_METHODS and e.path_params
        ]

        # A role at the top of the configured privilege hierarchy (e.g. an admin/support
        # persona) is generally *expected* to have broad cross-account read access as part
        # of its legitimate function. Testing BOLA by attacking with that identity would
        # produce a flood of false positives on endpoints that intentionally grant it
        # elevated access. We still test it as a potential *victim* (can a lower-privileged
        # role read the admin's data?) - just not as the attacker.
        max_rank = max((r.privilege_rank for r in self.config.roles), default=0)
        privileged_bypass_roles = {r.name for r in self.config.roles if r.privilege_rank == max_rank}

        for ep in candidates:
            id_param = next((p for p in ep.path_params if p), None)
            if not id_param:
                continue

            triples = pick_two_roles_with_resource(self.config.roles, id_param)
            for owner, attacker, resource_id in triples:
                if attacker.name in privileged_bypass_roles:
                    continue
                path = self.fill_path(ep.path, {id_param: resource_id})

                # Baseline: owner accessing their own resource (expected to succeed)
                owner_resp, owner_ev = self.client.request(
                    ep.method, path, role=owner,
                    description=f"Baseline: {owner.name} accesses own resource {resource_id}",
                )
                # Attack: different role accessing the owner's resource
                attack_body = _placeholder_body(ep) if ep.method in {"PUT", "PATCH"} else None
                attack_resp, attack_ev = self.client.request(
                    ep.method, path, role=attacker, json_body=attack_body,
                    description=f"BOLA probe: {attacker.name} attempts {owner.name}'s resource {resource_id}",
                )

                if owner_resp.status_code < 300 and attack_resp.status_code < 300:
                    findings.append(
                        Finding(
                            vuln_class=VulnClass.BOLA,
                            severity=Severity.HIGH,
                            endpoint=ep.key,
                            title=f"Possible BOLA/IDOR on {ep.key}",
                            description=(
                                f"Role '{attacker.name}' received a {attack_resp.status_code} response "
                                f"when requesting resource '{resource_id}' ({id_param}) owned by role "
                                f"'{owner.name}'. Baseline owner access also succeeded "
                                f"({owner_resp.status_code}), suggesting the endpoint may not enforce "
                                f"object-level ownership checks."
                            ),
                            actor_role=attacker.name,
                            victim_role=owner.name,
                            confirmed=False,
                            confidence="unverified",
                            evidence=[owner_ev, attack_ev],
                            remediation=(
                                "Enforce object-level authorization on every access to this resource: "
                                "verify the authenticated principal is the owner (or explicitly "
                                "authorized) before returning or mutating data, server-side, on every "
                                "request - never trust the client-supplied identifier alone."
                            ),
                            cwe="CWE-639",
                            owasp_api_id="API1:2023",
                            tags=["bola", "idor", ep.method.lower()],
                        )
                    )
        return findings


def _placeholder_body(ep: Endpoint) -> dict:
    """Very small heuristic body for PUT/PATCH probes; verification does not rely on
    this being semantically perfect, only on observing whether the mutation is accepted
    and whether it actually applies (checked separately by the verifier).
    """
    schema = ep.request_body_schema or {}
    props = schema.get("properties", {})
    body = {}
    for name, pspec in props.items():
        t = pspec.get("type")
        if t == "string":
            body[name] = "probe-value"
        elif t in ("integer", "number"):
            body[name] = 1
        elif t == "boolean":
            body[name] = True
    return body or {"probe": "value"}
