"""Broken Object Level Authorization / IDOR check (OWASP API1:2023)."""
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

        max_rank = max((r.privilege_rank for r in self.config.roles), default=0)
        privileged_bypass_roles = {r.name for r in self.config.roles if r.privilege_rank == max_rank}

        for ep in candidates:
            id_param = next((p for p in ep.path_params if p), None)
            if not id_param:
                continue

            # Endpoint context is essential when OpenAPI uses generic {id} parameters.
            # /expenses/{id} must match expense_id ownership, not user_id/payment_id.
            triples = pick_two_roles_with_resource(
                self.config.roles,
                id_param,
                endpoint_path=ep.path,
            )
            for owner, attacker, resource_id in triples:
                if attacker.name in privileged_bypass_roles:
                    continue
                path = self.fill_path(ep.path, {id_param: resource_id})

                owner_resp, owner_ev = self.client.request(
                    ep.method,
                    path,
                    role=owner,
                    description=f"Baseline: {owner.name} accesses own resource {resource_id}",
                )
                attack_body = _placeholder_body(ep) if ep.method in {"PUT", "PATCH"} else None
                attack_resp, attack_ev = self.client.request(
                    ep.method,
                    path,
                    role=attacker,
                    json_body=attack_body,
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
                                "object-level ownership checks."
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
