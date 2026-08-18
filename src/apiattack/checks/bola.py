"""Broken Object Level Authorization / IDOR check (OWASP API1:2023)."""
from __future__ import annotations

from typing import List, Set, Tuple

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck
from .resource_matching import pick_two_roles_with_resource

SUCCESS_MAX = 299


class BolaCheck(BaseCheck):
    name = "bola"
    vuln_class = VulnClass.BOLA

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        # BOLA is not limited to PUT/PATCH/DELETE. GET is often the most damaging
        # form because it discloses another user's object without changing state.
        candidates = [e for e in endpoints if e.path_params]

        max_rank = max((r.privilege_rank for r in self.config.roles), default=0)
        privileged_bypass_roles = {
            r.name for r in self.config.roles if r.privilege_rank == max_rank
        }

        for ep in candidates:
            for id_param in ep.path_params:
                triples = pick_two_roles_with_resource(
                    self.config.roles,
                    id_param,
                    endpoint_path=ep.path,
                )
                for owner, attacker, resource_id in triples:
                    # The highest-privilege persona is an authorization oracle rather
                    # than a useful attacker for ordinary object-ownership tests.
                    if attacker.name in privileged_bypass_roles:
                        continue

                    identity = (ep.key, owner.name, attacker.name, str(resource_id))
                    if identity in seen:
                        continue
                    seen.add(identity)

                    path = self.fill_path(ep.path, {id_param: resource_id})
                    owner_resp, owner_ev = self.client.request(
                        ep.method,
                        path,
                        role=owner,
                        description=(
                            f"BOLA baseline: {owner.name} accesses own "
                            f"{id_param}={resource_id}"
                        ),
                    )

                    # Only mutate when the endpoint itself is mutating. For DELETE,
                    # PUT and PATCH this is still an authorized test because the owner
                    # baseline establishes that the resource is live and accessible.
                    attack_body = (
                        _placeholder_body(ep)
                        if ep.method in {"PUT", "PATCH"}
                        else None
                    )
                    attack_resp, attack_ev = self.client.request(
                        ep.method,
                        path,
                        role=attacker,
                        json_body=attack_body,
                        description=(
                            f"BOLA probe: {attacker.name} attempts {owner.name}'s "
                            f"resource {resource_id}"
                        ),
                    )

                    if (
                        owner_resp.status_code <= SUCCESS_MAX
                        and attack_resp.status_code <= SUCCESS_MAX
                    ):
                        findings.append(
                            Finding(
                                vuln_class=VulnClass.BOLA,
                                severity=Severity.HIGH,
                                endpoint=ep.key,
                                title=f"Possible BOLA/IDOR on {ep.key}",
                                description=(
                                    f"Role '{attacker.name}' received HTTP "
                                    f"{attack_resp.status_code} when requesting "
                                    f"resource '{resource_id}' ({id_param}) owned by "
                                    f"'{owner.name}'. The owner baseline returned "
                                    f"HTTP {owner_resp.status_code}."
                                ),
                                actor_role=attacker.name,
                                victim_role=owner.name,
                                confirmed=False,
                                confidence="unverified",
                                evidence=[owner_ev, attack_ev],
                                remediation=(
                                    "Enforce object-level authorization on every access "
                                    "to this resource. Resolve the authenticated principal "
                                    "server-side and verify ownership or an explicit delegated "
                                    "permission before reading or mutating the object. Do not "
                                    "trust a client-supplied identifier by itself."
                                ),
                                cwe="CWE-639",
                                owasp_api_id="API1:2023",
                                tags=["bola", "idor", ep.method.lower()],
                            )
                        )
        return findings


def _placeholder_body(ep: Endpoint) -> dict:
    """Generate a schema-aware, minimally invasive body for PUT/PATCH probes."""
    schema = ep.request_body_schema or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    body = {}
    for name, pspec in props.items():
        if not isinstance(pspec, dict):
            continue
        t = pspec.get("type")
        if t == "string":
            body[name] = "apiat-bola-probe"
        elif t in ("integer", "number"):
            body[name] = 1
        elif t == "boolean":
            body[name] = True
    return body or {"probe": "apiat-bola-probe"}
