"""Broken Object Level Authorization / IDOR check (OWASP API1:2023)."""
from __future__ import annotations

import logging
from typing import List, Set, Tuple

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck
from .resource_matching import owned_ids_for_param, pick_two_roles_with_resource

LOG = logging.getLogger(__name__)
SUCCESS_MAX = 299


class BolaCheck(BaseCheck):
    name = "bola"
    vuln_class = VulnClass.BOLA

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()
        candidates = [e for e in endpoints if e.path_params]

        max_rank = max((r.privilege_rank for r in self.config.roles), default=0)
        privileged_bypass_roles = {
            r.name for r in self.config.roles if r.privilege_rank == max_rank
        }

        LOG.info("BOLA: %d path-parameter endpoints", len(candidates))

        for ep in candidates:
            for param in ep.path_params:
                # Resource matching is performed before HTTP traffic so the scanner
                # can distinguish "no ownership data" from "authorization denied".
                triples = pick_two_roles_with_resource(
                    self.config.roles, param, endpoint_path=ep.path
                )
                if not triples:
                    LOG.debug(
                        "BOLA skip: %s parameter=%s has no cross-role ownership mapping",
                        ep.key, param,
                    )
                    continue

                for owner, attacker, resource_id in triples:
                    if attacker.name in privileged_bypass_roles:
                        continue

                    identity = (ep.key, owner.name, attacker.name, str(resource_id))
                    if identity in seen:
                        continue
                    seen.add(identity)

                    path = self.fill_path(ep.path, {param: resource_id})
                    LOG.debug(
                        "BOLA probe: %s owner=%s attacker=%s resource=%s path=%s",
                        ep.key, owner.name, attacker.name, resource_id, path,
                    )

                    try:
                        owner_resp, owner_ev = self.client.request(
                            ep.method,
                            path,
                            role=owner,
                            description=(
                                f"BOLA baseline: {owner.name} accesses own "
                                f"{param}={resource_id}"
                            ),
                        )
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
                                f"BOLA probe: {attacker.name} attempts "
                                f"{owner.name}'s resource {resource_id}"
                            ),
                        )
                    except Exception as exc:  # noqa: BLE001
                        # A network/authentication error must never silently become
                        # "zero vulnerabilities". Keep the check deterministic and
                        # make the failure visible in debug logs.
                        LOG.warning(
                            "BOLA request failed: %s owner=%s attacker=%s resource=%s error=%s",
                            ep.key, owner.name, attacker.name, resource_id, exc,
                        )
                        continue

                    owner_status = owner_resp.status_code
                    attacker_status = attack_resp.status_code
                    LOG.info(
                        "BOLA result: %s owner=%s:%s attacker=%s:%s resource=%s",
                        ep.key, owner.name, owner_status, attacker.name,
                        attacker_status, resource_id,
                    )

                    # The baseline proves that the object exists and is accessible to
                    # its owner. The attacker receiving a successful response is the
                    # actual BOLA signal. Do not require a particular status such as 200:
                    # APIs legitimately use 201/202/204 for different operations.
                    if owner_status <= SUCCESS_MAX and attacker_status <= SUCCESS_MAX:
                        findings.append(
                            Finding(
                                vuln_class=VulnClass.BOLA,
                                severity=Severity.HIGH,
                                endpoint=ep.key,
                                title=f"BOLA/IDOR on {ep.key}",
                                description=(
                                    f"Role '{attacker.name}' received HTTP {attacker_status} "
                                    f"when accessing resource '{resource_id}' owned by "
                                    f"'{owner.name}'. The owner baseline returned HTTP "
                                    f"{owner_status}. This is consistent with missing "
                                    "object-level authorization."
                                ),
                                actor_role=attacker.name,
                                victim_role=owner.name,
                                confirmed=False,
                                confidence="unverified",
                                evidence=[owner_ev, attack_ev],
                                remediation=(
                                    "Enforce object-level authorization on every access to "
                                    "the resource. Resolve the authenticated principal "
                                    "server-side and verify ownership or an explicit delegated "
                                    "permission before reading or mutating the object."
                                ),
                                cwe="CWE-639",
                                owasp_api_id="API1:2023",
                                tags=["bola", "idor", ep.method.lower()],
                            )
                        )

        return findings


def _placeholder_body(ep: Endpoint) -> dict:
    """Generate a minimally invasive schema-aware body for PUT/PATCH probes."""
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
