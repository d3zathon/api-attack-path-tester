"""Broken Function Level Authorization check (OWASP API5:2023).

Strategy: the scan config declares which roles are *required* for a given endpoint,
either via the OpenAPI extension `x-required-roles` on the operation, or via the
`endpoint_role_requirements` map in the roles config (method + path -> [roles]).
For every such endpoint, the check calls it as every role that is NOT in the
required set and flags a candidate whenever a non-permitted role receives a
successful response.

This check depends entirely on explicit configuration of what *should* be restricted -
it does not guess, which keeps it precise and avoids flooding the report with
generic-scanner noise on endpoints that are intentionally public.
"""
from __future__ import annotations

from typing import List, Optional

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck


class BflaCheck(BaseCheck):
    name = "bfla"
    vuln_class = VulnClass.BFLA

    def _required_roles(self, ep: Endpoint) -> Optional[List[str]]:
        if ep.required_roles:
            return ep.required_roles
        return self.config.endpoint_role_requirements.get(ep.key)

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []

        for ep in endpoints:
            required = self._required_roles(ep)
            if not required:
                continue  # no declared restriction -> not in scope for this check

            for role in self.config.roles:
                if role.name in required:
                    continue  # this role is permitted, not a probe target

                path = ep.path
                for pp in ep.path_params:
                    # substitute a syntactically valid placeholder; ownership is irrelevant
                    # here since we're testing *function*-level access, not object-level
                    sample = self._any_sample_id(pp)
                    path = path.replace("{" + pp + "}", sample)

                body = {} if ep.method in {"POST", "PUT", "PATCH"} else None
                resp, ev = self.client.request(
                    ep.method, path, role=role, json_body=body,
                    description=f"BFLA probe: unauthorized role '{role.name}' calls restricted {ep.key}",
                )

                if resp.status_code < 300:
                    findings.append(
                        Finding(
                            vuln_class=VulnClass.BFLA,
                            severity=Severity.HIGH,
                            endpoint=ep.key,
                            title=f"Possible broken function-level authorization on {ep.key}",
                            description=(
                                f"Endpoint {ep.key} is declared as restricted to role(s) "
                                f"{required}, but role '{role.name}' received a "
                                f"{resp.status_code} response when calling it directly."
                            ),
                            actor_role=role.name,
                            victim_role=None,
                            confirmed=False,
                            confidence="unverified",
                            evidence=[ev],
                            remediation=(
                                "Add a server-side function-level authorization check on this "
                                "endpoint (e.g. role/permission middleware) rather than relying on "
                                "hiding the operation from lower-privileged clients in documentation "
                                "or UI only."
                            ),
                            cwe="CWE-862",
                            owasp_api_id="API5:2023",
                            tags=["bfla", ep.method.lower()],
                        )
                    )
        return findings

    @staticmethod
    def _any_sample_id(param_name: str) -> str:
        return "1"
