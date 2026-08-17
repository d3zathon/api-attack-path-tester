"""Privilege escalation check (mass-assignment of role/permission fields).

Two-stage logic:
  1. As the lowest-privileged role, attempt to set a privilege-related field
     (role, is_admin, permissions, ...) on a self-service mutating endpoint
     (e.g. PUT/PATCH /users/{id}/profile).
  2. If accepted (2xx), immediately probe a *function-restricted* endpoint (drawn from
     endpoint_role_requirements) that the low-priv role should NOT be able to reach.
     If that follow-up call now succeeds, this is a strong, directly-evidenced
     escalation - not just an accepted field.

Stage 2 is what lets this check hand the verifier (and the attack-path builder) a
finding backed by an observed capability change, not just a 200 on a PATCH.
"""
from __future__ import annotations

from typing import List, Optional

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck

PRIV_FIELDS = ["role", "roles", "is_admin", "isAdmin", "admin", "permissions", "user_type", "account_type"]
MUTATING_METHODS = {"POST", "PUT", "PATCH"}


class PrivEscCheck(BaseCheck):
    name = "privesc"
    vuln_class = VulnClass.PRIVESC

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        low_priv_role = min(self.config.roles, key=lambda r: r.privilege_rank)
        highest_role_name = max(self.config.roles, key=lambda r: r.privilege_rank).name

        for ep in endpoints:
            if ep.method not in MUTATING_METHODS or not ep.request_body_schema:
                continue
            props = (ep.request_body_schema or {}).get("properties", {})
            target_field = next((f for f in PRIV_FIELDS if f in props), None)
            if not target_field:
                continue

            path = ep.path
            for pp in ep.path_params:
                owned = low_priv_role.owned_resources.get(pp) or ["1"]
                path = path.replace("{" + pp + "}", str(owned[0]))

            tamper_value = (
                [highest_role_name] if target_field in ("roles", "permissions") else highest_role_name
            )
            if target_field in ("is_admin", "isAdmin", "admin"):
                tamper_value = True

            body = {target_field: tamper_value}
            resp, ev = self.client.request(
                ep.method, path, role=low_priv_role, json_body=body,
                description=(
                    f"Privilege escalation probe: role '{low_priv_role.name}' sets "
                    f"'{target_field}' -> {tamper_value!r} on {ep.key}"
                ),
            )
            if resp.status_code >= 300:
                continue  # rejected outright, not a candidate

            follow_up_ep, follow_up_finding = self._probe_restricted_capability(
                endpoints, low_priv_role
            )
            evidence = [ev]
            confirmed_capability = False
            if follow_up_ep is not None and follow_up_finding is not None:
                evidence.append(follow_up_finding)
                confirmed_capability = True

            findings.append(
                Finding(
                    vuln_class=VulnClass.PRIVESC,
                    severity=Severity.CRITICAL if confirmed_capability else Severity.HIGH,
                    endpoint=ep.key,
                    title=f"Possible privilege escalation via mass assignment on {ep.key}",
                    description=(
                        f"Role '{low_priv_role.name}' was able to set the privileged field "
                        f"'{target_field}' to an elevated value via {ep.key} "
                        f"(status {resp.status_code})."
                        + (
                            f" A subsequent call to the restricted endpoint "
                            f"{follow_up_ep.key if follow_up_ep else ''} then succeeded, "
                            f"directly confirming an elevated capability was gained."
                            if confirmed_capability else
                            " Function-level impact was not independently confirmed in this run "
                            "(no restricted endpoint configured to re-test against)."
                        )
                    ),
                    actor_role=low_priv_role.name,
                    confirmed=False,  # verification layer still finalizes this
                    confidence="unverified",
                    evidence=evidence,
                    remediation=(
                        "Use an explicit allow-list of client-settable fields on every write "
                        "endpoint (avoid blind '**request_body') and never allow role/permission "
                        "fields to be set through user-facing self-service endpoints. Privilege "
                        "changes should go through a separate, tightly-authorized admin flow."
                    ),
                    cwe="CWE-269",
                    owasp_api_id="API5:2023 / API3:2023",
                    tags=["privesc", "mass-assignment", ep.method.lower()],
                )
            )
        return findings

    def _probe_restricted_capability(self, endpoints: List[Endpoint], role):
        """After a suspected escalation, try one restricted endpoint to see if the role's
        effective privileges actually changed. Returns (endpoint, evidence) or (None, None).
        """
        for ep in endpoints:
            required = ep.required_roles or self.config.endpoint_role_requirements.get(ep.key)
            if not required or role.name in required:
                continue
            path = ep.path
            for pp in ep.path_params:
                path = path.replace("{" + pp + "}", "1")
            body = {} if ep.method in {"POST", "PUT", "PATCH"} else None
            resp, ev = self.client.request(
                ep.method, path, role=role, json_body=body,
                description=f"Post-escalation capability check: '{role.name}' retries restricted {ep.key}",
            )
            if resp.status_code < 300:
                return ep, ev
        return None, None
