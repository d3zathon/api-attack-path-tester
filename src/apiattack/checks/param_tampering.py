"""Parameter tampering check.

Looks at mutating endpoints (POST/PUT/PATCH) whose request body schema exposes
"sensitive" fields (price, balance, discount, status, owner_id, etc. - configurable
via `sensitive_fields` in the scan config). As the lowest-privileged role, it submits
a request with that field overridden to an attacker-favorable value alongside an
otherwise well-formed body, and flags a candidate when the server accepts the request
(2xx) rather than rejecting/ignoring the extra or out-of-range field.

This is distinct from the privilege-escalation check, which specifically chases
role/permission fields through to a confirmed capability change.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck

TAMPER_VALUES: Dict[str, Any] = {
    "price": 0.01,
    "amount": 0.01,
    "balance": 999999,
    "discount": 100,
    "credit": 999999,
    "status": "approved",
    "verified": True,
    "is_verified": True,
    "email_verified": True,
}
MUTATING_METHODS = {"POST", "PUT", "PATCH"}
SKIP_FIELDS = {"role", "roles", "is_admin", "isAdmin", "admin", "permissions",
               "owner_id", "ownerId", "user_id"}  # handled by privesc.py instead


class ParamTamperingCheck(BaseCheck):
    name = "param_tampering"
    vuln_class = VulnClass.PARAM_TAMPERING

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        low_priv_role = min(self.config.roles, key=lambda r: r.privilege_rank)

        for ep in endpoints:
            if ep.method not in MUTATING_METHODS or not ep.request_body_schema:
                continue
            props = (ep.request_body_schema or {}).get("properties", {})
            targets = [
                f for f in self.config.sensitive_fields
                if f in props and f not in SKIP_FIELDS
            ]
            if not targets:
                continue

            path = ep.path
            for pp in ep.path_params:
                owned = low_priv_role.owned_resources.get(pp) or ["1"]
                path = path.replace("{" + pp + "}", str(owned[0]))

            body: Dict[str, Any] = {}
            for field in targets:
                body[field] = TAMPER_VALUES.get(field, "tampered")

            resp, ev = self.client.request(
                ep.method, path, role=low_priv_role, json_body=body,
                description=(
                    f"Parameter tampering probe: role '{low_priv_role.name}' submits "
                    f"out-of-policy values for {targets} on {ep.key}"
                ),
            )

            if resp.status_code < 300:
                findings.append(
                    Finding(
                        vuln_class=VulnClass.PARAM_TAMPERING,
                        severity=Severity.MEDIUM,
                        endpoint=ep.key,
                        title=f"Possible parameter tampering on {ep.key} (fields: {', '.join(targets)})",
                        description=(
                            f"Submitting attacker-favorable values for {targets} as low-privilege "
                            f"role '{low_priv_role.name}' returned {resp.status_code}, suggesting "
                            f"the server may not be re-validating these fields server-side."
                        ),
                        actor_role=low_priv_role.name,
                        confirmed=False,
                        confidence="unverified",
                        evidence=[ev],
                        remediation=(
                            "Never trust client-supplied values for fields that affect price, "
                            "balance, ownership, or approval status. Recompute or re-validate "
                            "these fields server-side from trusted state, and use allow-lists for "
                            "which fields a given role may set on a resource."
                        ),
                        cwe="CWE-20",
                        owasp_api_id="API6:2023",
                        tags=["param-tampering", ep.method.lower()],
                    )
                )
        return findings
