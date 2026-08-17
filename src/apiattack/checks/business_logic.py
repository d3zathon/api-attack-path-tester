"""Business-logic / workflow flaw check (OWASP API6:2023 - unrestricted access to
sensitive business flows).

Unlike the other checks, this one is driven entirely by explicit `workflows` defined
in the scan config, because "correct business logic" cannot be inferred from an
OpenAPI spec alone - it has to be told what the intended sequence is. Two abuse
patterns are tested per workflow:

  1. Step skipping: execute the workflow but omit the step named in `skip_step_test`
     (e.g. skip "pay" and go straight to "checkout"). Flag if the final step still
     succeeds.
  2. Unsafe replay: execute a step named in `replay_step_test` twice in a row with
     no intervening state change (e.g. redeem the same coupon twice). Flag if both
     calls succeed identically (rather than the second being rejected).
"""
from __future__ import annotations

from typing import List, Optional

from ..config.loader import Workflow, WorkflowStep
from ..models import Endpoint, Finding, Severity, VulnClass
from .base import BaseCheck


class BusinessLogicCheck(BaseCheck):
    name = "business_logic"
    vuln_class = VulnClass.BUSINESS_LOGIC

    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        actor_role = min(self.config.roles, key=lambda r: r.privilege_rank)

        for wf in self.config.workflows:
            if wf.skip_step_test:
                f = self._test_skip_step(wf, actor_role)
                if f:
                    findings.append(f)
            if wf.replay_step_test:
                f = self._test_unsafe_replay(wf, actor_role)
                if f:
                    findings.append(f)
        return findings

    def _run_step(self, step: WorkflowStep, role):
        return self.client.request(
            step.method, step.path, role=role, json_body=step.body,
            description=f"Workflow '{step.name}' step as role '{role.name}'",
        )

    def _test_skip_step(self, wf: Workflow, role) -> Optional[Finding]:
        evidence = []
        final_resp = None
        for step in wf.steps:
            if step.name == wf.skip_step_test:
                continue  # deliberately omitted
            resp, ev = self._run_step(step, role)
            evidence.append(ev)
            final_resp = resp

        if final_resp is not None and final_resp.status_code < 300:
            return Finding(
                vuln_class=VulnClass.BUSINESS_LOGIC,
                severity=Severity.HIGH,
                endpoint=wf.steps[-1].name if wf.steps else wf.name,
                title=f"Workflow step skip accepted: '{wf.skip_step_test}' in '{wf.name}'",
                description=(
                    f"The workflow '{wf.name}' completed successfully "
                    f"(final status {final_resp.status_code}) even though the "
                    f"'{wf.skip_step_test}' step was never performed. This suggests the "
                    f"server does not enforce workflow state/ordering and relies on the "
                    f"client to call steps in the correct sequence."
                ),
                actor_role=role.name,
                confirmed=False,
                confidence="unverified",
                evidence=evidence,
                remediation=(
                    "Track workflow/order state server-side (e.g. a state machine) and "
                    "reject any step whose preconditions were not met, instead of trusting "
                    "the client to call endpoints in the intended order."
                ),
                cwe="CWE-841",
                owasp_api_id="API6:2023",
                tags=["business-logic", "workflow-skip"],
            )
        return None

    def _test_unsafe_replay(self, wf: Workflow, role) -> Optional[Finding]:
        step = next((s for s in wf.steps if s.name == wf.replay_step_test), None)
        if not step:
            return None
        resp1, ev1 = self._run_step(step, role)
        resp2, ev2 = self._run_step(step, role)

        if resp1.status_code < 300 and resp2.status_code < 300:
            return Finding(
                vuln_class=VulnClass.BUSINESS_LOGIC,
                severity=Severity.MEDIUM,
                endpoint=step.name,
                title=f"Unsafe replay accepted: '{step.name}' in workflow '{wf.name}'",
                description=(
                    f"Step '{step.name}' in workflow '{wf.name}' succeeded when called twice "
                    f"in a row with identical input (status {resp1.status_code}, then "
                    f"{resp2.status_code}), suggesting missing idempotency/state checks "
                    f"(e.g. a coupon or one-time action being usable more than once)."
                ),
                actor_role=role.name,
                confirmed=False,
                confidence="unverified",
                evidence=[ev1, ev2],
                remediation=(
                    "Enforce idempotency or single-use constraints server-side (e.g. mark "
                    "coupons/actions as consumed, use idempotency keys, or check current "
                    "state before allowing the action to repeat)."
                ),
                cwe="CWE-841",
                owasp_api_id="API6:2023",
                tags=["business-logic", "unsafe-replay"],
            )
        return None
