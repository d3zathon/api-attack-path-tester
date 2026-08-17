"""Verification layer.

Check modules deliberately over-flag: any cross-role 2xx is a *candidate*. This module's
job is to separate real, evidenced vulnerabilities from noise (flaky endpoints, generic
200-with-empty-body responses, endpoints that are genuinely public, etc.) before anything
reaches the report. A finding leaves this module in one of three states:

  - dropped entirely (not returned) - re-test showed the behavior doesn't reproduce, or the
    response does not actually indicate unauthorized access/mutation.
  - confidence="unverified" - plausible but could not be independently corroborated
    (kept in the report but clearly labeled, not counted as "confirmed").
  - confidence="verified" / "verified-high-confidence" and confirmed=True - reproduced and
    corroborated by response content, not status code alone.
"""
from __future__ import annotations

import re
from typing import List, Optional

from ..config.loader import ScanConfig
from ..engine.http_client import HttpClient
from ..models import Finding, Role, VulnClass

ERRORISH_MARKERS = re.compile(
    r"\b(forbidden|unauthorized|not[ _-]?allowed|access[ _-]?denied|permission[ _-]?denied|"
    r"invalid[ _-]?token|error)\b", re.IGNORECASE,
)


class Verifier:
    def __init__(self, config: ScanConfig, client: HttpClient):
        self.config = config
        self.client = client

    def _role(self, name: str) -> Optional[Role]:
        try:
            return self.config.role_by_name(name)
        except KeyError:
            return None

    def verify_all(self, findings: List[Finding]) -> List[Finding]:
        verified: List[Finding] = []
        for f in findings:
            result = self._verify_one(f)
            if result is not None:
                verified.append(result)
        return verified

    def _verify_one(self, f: Finding) -> Optional[Finding]:
        if f.vuln_class == VulnClass.BOLA:
            return self._verify_bola(f)
        if f.vuln_class == VulnClass.BFLA:
            return self._verify_bfla(f)
        if f.vuln_class == VulnClass.PRIVESC:
            return self._verify_privesc(f)
        if f.vuln_class == VulnClass.PARAM_TAMPERING:
            return self._verify_param_tampering(f)
        if f.vuln_class == VulnClass.BUSINESS_LOGIC:
            return self._verify_business_logic(f)
        return f

    # -- individual verification strategies -------------------------------------------------

    def _verify_bola(self, f: Finding) -> Optional[Finding]:
        attack_ev = f.evidence[-1] if f.evidence else None
        if attack_ev is None:
            return None

        body = attack_ev.response_body_excerpt or ""
        if not body.strip() or body.strip() in ("{}", "[]", "null"):
            f.confidence = "unverified"
            f.verification_notes.append(
                "Attacker response body was empty - status code alone is not strong "
                "enough evidence of data disclosure; kept as unverified."
            )
            f.confirmed = False
            return f
        if ERRORISH_MARKERS.search(body):
            # server returned 2xx but body reads like an error/soft-block -> drop
            return None

        actor = self._role(f.actor_role)
        stable = True
        if actor:
            # re-issue to confirm reproducibility rather than a one-off race/flake
            resp2, ev2 = self.client.request(
                attack_ev.method, _path_from_url(attack_ev.url, self.client.base_url),
                role=actor, description=f"Verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
            stable = resp2.status_code == attack_ev.status_code

        victim = self._role(f.victim_role) if f.victim_role else None
        marker_hit = False
        if victim:
            markers = victim.metadata.get("identity_markers", [])
            marker_hit = any(m and m in body for m in markers)

        if not stable:
            f.confidence = "unverified"
            f.verification_notes.append("Result did not reproduce on re-test.")
            f.confirmed = False
            return f

        if marker_hit:
            f.confidence = "verified-high-confidence"
            f.confirmed = True
            f.verification_notes.append(
                "Response body contained an identity marker belonging to the victim role, "
                "directly confirming cross-account data disclosure."
            )
        else:
            f.confidence = "verified"
            f.confirmed = True
            f.verification_notes.append(
                "Result reproduced consistently and the response body was non-empty and "
                "non-error-shaped; no explicit victim identity marker configured to confirm "
                "content further."
            )
        return f

    def _verify_bfla(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None:
            return None
        body = ev.response_body_excerpt or ""
        if ERRORISH_MARKERS.search(body):
            return None

        actor = self._role(f.actor_role)
        if actor:
            resp2, ev2 = self.client.request(
                ev.method, _path_from_url(ev.url, self.client.base_url),
                role=actor, description=f"Verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
            if resp2.status_code != ev.status_code:
                f.confidence = "unverified"
                f.verification_notes.append("Result did not reproduce on re-test.")
                f.confirmed = False
                return f

        f.confidence = "verified"
        f.confirmed = True
        f.verification_notes.append(
            "Restricted endpoint reproducibly returned a success status to an "
            "unauthorized role, with a response body that does not read as an error."
        )
        return f

    def _verify_privesc(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) >= 2:
            follow_up = f.evidence[-1]
            if follow_up.status_code < 300 and not ERRORISH_MARKERS.search(
                follow_up.response_body_excerpt or ""
            ):
                f.confidence = "verified-high-confidence"
                f.confirmed = True
                f.verification_notes.append(
                    "Escalation was confirmed by directly observing a subsequent "
                    "restricted-endpoint call succeed after the privilege field was set."
                )
                return f
        f.confidence = "unverified"
        f.confirmed = False
        f.verification_notes.append(
            "Privileged field was accepted, but no independent restricted-endpoint call "
            "confirmed an actual capability change; kept as unverified rather than confirmed."
        )
        return f

    def _verify_param_tampering(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None:
            return None
        body = ev.response_body_excerpt or ""
        # crude but effective: does the response echo back the tampered value?
        tampered_values = [str(v) for v in (ev.request_body or {}).values()]
        echoed = any(v and v in body for v in tampered_values)

        if echoed:
            f.confidence = "verified"
            f.confirmed = True
            f.verification_notes.append(
                "The tampered value was echoed back in the response, indicating the "
                "server accepted and likely persisted the client-supplied value."
            )
        else:
            f.confidence = "unverified"
            f.confirmed = False
            f.verification_notes.append(
                "Request was accepted (2xx) but the tampered value was not observable "
                "in the response; could not independently confirm server-side effect "
                "without a read-back endpoint. Recommend manual confirmation."
            )
        return f

    def _verify_business_logic(self, f: Finding) -> Optional[Finding]:
        # The check module already requires the abusive sequence to fully succeed
        # end-to-end, which is itself strong evidence; we mark these verified but not
        # "high confidence" since there's no independent second signal.
        f.confidence = "verified"
        f.confirmed = True
        f.verification_notes.append(
            "Confirmed by directly executing the abusive workflow sequence and "
            "observing it complete successfully."
        )
        return f


def _path_from_url(url: str, base_url: str) -> str:
    return url[len(base_url):] if url.startswith(base_url) else url
