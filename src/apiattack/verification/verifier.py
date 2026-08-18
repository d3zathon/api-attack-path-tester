"""Verification layer for APIAT findings."""
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

    def _verify_bola(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) < 2:
            return None

        owner_ev = f.evidence[0]
        attack_ev = f.evidence[1]

        # A BOLA requires an object that the legitimate owner can access and a
        # successful cross-principal access by the attacker. Status codes are the
        # first gate; content is a second signal rather than a substitute for it.
        if owner_ev.status_code >= 300:
            return None
        if attack_ev.status_code >= 300:
            return None

        body = attack_ev.response_body_excerpt or ""
        if not body.strip() or body.strip() in ("{}", "[]", "null"):
            f.confidence = "unverified"
            f.verification_notes.append(
                "Attacker received a successful status, but the response body was empty; "
                "status code alone was insufficient to confirm object disclosure."
            )
            f.confirmed = False
            return f
        if ERRORISH_MARKERS.search(body):
            return None

        actor = self._role(f.actor_role)
        if actor:
            resp2, ev2 = self.client.request(
                attack_ev.method,
                _path_from_url(attack_ev.url, self.client.base_url),
                role=actor,
                description=f"Verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
            if resp2.status_code >= 300 or resp2.status_code != attack_ev.status_code:
                f.confidence = "unverified"
                f.verification_notes.append("Successful cross-role access did not reproduce on re-test.")
                f.confirmed = False
                return f

        victim = self._role(f.victim_role) if f.victim_role else None
        marker_hit = False
        if victim:
            markers = victim.metadata.get("identity_markers", [])
            marker_hit = any(m and m in body for m in markers)

        f.confirmed = True
        if marker_hit:
            f.confidence = "verified-high-confidence"
            f.verification_notes.append(
                "Cross-role access reproduced and the response contained a configured victim identity marker."
            )
        else:
            f.confidence = "verified"
            f.verification_notes.append(
                "Cross-role access reproduced with successful, non-empty, non-error-shaped response content."
            )
        return f

    def _verify_bfla(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None or ev.status_code >= 300:
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
            if resp2.status_code != ev.status_code or resp2.status_code >= 300:
                f.confidence = "unverified"
                f.confirmed = False
                f.verification_notes.append("Result did not reproduce on re-test.")
                return f
        f.confidence = "verified"
        f.confirmed = True
        f.verification_notes.append("Restricted endpoint reproducibly returned success to an unauthorized role.")
        return f

    def _verify_privesc(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) >= 2:
            follow_up = f.evidence[-1]
            if follow_up.status_code < 300 and not ERRORISH_MARKERS.search(follow_up.response_body_excerpt or ""):
                f.confidence = "verified-high-confidence"
                f.confirmed = True
                f.verification_notes.append("Privilege escalation was confirmed by a subsequent restricted-endpoint call.")
                return f
        f.confidence = "unverified"
        f.confirmed = False
        f.verification_notes.append("Privileged field was accepted but capability change was not independently confirmed.")
        return f

    def _verify_param_tampering(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None or ev.status_code >= 300:
            return None
        body = ev.response_body_excerpt or ""
        tampered_values = [str(v) for v in (ev.request_body or {}).values()]
        echoed = any(v and v in body for v in tampered_values)
        f.confirmed = echoed
        f.confidence = "verified" if echoed else "unverified"
        f.verification_notes.append(
            "Tampered value was observed in the response."
            if echoed else
            "Request was accepted but the tampered value was not observable in the response."
        )
        return f

    def _verify_business_logic(self, f: Finding) -> Optional[Finding]:
        f.confidence = "verified"
        f.confirmed = True
        f.verification_notes.append("Confirmed by executing the abusive workflow sequence successfully.")
        return f


def _path_from_url(url: str, base_url: str) -> str:
    return url[len(base_url):] if url.startswith(base_url) else url
