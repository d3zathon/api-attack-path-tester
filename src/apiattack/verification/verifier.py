"""Verification layer for APIAT findings.

Verification must distinguish a blocked probe from a probe that was never useful enough
to assess. BOLA is confirmed only when the legitimate owner can access the object and a
different principal can reproducibly access the same object. Generic response text such
as ``error`` is not treated as an authorization failure because valid API payloads often
contain that field/message.
"""
from __future__ import annotations

import json
import re
from typing import List, Optional

from ..config.loader import ScanConfig
from ..engine.http_client import HttpClient
from ..models import Finding, Role, VulnClass

AUTH_DENIAL_MARKERS = re.compile(
    r"\b(forbidden|unauthorized|not[ _-]?allowed|access[ _-]?denied|permission[ _-]?denied|"
    r"invalid[ _-]?token|authentication required|insufficient permissions?)\b",
    re.IGNORECASE,
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

    @staticmethod
    def _successful(status_code: int) -> bool:
        return 200 <= status_code < 300

    @staticmethod
    def _body_has_authorization_denial(body: str) -> bool:
        return bool(AUTH_DENIAL_MARKERS.search(body or ""))

    @staticmethod
    def _meaningful_body(body: str) -> bool:
        text = (body or "").strip()
        if not text or text in {"{}", "[]", "null", "\"\""}:
            return False
        return True

    @staticmethod
    def _canonical_body(body: str) -> str:
        """Normalize JSON so verification is not fooled by formatting differences."""
        try:
            return json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return " ".join((body or "").split())

    def _verify_bola(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) < 2:
            return None

        owner_ev = f.evidence[0]
        attack_ev = f.evidence[1]

        # Candidate generation has already established an ownership relationship.
        # Verification now answers one question: can the other principal reproduce
        # access to the owner's object?
        if not self._successful(owner_ev.status_code):
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append(
                f"Owner baseline failed with HTTP {owner_ev.status_code}; object availability "
                "could not be established for this candidate."
            )
            return f

        if not self._successful(attack_ev.status_code):
            f.confirmed = False
            f.confidence = "verified-safe" if attack_ev.status_code in {401, 403} else "unverified"
            f.verification_notes.append(
                f"Cross-role request was blocked with HTTP {attack_ev.status_code}; "
                "no BOLA was confirmed."
            )
            return f

        body = attack_ev.response_body_excerpt or ""
        if self._body_has_authorization_denial(body):
            f.confirmed = False
            f.confidence = "verified-safe"
            f.verification_notes.append(
                "Cross-role response contained an explicit authorization-denial marker; "
                "the successful status was not treated as sufficient evidence."
            )
            return f

        if not self._meaningful_body(body) and attack_ev.method.upper() in {"GET", "HEAD"}:
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append(
                "Cross-role GET succeeded but returned no meaningful representation of the object."
            )
            return f

        actor = self._role(f.actor_role)
        if actor:
            resp2, ev2 = self.client.request(
                attack_ev.method,
                _path_from_url(attack_ev.url, self.client.base_url),
                role=actor,
                description=f"BOLA verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
            if not self._successful(resp2.status_code):
                f.confirmed = False
                f.confidence = "unverified"
                f.verification_notes.append(
                    f"Cross-role access was not reproducible on re-test (HTTP {resp2.status_code})."
                )
                return f

            # For reads, require a stable representation across two attacker requests.
            # This avoids confirming a transient 2xx error page or health response.
            if attack_ev.method.upper() in {"GET", "HEAD"}:
                body2 = ev2.response_body_excerpt or ""
                if self._body_has_authorization_denial(body2):
                    f.confirmed = False
                    f.confidence = "unverified"
                    f.verification_notes.append(
                        "The second cross-role response contained an authorization denial."
                    )
                    return f
                if self._canonical_body(body2) != self._canonical_body(body):
                    f.confirmed = False
                    f.confidence = "unverified"
                    f.verification_notes.append(
                        "Cross-role access returned inconsistent representations on re-test."
                    )
                    return f

        victim = self._role(f.victim_role) if f.victim_role else None
        marker_hit = False
        if victim:
            markers = victim.metadata.get("identity_markers", [])
            marker_hit = any(str(m) and str(m) in body for m in markers)

        f.confirmed = True
        if marker_hit:
            f.confidence = "verified-high-confidence"
            f.verification_notes.append(
                "Cross-role access reproduced and the response contained a configured victim identity marker."
            )
        else:
            f.confidence = "verified"
            f.verification_notes.append(
                "The legitimate owner accessed the object and the different principal "
                "reproducibly received a successful, meaningful representation of it."
            )
        return f

    def _verify_bfla(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None or not self._successful(ev.status_code):
            return None
        body = ev.response_body_excerpt or ""
        if self._body_has_authorization_denial(body):
            return None
        actor = self._role(f.actor_role)
        if actor:
            resp2, ev2 = self.client.request(
                ev.method, _path_from_url(ev.url, self.client.base_url),
                role=actor, description=f"Verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
            if not self._successful(resp2.status_code):
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
            if self._successful(follow_up.status_code) and not self._body_has_authorization_denial(follow_up.response_body_excerpt or ""):
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
        if ev is None or not self._successful(ev.status_code):
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
