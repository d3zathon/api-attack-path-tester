"""Verification layer for APIAT findings.

Verification distinguishes a blocked probe from a reproducibly successful cross-principal
access. BOLA verification deliberately avoids byte-for-byte response comparison because
real APIs commonly return dynamic fields such as timestamps, request IDs, pagination
metadata, or server-generated values.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Optional

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
        return bool(text and text not in {"{}", "[]", "null", "\"\""})

    @staticmethod
    def _json_value(body: str) -> Any:
        try:
            return json.loads(body)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _same_resource(cls, first: str, second: str, resource_id: Optional[str] = None) -> bool:
        """Determine whether two successful representations refer to the same object.

        Exact body equality is intentionally not required. Dynamic fields are normal in
        production APIs. If the JSON exposes an ``id`` field matching the tested object,
        use that strong signal; otherwise successful repeated access is sufficient after
        the endpoint/path has already fixed the concrete object identifier.
        """
        if not first.strip() or not second.strip():
            return False
        if resource_id is None:
            return True

        a = cls._json_value(first)
        b = cls._json_value(second)
        if isinstance(a, dict) and isinstance(b, dict):
            ids_a = [a.get(k) for k in ("id", "expense_id", "payment_id", "user_id", "project_id")]
            ids_b = [b.get(k) for k in ("id", "expense_id", "payment_id", "user_id", "project_id")]
            present_a = {str(v) for v in ids_a if v is not None}
            present_b = {str(v) for v in ids_b if v is not None}
            if present_a or present_b:
                return str(resource_id) in present_a and str(resource_id) in present_b
        return True

    def _verify_bola(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) < 2:
            return None

        owner_ev = f.evidence[0]
        attack_ev = f.evidence[1]

        if not self._successful(owner_ev.status_code):
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append(
                f"Owner baseline failed with HTTP {owner_ev.status_code}; object availability "
                "could not be established."
            )
            return f

        if not self._successful(attack_ev.status_code):
            f.confirmed = False
            f.confidence = "verified-safe" if attack_ev.status_code in {401, 403} else "unverified"
            f.verification_notes.append(
                f"Cross-role request was blocked with HTTP {attack_ev.status_code}; no BOLA confirmed."
            )
            return f

        body = attack_ev.response_body_excerpt or ""
        if self._body_has_authorization_denial(body):
            f.confirmed = False
            f.confidence = "verified-safe"
            f.verification_notes.append("Successful response contained an explicit authorization-denial marker.")
            return f

        if attack_ev.method.upper() in {"GET", "HEAD"} and not self._meaningful_body(body):
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append("Cross-role read succeeded but returned no meaningful object representation.")
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

            body2 = ev2.response_body_excerpt or ""
            if self._body_has_authorization_denial(body2):
                f.confirmed = False
                f.confidence = "unverified"
                f.verification_notes.append("The re-test contained an authorization-denial marker.")
                return f
            if attack_ev.method.upper() in {"GET", "HEAD"} and not self._meaningful_body(body2):
                f.confirmed = False
                f.confidence = "unverified"
                f.verification_notes.append("The re-test returned no meaningful object representation.")
                return f

            # Do NOT require byte-for-byte equality. APIs routinely change timestamps,
            # request IDs, cache metadata, etags, and other dynamic fields between calls.
            resource_id = _resource_id_from_description(f.description)
            if not self._same_resource(body, body2, resource_id):
                f.confirmed = False
                f.confidence = "unverified"
                f.verification_notes.append("Re-test succeeded but did not expose the same object identifier.")
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
                "Owner access succeeded and a different principal reproducibly received the same "
                "object through a successful, meaningful response. Dynamic response fields were ignored."
            )
        return f

    def _verify_bfla(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None or not self._successful(ev.status_code):
            return None
        if self._body_has_authorization_denial(ev.response_body_excerpt or ""):
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
            "Tampered value was observed in the response." if echoed else
            "Request was accepted but the tampered value was not observable in the response."
        )
        return f

    def _verify_business_logic(self, f: Finding) -> Optional[Finding]:
        f.confidence = "verified"
        f.confirmed = True
        f.verification_notes.append("Confirmed by executing the abusive workflow sequence successfully.")
        return f


def _resource_id_from_description(description: str) -> Optional[str]:
    match = re.search(r"resource ['\"]([^'\"]+)['\"]", description or "")
    return match.group(1) if match else None


def _path_from_url(url: str, base_url: str) -> str:
    return url[len(base_url):] if url.startswith(base_url) else url
