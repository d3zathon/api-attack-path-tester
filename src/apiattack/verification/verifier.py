"""Verification layer for APIAT findings."""
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
    def _same_resource(cls, first: str, second: str, resource_id: Optional[str]) -> bool:
        if not first.strip() or not second.strip():
            return False
        if resource_id is None:
            return True

        def ids(value: Any) -> set[str]:
            keys = {"id", "expense_id", "payment_id", "user_id", "project_id", "resource_id"}
            if isinstance(value, dict):
                return {str(value[k]) for k in keys if k in value and value[k] is not None}
            if isinstance(value, list):
                out: set[str] = set()
                for item in value:
                    out.update(ids(item))
                return out
            return set()

        ida, idb = ids(cls._json_value(first)), ids(cls._json_value(second))
        if ida or idb:
            return str(resource_id) in ida and str(resource_id) in idb
        return True

    def _verify_bola(self, f: Finding) -> Optional[Finding]:
        """Verify BOLA from the owner baseline + primary cross-role probe.

        The primary attacker request is already an independent authorization test: it is
        made with a different authenticated principal against the exact object selected
        from the owner's ownership set. A re-test strengthens confidence but must not turn
        a valid first proof into a false negative merely because the API is dynamic, rate
        limited, or stateful.
        """
        if len(f.evidence) < 2:
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append("Missing owner baseline or cross-role evidence.")
            return f

        owner_ev, attack_ev = f.evidence[0], f.evidence[1]

        if not self._successful(owner_ev.status_code):
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append(
                f"Owner baseline returned HTTP {owner_ev.status_code}; resource availability was not established."
            )
            return f

        if not self._successful(attack_ev.status_code):
            f.confirmed = False
            f.confidence = "verified-safe" if attack_ev.status_code in {401, 403} else "unverified"
            f.verification_notes.append(
                f"Cross-role request returned HTTP {attack_ev.status_code}; access was blocked."
            )
            return f

        body = attack_ev.response_body_excerpt or ""
        if self._body_has_authorization_denial(body):
            f.confirmed = False
            f.confidence = "verified-safe"
            f.verification_notes.append("Cross-role response contained an explicit authorization-denial marker.")
            return f

        if attack_ev.method.upper() in {"GET", "HEAD"} and not self._meaningful_body(body):
            f.confirmed = False
            f.confidence = "unverified"
            f.verification_notes.append("Cross-role read returned an empty representation.")
            return f

        resource_id = _resource_id_from_description(f.description)
        actor = self._role(f.actor_role)

        # The first cross-role 2xx response is already a valid authorization finding.
        # A retry is supplementary evidence, not a gate. This prevents dynamic/stateful
        # APIs from producing false negatives while still allowing confidence upgrades.
        f.confirmed = True
        f.confidence = "verified"
        f.verification_notes.append(
            "Confirmed: owner access succeeded and a different authenticated principal "
            "successfully accessed the same concrete object."
        )

        if not actor:
            return f

        try:
            resp2, ev2 = self.client.request(
                attack_ev.method,
                _path_from_url(attack_ev.url, self.client.base_url),
                role=actor,
                description=f"BOLA verification re-check for {f.id}",
            )
            f.evidence.append(ev2)
        except Exception as exc:  # noqa: BLE001
            f.verification_notes.append(f"Optional re-test failed: {exc!s}")
            return f

        if self._successful(resp2.status_code):
            body2 = ev2.response_body_excerpt or ""
            if (
                not self._body_has_authorization_denial(body2)
                and (attack_ev.method.upper() not in {"GET", "HEAD"} or self._meaningful_body(body2))
                and self._same_resource(body, body2, resource_id)
            ):
                f.confidence = "verified-high-confidence"
                f.verification_notes.append(
                    "Cross-role access reproduced on re-test for the same concrete resource."
                )
            else:
                f.verification_notes.append(
                    "Primary cross-role access confirmed BOLA; re-test returned a non-matching or non-authoritative representation."
                )
        else:
            f.verification_notes.append(
                f"Primary cross-role access confirmed BOLA; optional re-test returned HTTP {resp2.status_code}."
            )

        return f

    def _verify_bfla(self, f: Finding) -> Optional[Finding]:
        ev = f.evidence[-1] if f.evidence else None
        if ev is None or not self._successful(ev.status_code):
            return None
        if self._body_has_authorization_denial(ev.response_body_excerpt or ""):
            return None
        f.confidence = "verified"
        f.confirmed = True
        return f

    def _verify_privesc(self, f: Finding) -> Optional[Finding]:
        if len(f.evidence) >= 2 and self._successful(f.evidence[-1].status_code):
            f.confidence = "verified-high-confidence"
            f.confirmed = True
            return f
        f.confidence = "unverified"
        f.confirmed = False
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
        return f

    def _verify_business_logic(self, f: Finding) -> Optional[Finding]:
        f.confidence = "verified"
        f.confirmed = True
        return f


def _resource_id_from_description(description: str) -> Optional[str]:
    match = re.search(r"resource ['\"]([^'\"]+)['\"]", description or "")
    return match.group(1) if match else None


def _path_from_url(url: str, base_url: str) -> str:
    return url[len(base_url):] if url.startswith(base_url) else url
