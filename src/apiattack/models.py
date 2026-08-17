"""Core data models shared across the engine, checks, verification and reporting layers."""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnClass(str, enum.Enum):
    BOLA = "BOLA/IDOR"                     # API1:2023 - Broken Object Level Authorization
    BFLA = "BFLA"                          # API5:2023 - Broken Function Level Authorization
    PRIVESC = "Privilege Escalation"       # API3/API5 combo, mass assignment / param tampering
    PARAM_TAMPERING = "Parameter Tampering"
    BUSINESS_LOGIC = "Business Logic Flaw" # API6:2023 - Unrestricted Access to Business Flows


@dataclass
class Role:
    """A named identity/persona the tool authenticates as during testing."""
    name: str
    auth_header: Dict[str, str] = field(default_factory=dict)
    owned_resources: Dict[str, List[str]] = field(default_factory=dict)
    # e.g. {"order_id": ["ord_101"], "user_id": ["u_2"]}
    privilege_rank: int = 0  # higher = more privileged; used for escalation direction
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    path_params: List[str] = field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    required_roles: Optional[List[str]] = None  # from x-required-roles or roles_config.yaml
    is_id_bearing: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Evidence:
    """A single HTTP request/response pair captured as proof for a finding."""
    description: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[Any]
    status_code: int
    response_headers: Dict[str, str]
    response_body_excerpt: str
    elapsed_ms: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8]}")
    vuln_class: VulnClass = VulnClass.BOLA
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    title: str = ""
    description: str = ""
    actor_role: str = ""
    victim_role: Optional[str] = None
    confirmed: bool = False
    confidence: str = "unverified"   # unverified | verified | verified-high-confidence
    verification_notes: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    remediation: str = ""
    cwe: Optional[str] = None
    owasp_api_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class AttackPathStep:
    finding_id: str
    description: str


@dataclass
class AttackPath:
    id: str = field(default_factory=lambda: f"AP-{uuid.uuid4().hex[:8]}")
    title: str = ""
    starting_role: str = ""
    impact: str = ""
    steps: List[AttackPathStep] = field(default_factory=list)
    severity: Severity = Severity.HIGH


@dataclass
class ScanResult:
    target: str
    started_at: float
    finished_at: Optional[float] = None
    roles_tested: List[str] = field(default_factory=list)
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    raw_candidate_count: int = 0  # candidates before verification filtered out false positives

    @property
    def confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.confirmed]
