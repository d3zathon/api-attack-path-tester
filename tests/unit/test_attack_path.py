from apiattack.attack_path.graph import build_attack_paths
from apiattack.models import Finding, Severity, VulnClass


def _finding(**kwargs) -> Finding:
    defaults = dict(confirmed=True, confidence="verified", evidence=[])
    defaults.update(kwargs)
    return Finding(**defaults)


def test_no_paths_when_no_confirmed_findings():
    findings = [_finding(confirmed=False, vuln_class=VulnClass.BOLA, actor_role="attacker")]
    assert build_attack_paths(findings) == []


def test_privesc_to_bfla_chain():
    findings = [
        _finding(
            vuln_class=VulnClass.PRIVESC, actor_role="attacker",
            confidence="verified-high-confidence", endpoint="PUT /users/2/profile",
        ),
        _finding(
            vuln_class=VulnClass.BFLA, actor_role="attacker",
            endpoint="GET /admin/reports",
        ),
    ]
    paths = build_attack_paths(findings)
    assert len(paths) == 1
    assert "privilege escalation" in paths[0].title.lower()
    assert paths[0].severity == Severity.CRITICAL
    assert len(paths[0].steps) == 2


def test_bola_recon_chain_requires_second_class():
    findings = [
        _finding(vuln_class=VulnClass.BOLA, actor_role="attacker", endpoint="GET /users/1"),
    ]
    # BOLA alone (no privesc/bfla to chain into) should not produce a chain
    assert build_attack_paths(findings) == []


def test_bola_plus_bfla_chain():
    findings = [
        _finding(vuln_class=VulnClass.BOLA, actor_role="attacker", endpoint="GET /users/1"),
        _finding(vuln_class=VulnClass.BFLA, actor_role="attacker", endpoint="GET /admin/reports"),
    ]
    paths = build_attack_paths(findings)
    assert any("recon" in p.title.lower() for p in paths)
