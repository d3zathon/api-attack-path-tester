from pathlib import Path

import pytest

from apiattack.config.loader import ScanConfig, Workflow, WorkflowStep
from apiattack.engine.runner import run_scan
from apiattack.models import Role, VulnClass

SPEC = str(Path(__file__).parent.parent.parent / "examples" / "openapi_lab.yaml")


def _build_config(lab_server: str, lab_tokens: dict) -> ScanConfig:
    roles = [
        Role(
            name="attacker_low_priv", privilege_rank=0,
            auth_header={"Authorization": f"Bearer {lab_tokens['attacker']}"},
            owned_resources={"user_id": ["2"], "order_id": ["ord_2"]},
            metadata={"identity_markers": ["attacker@example.com"]},
        ),
        Role(
            name="victim_user", privilege_rank=1,
            auth_header={"Authorization": f"Bearer {lab_tokens['victim']}"},
            owned_resources={"user_id": ["1"], "order_id": ["ord_1"]},
            metadata={"identity_markers": ["victim@example.com"]},
        ),
        Role(
            name="admin", privilege_rank=9,
            auth_header={"Authorization": f"Bearer {lab_tokens['admin']}"},
            owned_resources={},
            metadata={"identity_markers": ["admin@example.com"]},
        ),
    ]
    workflows = [
        Workflow(
            name="checkout",
            description="Checkout should require payment first.",
            steps=[
                WorkflowStep("create_cart", "POST", "/cart", {}),
                WorkflowStep("pay", "POST", "/cart/1/payment", {"amount": 10}),
                WorkflowStep("checkout", "POST", "/cart/1/checkout", {}),
            ],
            skip_step_test="pay",
        ),
        Workflow(
            name="coupon_redeem",
            description="Coupon should be single-use.",
            steps=[WorkflowStep("redeem", "POST", "/coupons/apply", {"code": "WELCOME10"})],
            replay_step_test="redeem",
        ),
    ]
    return ScanConfig(
        base_url=lab_server,
        roles=roles,
        endpoint_role_requirements={
            "GET /admin/users": ["admin"],
            "GET /admin/reports": ["admin"],
        },
        sensitive_fields=["price", "balance", "status", "discount"],
        rate_limit_delay_ms=0,
        workflows=workflows,
    )


@pytest.fixture()
def scan_result(lab_server, lab_tokens):
    config = _build_config(lab_server, lab_tokens)
    return run_scan(SPEC, config)


def _confirmed(result, vuln_class, endpoint_contains=None):
    return [
        f for f in result.confirmed_findings
        if f.vuln_class == vuln_class and (endpoint_contains is None or endpoint_contains in f.endpoint)
    ]


class TestKnownVulnerabilitiesAreDetected:
    def test_bola_on_user_profile(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.BOLA, "/users/{user_id}")
        assert hits, "Expected the known BOLA on GET /users/{user_id} to be confirmed"

    def test_bola_on_orders(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.BOLA, "/orders/{order_id}")
        assert hits, "Expected the known BOLA on GET /orders/{order_id} to be confirmed"

    def test_bfla_on_admin_reports(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.BFLA, "/admin/reports")
        assert hits, "Expected BFLA on GET /admin/reports to be confirmed"

    def test_privesc_via_mass_assignment(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.PRIVESC)
        assert hits, "Expected mass-assignment privilege escalation to be confirmed"

    def test_business_logic_checkout_skip(self, scan_result):
        hits = [f for f in scan_result.confirmed_findings if "checkout" in f.title.lower()]
        assert hits, "Expected checkout-without-payment business logic flaw to be confirmed"

    def test_business_logic_coupon_replay(self, scan_result):
        hits = [f for f in scan_result.confirmed_findings if "replay" in f.title.lower()]
        assert hits, "Expected coupon replay business logic flaw to be confirmed"


class TestSafeControlEndpointsAreNotFalsePositives:
    def test_admin_users_endpoint_not_flagged(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.BFLA, "/admin/users")
        assert not hits, "GET /admin/users correctly enforces the admin role and must not be flagged"

    def test_secure_user_endpoint_not_flagged_as_bola(self, scan_result):
        hits = _confirmed(scan_result, VulnClass.BOLA, "/users/{user_id}/secure")
        assert not hits, "GET /users/{user_id}/secure correctly checks ownership and must not be flagged"


class TestAttackPathsAreBuilt:
    def test_at_least_one_attack_path(self, scan_result):
        assert len(scan_result.attack_paths) >= 1

    def test_attack_path_references_real_findings(self, scan_result):
        finding_ids = {f.id for f in scan_result.confirmed_findings}
        for path in scan_result.attack_paths:
            for step in path.steps:
                assert step.finding_id in finding_ids
