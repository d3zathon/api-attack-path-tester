from apiattack.checks.resource_matching import owned_ids_for_param, pick_two_roles_with_resource
from apiattack.models import Role


def test_exact_match():
    role = Role(name="a", owned_resources={"user_id": ["1"]})
    assert owned_ids_for_param(role, "user_id") == ["1"]


def test_camel_case_normalization():
    role = Role(name="a", owned_resources={"user_id": ["1"]})
    assert owned_ids_for_param(role, "userId") == ["1"]


def test_no_match_returns_empty():
    role = Role(name="a", owned_resources={"order_id": ["ord_1"]})
    assert owned_ids_for_param(role, "user_id") == []


def test_pick_two_roles_with_resource_finds_disjoint_ownership():
    owner = Role(name="victim", owned_resources={"user_id": ["1"]})
    attacker = Role(name="attacker", owned_resources={"user_id": ["2"]})
    triples = pick_two_roles_with_resource([owner, attacker], "user_id")
    assert (owner, attacker, "1") in [(o, a, r) for o, a, r in triples]
    assert (attacker, owner, "2") in [(o, a, r) for o, a, r in triples]


def test_pick_two_roles_excludes_shared_ownership():
    a = Role(name="a", owned_resources={"user_id": ["1"]})
    b = Role(name="b", owned_resources={"user_id": ["1"]})  # same id, e.g. shared resource
    triples = pick_two_roles_with_resource([a, b], "user_id")
    assert triples == []
