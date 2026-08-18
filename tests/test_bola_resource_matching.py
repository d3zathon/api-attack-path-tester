from apiattack.checks.resource_matching import pick_two_roles_with_resource
from apiattack.models import Role


def test_generic_id_maps_to_endpoint_resource_type():
    alice = Role(name="alice", owned_resources={"expense_id": ["1", "2"]})
    carol = Role(name="carol", owned_resources={"expense_id": ["4"]})

    triples = pick_two_roles_with_resource(
        [alice, carol], "id", endpoint_path="/api/v1/expenses/{id}"
    )

    assert (carol, alice, "4") in triples
    assert (alice, carol, "1") in triples


def test_generic_id_uses_resource_before_nested_action():
    alice = Role(name="alice", owned_resources={"expense_id": ["1"]})
    carol = Role(name="carol", owned_resources={"expense_id": ["4"]})

    triples = pick_two_roles_with_resource(
        [alice, carol], "id", endpoint_path="/api/v1/expenses/{id}/approve"
    )

    assert (carol, alice, "4") in triples


def test_semantic_parameter_names_are_supported():
    alice = Role(name="alice", owned_resources={"expense_id": ["1"]})
    bob = Role(name="bob", owned_resources={"expense_id": ["2"]})

    triples = pick_two_roles_with_resource(
        [alice, bob], "expense_id", endpoint_path="/api/v1/expenses/{expense_id}"
    )

    assert len(triples) == 2


def test_no_cross_resource_id_collision():
    alice = Role(name="alice", owned_resources={"user_id": ["1"]})
    bob = Role(name="bob", owned_resources={"expense_id": ["1"]})

    triples = pick_two_roles_with_resource(
        [alice, bob], "id", endpoint_path="/api/v1/expenses/{id}"
    )

    assert triples == [(bob, alice, "1")]
