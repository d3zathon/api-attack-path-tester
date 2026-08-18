import json

from apiattack.spec_parser import parse_spec


def test_any_path_parameter_is_object_bearing(tmp_path):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1"},
        "paths": {
            "/accounts/{accountNumber}": {
                "get": {"operationId": "getAccount"}
            },
            "/expenses/{id}/approve": {
                "post": {"operationId": "approveExpense"}
            },
        },
    }
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(spec), encoding="utf-8")

    endpoints = parse_spec(str(path))

    assert all(ep.is_id_bearing for ep in endpoints)
    assert endpoints[0].path_params == ["accountNumber"]
    assert endpoints[1].path_params == ["id"]
