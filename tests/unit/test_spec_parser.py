from pathlib import Path

from apiattack.spec_parser import parse_spec, summarize

SPEC = str(Path(__file__).parent.parent.parent / "examples" / "openapi_lab.yaml")


def test_parses_all_operations():
    endpoints = parse_spec(SPEC)
    keys = {e.key for e in endpoints}
    assert "GET /users/{user_id}" in keys
    assert "PUT /users/{user_id}/profile" in keys
    assert "GET /admin/reports" in keys
    assert len(endpoints) >= 10


def test_identifies_id_bearing_endpoints():
    endpoints = parse_spec(SPEC)
    user_ep = next(e for e in endpoints if e.key == "GET /users/{user_id}")
    assert user_ep.is_id_bearing
    assert user_ep.path_params == ["user_id"]

    login_ep = next(e for e in endpoints if e.key == "POST /login")
    assert not login_ep.is_id_bearing


def test_required_roles_extension_parsed():
    endpoints = parse_spec(SPEC)
    admin_ep = next(e for e in endpoints if e.key == "GET /admin/reports")
    assert admin_ep.required_roles == ["admin"]


def test_request_body_schema_extracted():
    endpoints = parse_spec(SPEC)
    profile_ep = next(e for e in endpoints if e.key == "PUT /users/{user_id}/profile")
    assert "role" in profile_ep.request_body_schema["properties"]


def test_summarize():
    endpoints = parse_spec(SPEC)
    info = summarize(endpoints)
    assert info["total_endpoints"] == len(endpoints)
    assert "GET" in info["methods"]
