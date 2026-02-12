"""Tests for Cedar engine (entity building, group aliases, policy eval).

Uses real Cedar schema and policies from the secdashboards cedar/ directory.
"""

from pathlib import Path

import pytest

from secdashboards.web.auth.cedar_engine import (
    SECDASH_GROUP_MAP,
    build_entities,
    init_cedar_engine,
    is_initialized,
    reset_for_testing,
)

CEDAR_DIR = Path(__file__).parent.parent / "src" / "secdashboards" / "web" / "cedar"
SCHEMA_PATH = str(CEDAR_DIR / "schema.cedarschema.json")
POLICY_DIR = str(CEDAR_DIR / "policies")


@pytest.fixture(autouse=True)
def reset_cedar():
    """Reset Cedar engine before each test."""
    reset_for_testing()
    yield
    reset_for_testing()


@pytest.fixture
def cedar_engine():
    """Initialize Cedar engine with real schema and policies."""
    init_cedar_engine(schema_path=SCHEMA_PATH, policy_dir=POLICY_DIR)


# ── Initialization ────────────────────────────────────────────────────────


def test_not_initialized_by_default():
    assert not is_initialized()


def test_init_with_schema_and_policies(cedar_engine):
    assert is_initialized()


def test_init_fails_without_schema():
    with pytest.raises(ValueError, match="schema"):
        init_cedar_engine(policy_dir=POLICY_DIR)


def test_init_fails_without_policies():
    with pytest.raises(ValueError, match="policies"):
        init_cedar_engine(schema_path=SCHEMA_PATH)


def test_init_fails_with_invalid_policy():
    with pytest.raises((ValueError, Exception)):
        init_cedar_engine(
            schema_path=SCHEMA_PATH,
            policies="this is not valid cedar",
        )


# ── Entity Building ───────────────────────────────────────────────────────


def test_build_entities_creates_user():
    claims = {"sub": "user-1", "email": "a@b.com", "cognito:groups": ["admin"]}
    entities = build_entities(claims)
    user = next(e for e in entities if e["uid"]["type"] == "Secdash::User")
    assert user["uid"]["id"] == "user-1"
    assert user["attrs"]["email"] == "a@b.com"


def test_build_entities_creates_group_entities():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admin", "soc-analyst"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "Secdash::UserGroup"]
    group_ids = {g["uid"]["id"] for g in groups}
    assert "admin" in group_ids
    assert "soc-analyst" in group_ids


def test_build_entities_resolves_group_aliases():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admins", "readonly"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "Secdash::UserGroup"]
    group_ids = {g["uid"]["id"] for g in groups}
    assert "admin" in group_ids  # admins → admin
    assert "read-only" in group_ids  # readonly → read-only


def test_build_entities_deduplicates_groups():
    claims = {"sub": "u", "email": "", "cognito:groups": ["admin", "admins", "administrators"]}
    entities = build_entities(claims)
    groups = [e for e in entities if e["uid"]["type"] == "Secdash::UserGroup"]
    assert len(groups) == 1  # All map to "admin"


def test_build_entities_default_resource():
    claims = {"sub": "u", "email": ""}
    entities = build_entities(claims)
    resource = next(e for e in entities if e["uid"]["type"] == "Secdash::Resource")
    assert resource["uid"]["id"] == "_application"
    assert resource["attrs"]["resourceType"] == "application"


def test_build_entities_custom_resource():
    claims = {"sub": "u", "email": ""}
    resource = {"id": "rule-1", "type": "detection", "owner": "owner-sub"}
    entities = build_entities(claims, resource)
    res = next(e for e in entities if e["uid"]["type"] == "Secdash::Resource")
    assert res["uid"]["id"] == "rule-1"
    assert res["attrs"]["resourceType"] == "detection"
    assert res["attrs"]["owner"] == {"__entity": {"type": "Secdash::User", "id": "owner-sub"}}


def test_build_entities_no_owner():
    claims = {"sub": "u", "email": ""}
    resource = {"id": "rule-1", "type": "detection"}
    entities = build_entities(claims, resource)
    res = next(e for e in entities if e["uid"]["type"] == "Secdash::Resource")
    assert "owner" not in res["attrs"]


def test_build_entities_user_parents_linked_to_groups():
    claims = {"sub": "u", "email": "", "cognito:groups": ["soc-analyst"]}
    entities = build_entities(claims)
    user = next(e for e in entities if e["uid"]["type"] == "Secdash::User")
    assert any(p["id"] == "soc-analyst" for p in user["parents"])


# ── Group Aliases ─────────────────────────────────────────────────────────


def test_all_admin_aliases_resolve():
    for alias in ["admin", "admins", "administrators"]:
        assert SECDASH_GROUP_MAP[alias] == "admin"


def test_all_readonly_aliases_resolve():
    for alias in ["read-only", "readonly", "viewer"]:
        assert SECDASH_GROUP_MAP[alias] == "read-only"


def test_detection_engineer_aliases():
    for alias in ["detection-engineer", "detection_engineer"]:
        assert SECDASH_GROUP_MAP[alias] == "detection-engineer"


def test_soc_analyst_aliases():
    for alias in ["soc-analyst", "soc_analyst"]:
        assert SECDASH_GROUP_MAP[alias] == "soc-analyst"


def test_incident_responder_aliases():
    for alias in ["incident-responder", "incident_responder"]:
        assert SECDASH_GROUP_MAP[alias] == "incident-responder"


def test_unknown_group_passes_through():
    from secdashboards.web.auth.cedar_engine import _resolve_group

    assert _resolve_group("custom-team") == "custom-team"


# ── Policy Evaluation ─────────────────────────────────────────────────────


def _make_session(make_jwt_fn, groups):
    """Helper to build a session dict with tokens."""
    token = make_jwt_fn(groups=groups)
    return {"tokens": {"id_token": token, "access_token": "at"}}


def test_admin_can_do_anything(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["admin"])
    result = authorize(session=session, action="deploy:lambda")
    assert result["authorized"] is True


def test_readonly_can_view_dashboard(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["read-only"])
    result = authorize(session=session, action="view:dashboard")
    assert result["authorized"] is True


def test_readonly_cannot_deploy(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["read-only"])
    result = authorize(session=session, action="deploy:lambda")
    assert result["authorized"] is False


def test_detection_engineer_can_create_detection(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["detection-engineer"])
    result = authorize(session=session, action="create:detection")
    assert result["authorized"] is True


def test_detection_engineer_cannot_deploy(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["detection-engineer"])
    result = authorize(session=session, action="deploy:lambda")
    assert result["authorized"] is False


def test_soc_analyst_can_investigate(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["soc-analyst"])
    result = authorize(session=session, action="create:investigation")
    assert result["authorized"] is True


def test_soc_analyst_cannot_create_detection(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["soc-analyst"])
    result = authorize(session=session, action="create:detection")
    assert result["authorized"] is False


def test_incident_responder_can_export(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["incident-responder"])
    result = authorize(session=session, action="export:investigation")
    assert result["authorized"] is True


def test_incident_responder_cannot_deploy(cedar_engine, make_jwt):
    from secdashboards.web.auth.cedar_engine import authorize

    session = _make_session(make_jwt, ["incident-responder"])
    result = authorize(session=session, action="deploy:lambda")
    assert result["authorized"] is False
