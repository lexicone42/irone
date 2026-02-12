"""Cedar authorization engine for secdashboards.

Wraps cedarpy with the Secdash:: namespace and maps Cognito groups
to secdashboards RBAC roles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cedarpy

from secdashboards.web.auth.cognito import decode_jwt_payload

# Secdashboards group mapping:
# Cognito group name → canonical Cedar group ID
SECDASH_GROUP_MAP: dict[str, str] = {
    "admin": "admin",
    "admins": "admin",
    "administrators": "admin",
    "detection-engineer": "detection-engineer",
    "detection_engineer": "detection-engineer",
    "soc-analyst": "soc-analyst",
    "soc_analyst": "soc-analyst",
    "incident-responder": "incident-responder",
    "incident_responder": "incident-responder",
    "read-only": "read-only",
    "readonly": "read-only",
    "viewer": "read-only",
}

_initialized = False
_schema: dict[str, Any] | None = None
_policy_text: str | None = None


def _default_resolve_group(group: str) -> str:
    return SECDASH_GROUP_MAP.get(group.lower(), group)


_resolve_group = _default_resolve_group


def init_cedar_engine(
    *,
    schema_path: str | None = None,
    policy_dir: str | None = None,
    schema: dict[str, Any] | str | None = None,
    policies: str | None = None,
    resolve_group: Any = None,
) -> None:
    """Initialize the Cedar engine. Call once at server startup."""
    global _initialized, _schema, _policy_text, _resolve_group

    # Load schema
    if schema is not None:
        _schema = json.loads(schema) if isinstance(schema, str) else schema
    elif schema_path:
        _schema = json.loads(Path(schema_path).read_text())
    else:
        raise ValueError("init_cedar_engine requires schema or schema_path")

    # Load policies
    if policies is not None:
        _policy_text = policies
    elif policy_dir:
        policy_path = Path(policy_dir)
        files = sorted(f.name for f in policy_path.iterdir() if f.suffix == ".cedar")
        if not files:
            raise ValueError(f"No .cedar files found in {policy_dir}")
        _policy_text = "\n\n".join((policy_path / f).read_text() for f in files)
    else:
        raise ValueError("init_cedar_engine requires policies or policy_dir")

    # Validate policies against schema
    result = cedarpy.validate_policies(_policy_text, _schema)
    if not result:
        errors = [str(e) for e in getattr(result, "errors", [])]
        raise ValueError(f"Cedar validation failed: {'; '.join(errors) or 'unknown error'}")

    if resolve_group:
        _resolve_group = resolve_group

    _initialized = True


def is_initialized() -> bool:
    return _initialized


def build_entities(
    claims: dict[str, Any], resource: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Build Cedar entities from JWT claims and a resource descriptor."""
    resource = resource or {}
    groups = claims.get("cognito:groups", [])
    canonical_groups = list({_resolve_group(g) for g in groups})
    entities: list[dict[str, Any]] = []

    # Principal (User) entity
    entities.append(
        {
            "uid": {"type": "Secdash::User", "id": claims["sub"]},
            "attrs": {"email": claims.get("email", ""), "sub": claims["sub"]},
            "parents": [{"type": "Secdash::UserGroup", "id": g} for g in canonical_groups],
        }
    )

    # UserGroup entities — Cedar requires these to exist
    for group in canonical_groups:
        entities.append(
            {
                "uid": {"type": "Secdash::UserGroup", "id": group},
                "attrs": {},
                "parents": [],
            }
        )

    # Resource entity
    resource_id = resource.get("id", "_application")
    resource_attrs: dict[str, Any] = {
        "resourceType": resource.get("type", "application"),
    }
    if resource.get("owner"):
        resource_attrs["owner"] = {"__entity": {"type": "Secdash::User", "id": resource["owner"]}}
    entities.append(
        {
            "uid": {"type": "Secdash::Resource", "id": resource_id},
            "attrs": resource_attrs,
            "parents": [],
        }
    )

    return entities


def authorize(
    *,
    session: dict[str, Any],
    action: str,
    resource: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a Cedar authorization request.

    Returns: { authorized: bool, reason: str, diagnostics: dict }
    """
    if not _initialized:
        raise RuntimeError("Cedar engine not initialized. Call init_cedar_engine() first.")

    resource = resource or {}
    context = context or {}
    claims = decode_jwt_payload(session["tokens"]["id_token"])
    entities = build_entities(claims, resource)
    resource_id = resource.get("id", "_application")

    request = {
        "principal": f'Secdash::User::"{claims["sub"]}"',
        "action": f'Secdash::Action::"{action}"',
        "resource": f'Secdash::Resource::"{resource_id}"',
        "context": context,
    }

    # Use is_authorized_batch with schema for request validation
    results = cedarpy.is_authorized_batch(
        requests=[request],
        policies=_policy_text,
        entities=entities,
        schema=_schema,
    )

    result = results[0]

    if result.allowed:
        return {
            "authorized": True,
            "reason": "allowed",
            "diagnostics": {},
        }
    else:
        return {
            "authorized": False,
            "reason": "No matching permit policy",
            "diagnostics": {},
        }


def get_schema() -> dict[str, Any] | None:
    return _schema


def get_policies() -> str | None:
    return _policy_text


def get_resolve_group():
    return _resolve_group


def reset_for_testing() -> None:
    """Reset engine state. For testing only."""
    global _initialized, _schema, _policy_text, _resolve_group
    _initialized = False
    _schema = None
    _policy_text = None
    _resolve_group = _default_resolve_group
