"""Cognito passkey authentication and Cedar authorization for secdashboards."""

from secdashboards.web.auth.dependencies import get_current_user, require_auth

__all__ = ["require_auth", "get_current_user"]
