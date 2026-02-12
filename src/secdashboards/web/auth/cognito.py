"""Cognito integration: token exchange, refresh, JWKS verification."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Module-level config reference — set via configure() at app startup
_cognito_client_id: str = ""
_cognito_client_secret: str = ""
_cognito_issuer: str = ""
_jwks_url: str = ""
_cognito_idp_url: str = ""
_cognito_token_url: str = ""

# JWKS cache
_jwks_cache: dict[str, Any] | None = None
_jwks_cache_time: float = 0
_JWKS_CACHE_TTL = 3600  # 1 hour


def configure(
    *,
    client_id: str,
    client_secret: str = "",
    user_pool_id: str,
    domain: str,
    region: str = "us-west-2",
) -> None:
    """Configure the Cognito module. Call once at app startup."""
    global _cognito_client_id, _cognito_client_secret
    global _cognito_issuer, _jwks_url, _cognito_idp_url, _cognito_token_url

    _cognito_client_id = client_id
    _cognito_client_secret = client_secret
    _cognito_issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    _jwks_url = f"{_cognito_issuer}/.well-known/jwks.json"
    _cognito_idp_url = f"https://cognito-idp.{region}.amazonaws.com/"
    _cognito_token_url = f"https://{domain}/oauth2/token"


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch JWKS from Cognito, with caching."""
    global _jwks_cache, _jwks_cache_time

    if _jwks_cache and (time.time() - _jwks_cache_time < _JWKS_CACHE_TTL):
        return _jwks_cache

    async with httpx.AsyncClient() as client:
        resp = await client.get(_jwks_url)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_time = time.time()
        return _jwks_cache


def _get_signing_key(jwks: dict[str, Any], token: str) -> RSAPublicKey:
    """Find the signing key from JWKS matching the token's kid header."""
    from jwt.algorithms import RSAAlgorithm

    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise ValueError("Token missing kid header")

    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            key = RSAAlgorithm.from_jwk(key_data)
            assert isinstance(key, RSAPublicKey)  # JWKS keys are always public
            return key

    raise ValueError(f"Signing key not found for kid: {kid}")


async def verify_id_token(token: str) -> dict[str, Any]:
    """Verify an ID token's signature, issuer, audience, and expiry."""
    jwks = await _fetch_jwks()
    key = _get_signing_key(jwks, token)

    payload = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        issuer=_cognito_issuer,
        audience=_cognito_client_id,
        options={"require": ["exp", "iss", "aud"]},
    )
    return payload


async def cognito_request(action: str, body: dict[str, Any]) -> dict[str, Any]:
    """Make a request to Cognito IDP (e.g., InitiateAuth)."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _cognito_idp_url,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": f"AWSCognitoIdentityProviderService.{action}",
            },
            json=body,
        )

    data = resp.json()
    if not resp.is_success or "__type" in data:
        msg = data.get("message") or data.get("__type") or "Cognito request failed"
        raise RuntimeError(msg)

    return data


async def exchange_code_for_tokens(code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange an OAuth authorization code for tokens."""
    params = {
        "grant_type": "authorization_code",
        "client_id": _cognito_client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if _cognito_client_secret:
        params["client_secret"] = _cognito_client_secret

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _cognito_token_url,
            data=params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if not resp.is_success:
        raise RuntimeError(f"Token exchange failed: {resp.text}")

    return resp.json()


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verification (for server-trusted tokens)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    payload_b64 = parts[1]
    # Add padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def is_token_expired(token: str) -> bool:
    """Check if a JWT is expired based on its exp claim."""
    try:
        payload = decode_jwt_payload(token)
        return time.time() >= payload.get("exp", 0)
    except Exception:
        return True


def get_client_id() -> str:
    """Return configured client ID."""
    return _cognito_client_id


def get_cognito_token_url() -> str:
    """Return the Cognito token endpoint URL."""
    return _cognito_token_url


def reset_jwks_cache() -> None:
    """Reset the JWKS cache. For testing."""
    global _jwks_cache, _jwks_cache_time
    _jwks_cache = None
    _jwks_cache_time = 0
