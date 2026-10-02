"""Authentication: verify partner JWTs.

SR-1: signature, expiry, issuer and audience are always verified, and the
algorithm is pinned so a token cannot pick its own (alg=none, HS/RS confusion).
In production the key would come from the identity provider's JWKS (RS256);
the lab uses a shared HS256 secret so it runs without an IdP."""
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, get_settings

ALGORITHMS = ["HS256"]
_bearer = HTTPBearer(auto_error=True)


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str  # the bank partner this caller belongs to
    scopes: frozenset


def current_principal(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> Principal:
    try:
        claims = jwt.decode(
            creds.credentials,
            settings.jwt_secret,
            algorithms=ALGORITHMS,
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            leeway=30,
            options={"require": ["exp", "iat", "sub", "tenant"]},
        )
    except jwt.PyJWTError:
        # Same message for every failure: don't tell an attacker which check failed.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    return Principal(
        subject=str(claims["sub"]),
        tenant_id=str(claims["tenant"]),
        scopes=frozenset(str(claims.get("scope", "")).split()),
    )


def require_scope(scope: str):
    """SR-3: each route declares the one scope it needs (least privilege for API clients)."""

    def checker(principal: Principal = Depends(current_principal)) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient scope")
        return principal

    return checker
