"""SR-1: token verification. Each test is an attack a real client could try."""
import base64
import json
import time

from .conftest import auth, make_token


def test_valid_token_works(client):
    assert client.get("/v1/offers", headers=auth(make_token())).status_code == 200


def test_missing_token_rejected(client):
    assert client.get("/v1/offers").status_code in (401, 403)


def test_expired_token_rejected(client):
    old = int(time.time()) - 3600
    assert client.get("/v1/offers", headers=auth(make_token(iat=old, exp=old + 60))).status_code == 401


def test_wrong_audience_rejected(client):
    assert client.get("/v1/offers", headers=auth(make_token(aud="some-other-api"))).status_code == 401


def test_wrong_signing_key_rejected(client):
    forged = make_token(key="attacker-key-of-sufficient-length-123")  # gitleaks:allow (test fixture, not a real key)
    assert client.get("/v1/offers", headers=auth(forged)).status_code == 401


def test_alg_none_rejected(client):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    now = int(time.time())
    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(
        {"sub": "x", "tenant": "bank-b", "scope": "offers:read", "iss": "https://auth.offerline.example",
         "aud": "offerline-partner-api", "iat": now, "exp": now + 300}) + "."
    assert client.get("/v1/offers", headers=auth(forged)).status_code == 401


def test_missing_tenant_claim_rejected(client):
    from .conftest import AUD, ISS, SECRET
    import jwt
    now = int(time.time())
    token = jwt.encode({"sub": "x", "iss": ISS, "aud": AUD, "iat": now, "exp": now + 300, "scope": "offers:read"}, SECRET, algorithm="HS256")
    assert client.get("/v1/offers", headers=auth(token)).status_code == 401


def test_deeply_nested_forged_payload_is_401_not_500(client):
    """Reachability check for CVE-2026-101918 (PyJWT <= 2.14.0, RecursionError on
    nested payloads). We always verify the signature first, so a forged token
    is rejected before the payload is parsed. Kept as a regression test."""
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    token = (b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + b"." +
             b64(b"[" * 20000 + b"]" * 20000) + b"." + b64(b"forged")).decode()
    assert client.get("/v1/offers", headers=auth(token)).status_code == 401


def test_short_signing_secret_refused_at_startup(monkeypatch):
    import pytest
    from app.config import Settings
    monkeypatch.setenv("OFFERLINE_JWT_SECRET", "too-short")
    with pytest.raises(RuntimeError):
        Settings()
