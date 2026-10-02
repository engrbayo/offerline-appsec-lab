import os
import time

import jwt
import pytest

os.environ.setdefault("OFFERLINE_JWT_SECRET", "test-only-secret-not-used-anywhere-else")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

SECRET = os.environ["OFFERLINE_JWT_SECRET"]
ISS, AUD = "https://auth.offerline.example", "offerline-partner-api"


def make_token(tenant="bank-a", scope="transactions:read offers:read", key=SECRET, **claim_overrides):
    now = int(time.time())
    claims = {"sub": f"svc-{tenant}", "tenant": tenant, "scope": scope, "iss": ISS, "aud": AUD, "iat": now, "exp": now + 300}
    claims.update(claim_overrides)
    return jwt.encode(claims, key, algorithm="HS256")


@pytest.fixture
def client():
    return TestClient(app)


def auth(token):
    return {"Authorization": f"Bearer {token}"}
