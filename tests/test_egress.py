"""SR-6: SSRF defenses on partner webhook URLs."""
import pytest

from app.egress import UnsafeURL, validate_outbound_url

ALLOWED = frozenset({"hooks.bank-a.example"})


def public(_host):
    return ["8.8.8.8"]  # stand-in for a real public address; no DNS needed in tests


@pytest.mark.parametrize("url", [
    "http://hooks.bank-a.example/cb",                 # not https
    "https://169.254.169.254/latest/meta-data/",      # AWS instance metadata
    "https://evil.example/cb",                        # not allowlisted
    "https://hooks.bank-a.example:8443/cb",           # odd port
    "https://user:pass@hooks.bank-a.example/cb",      # credentials in URL
    "https://hooks.bank-a.example.evil.example/cb",   # suffix trick
])
def test_rejected(url):
    with pytest.raises(UnsafeURL):
        validate_outbound_url(url, ALLOWED, resolve=public)


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.4.7", "169.254.169.254", "169.254.170.2", "::1", "fd00::1"])
def test_allowlisted_host_resolving_to_private_address_rejected(addr):
    with pytest.raises(UnsafeURL):
        validate_outbound_url("https://hooks.bank-a.example/cb", ALLOWED, resolve=lambda h: [addr])


def test_good_url_accepted():
    assert validate_outbound_url("https://hooks.bank-a.example/cb", ALLOWED, resolve=public)


def test_webhook_route_requires_admin_scope(client):
    from .conftest import auth, make_token
    r = client.put("/v1/partner/webhook", json={"url": "https://169.254.169.254/"}, headers=auth(make_token()))
    assert r.status_code == 403


def test_webhook_route_rejects_metadata_url(client):
    from .conftest import auth, make_token
    r = client.put("/v1/partner/webhook", json={"url": "https://169.254.169.254/"},
                   headers=auth(make_token(scope="partner:admin")))
    assert r.status_code == 422
