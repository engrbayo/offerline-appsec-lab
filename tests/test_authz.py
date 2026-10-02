"""SR-2 and SR-3: object-level authorization and scopes.

These are the tests scanners can't write for you: SAST and DAST don't know
that account acct_b_001 belongs to bank-b. Business-logic authorization has
to be tested explicitly."""
from .conftest import auth, make_token


def test_own_account_readable(client):
    r = client.get("/v1/accounts/acct_a_001/transactions", headers=auth(make_token("bank-a")))
    assert r.status_code == 200
    assert {t["id"] for t in r.json()["transactions"]} == {"txn_1", "txn_2"}


def test_cross_tenant_account_is_404_not_403(client):
    r = client.get("/v1/accounts/acct_b_001/transactions", headers=auth(make_token("bank-a")))
    assert r.status_code == 404  # must not reveal the account exists


def test_nonexistent_account_same_response_as_cross_tenant(client):
    other = client.get("/v1/accounts/acct_b_001/transactions", headers=auth(make_token("bank-a")))
    missing = client.get("/v1/accounts/acct_zzz/transactions", headers=auth(make_token("bank-a")))
    assert (other.status_code, other.json()) == (missing.status_code, missing.json())


def test_sql_injection_in_path_is_just_a_missing_account(client):
    r = client.get("/v1/accounts/acct_a_001' OR '1'='1/transactions", headers=auth(make_token("bank-a")))
    assert r.status_code == 404


def test_offers_scoped_to_token_tenant(client):
    r = client.get("/v1/offers", headers=auth(make_token("bank-b")))
    assert [o["id"] for o in r.json()["offers"]] == ["off_2"]


def test_tenant_query_param_is_ignored(client):
    r = client.get("/v1/offers?tenant_id=bank-a", headers=auth(make_token("bank-b")))
    assert [o["id"] for o in r.json()["offers"]] == ["off_2"]


def test_missing_scope_is_403(client):
    r = client.get("/v1/accounts/acct_a_001/transactions", headers=auth(make_token("bank-a", scope="offers:read")))
    assert r.status_code == 403


def test_limit_is_bounded(client):
    r = client.get("/v1/accounts/acct_a_001/transactions?limit=100000", headers=auth(make_token("bank-a")))
    assert r.status_code == 422
