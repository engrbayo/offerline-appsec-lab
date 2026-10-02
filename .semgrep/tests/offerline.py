# Test cases for .semgrep/offerline.yml. Run: semgrep --test .semgrep/
import httpx
import jwt
import requests

from app import db
from app.authz import authorize_account
from app.egress import validate_outbound_url


@app.get("/v1/accounts/{account_id}/transactions")
def idor_route(account_id: str, principal=None, conn=None):
    # ruleid: offerline.account-route-missing-authz
    account = db.get_account(conn, account_id)
    return db.list_transactions(conn, account["id"], 50)


@app.get("/v1/accounts/{account_id}/transactions")
def safe_route(account_id: str, principal=None, conn=None):
    # ok: offerline.account-route-missing-authz
    account = db.get_account(conn, account_id)
    authorize_account(principal, account)
    return db.list_transactions(conn, account_id, 50)


@app.get("/v1/accounts/{account_id}")
def safe_route_assigned(account_id: str, principal=None, conn=None):
    # ok: offerline.account-route-missing-authz
    account = db.get_account(conn, account_id)
    acct = authorize_account(principal, account)
    return acct


def decode_bad(token, key):
    # ruleid: offerline.jwt-decode-unsafe
    return jwt.decode(token, key)


def decode_unverified(token, key):
    # ruleid: offerline.jwt-decode-unsafe
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})


def decode_good(token, key):
    # ok: offerline.jwt-decode-unsafe
    return jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i")


def send_bad(body):
    # ruleid: offerline.outbound-request-unvalidated-url
    requests.post(body.url, json={})


def send_bad_httpx(body):
    target = body.url
    # ruleid: offerline.outbound-request-unvalidated-url
    httpx.post(target, json={})


def send_good(body, allowed):
    url = validate_outbound_url(body.url, allowed)
    # ok: offerline.outbound-request-unvalidated-url
    requests.post(url, json={})


def sql_bad(conn, account_id):
    # ruleid: offerline.sql-built-from-strings
    return conn.execute(f"SELECT * FROM accounts WHERE id = '{account_id}'")


def sql_bad_concat(conn, account_id):
    # ruleid: offerline.sql-built-from-strings
    return conn.execute("SELECT * FROM accounts WHERE id = '" + account_id + "'")


def sql_good(conn, account_id):
    # ok: offerline.sql-built-from-strings
    return conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
