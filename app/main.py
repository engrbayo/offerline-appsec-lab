"""Offerline partner API (lab).

Routes are deliberately small so each security control is easy to point at:
  SR-1 token verification ........ auth.current_principal
  SR-2 object-level authorization  authz.authorize_account
  SR-3 per-route scopes .......... auth.require_scope
  SR-4 parameterized SQL ......... db.*
  SR-5/7 ingest validation ....... ingest.*
  SR-6 SSRF-safe webhooks ........ egress.validate_outbound_url
  SR-8 audit logging, no PII ..... authz + exception handler
  SR-9 safe responses/headers .... middleware below
"""
import logging

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import db
from .auth import Principal, require_scope
from .authz import authorize_account
from .config import get_settings
from .egress import UnsafeURL, validate_outbound_url
from .ingest import RejectedFile, parse_file, validate_key

log = logging.getLogger("offerline")
_settings = get_settings()

app = FastAPI(
    title="Offerline Partner API",
    version="0.1.0",
    # The spec is published only in test environments, where the nightly DAST scan uses it.
    docs_url="/docs" if _settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _settings.enable_docs else None,
)
_conn = db.connect()


def get_conn():
    return _conn


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"  # responses carry financial data
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # SR-9: log the detail server-side; the client gets no stack trace.
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "internal error"}, status_code=500)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/v1/accounts/{account_id}/transactions")
def get_transactions(
    account_id: str,
    limit: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(require_scope("transactions:read")),
    conn=Depends(get_conn),
):
    account = db.get_account(conn, account_id)
    authorize_account(principal, account)
    return {"account_id": account_id, "transactions": db.list_transactions(conn, account_id, limit)}


@app.get("/v1/offers")
def get_offers(principal: Principal = Depends(require_scope("offers:read")), conn=Depends(get_conn)):
    # Tenant comes from the verified token, never from a query parameter.
    return {"offers": db.list_offers(conn, principal.tenant_id)}


class WebhookIn(BaseModel):
    url: str = Field(max_length=2048)


@app.put("/v1/partner/webhook", status_code=204)
def put_webhook(
    body: WebhookIn,
    principal: Principal = Depends(require_scope("partner:admin")),
    conn=Depends(get_conn),
):
    try:
        url = validate_outbound_url(body.url, _settings.webhook_allowed_hosts)
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc))
    db.set_webhook(conn, principal.tenant_id, url)


class IngestIn(BaseModel):
    key: str = Field(max_length=300)
    content: str


@app.post("/v1/ingest/validate")
def validate_ingest(body: IngestIn, principal: Principal = Depends(require_scope("ingest:write"))):
    try:
        validate_key(body.key, principal.tenant_id)
        rows = parse_file(body.content, _settings.max_ingest_bytes)
    except RejectedFile as exc:
        raise HTTPException(422, str(exc))
    return {"accepted_rows": len(rows)}
