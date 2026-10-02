"""Object-level authorization (SR-2), the control behind the #1 API risk:
broken object-level authorization (BOLA / IDOR).

Every route that takes an object id from the caller must load the object and
pass it through one of these functions before returning anything. The custom
Semgrep rule `offerline.account-route-missing-authz` enforces that in CI."""
import logging

from fastapi import HTTPException, status

from .auth import Principal

log = logging.getLogger("offerline.audit")


def authorize_account(principal: Principal, account: dict | None) -> dict:
    if account is None or account["tenant_id"] != principal.tenant_id:
        if account is not None:
            # SR-8: log the denial (who, what) without logging transaction data.
            log.warning("authz_denied sub=%s tenant=%s account=%s", principal.subject, principal.tenant_id, account["id"])
        # 404, not 403: a 403 would confirm the account exists in another tenant.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return account
