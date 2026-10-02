#!/usr/bin/env python3
"""Cross-tenant authorization probe against a running API.

DAST scanners test inputs; they don't know that acct_b_001 belongs to bank-b.
This probe does: it takes each tenant's token and requests every other
tenant's objects. Any 2xx is an IDOR and fails the job."""
import os
import subprocess
import sys

import httpx

BASE = sys.argv[1].rstrip("/")
OBJECTS = {"bank-a": ["acct_a_001"], "bank-b": ["acct_b_001"]}  # seeded test data


def token(tenant):
    return subprocess.check_output([sys.executable, os.path.join(os.path.dirname(__file__), "mint_test_token.py"), tenant],
                                   text=True).strip()


failures = 0
for caller in OBJECTS:
    headers = {"Authorization": f"Bearer {token(caller)}"}
    for owner, ids in OBJECTS.items():
        for obj in ids:
            r = httpx.get(f"{BASE}/v1/accounts/{obj}/transactions", headers=headers)
            expected_ok = owner == caller
            ok = (r.status_code == 200) == expected_ok and (expected_ok or r.status_code == 404)
            print(f"{'PASS' if ok else 'FAIL'}  {caller} -> {obj} ({owner}): {r.status_code}")
            failures += not ok
sys.exit(1 if failures else 0)
