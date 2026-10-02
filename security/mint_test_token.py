#!/usr/bin/env python3
"""Mint a short-lived token for DAST and probes. Test environments only:
the secret is a CI secret that exists nowhere else."""
import os
import sys
import time

import jwt

tenant = sys.argv[1]
scopes = sys.argv[2] if len(sys.argv) > 2 else "transactions:read offers:read partner:admin ingest:write"
now = int(time.time())
print(jwt.encode({"sub": f"dast-{tenant}", "tenant": tenant, "scope": scopes, "iat": now, "exp": now + 3600,
                  "iss": "https://auth.offerline.example", "aud": "offerline-partner-api"},
                 os.environ["OFFERLINE_JWT_SECRET"], algorithm="HS256"))
