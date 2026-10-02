# Answers

## d1_invoices.py (Python / Flask)
1. **IDOR** in `get_invoice`: any logged-in user reads any invoice by changing
   the integer. Sequential ids make it trivially enumerable. Fix: filter by
   owner in the query (`Invoice.query.filter_by(id=..., tenant_id=current_user.tenant_id).first_or_404()`).
   Prevent recurrence: a shared helper plus a custom Semgrep rule plus a cross-tenant test.
2. **Path traversal** in `download_statement`: `file=../../etc/passwd`, or an
   absolute path, which makes `os.path.join` discard the base directory entirely.
   Fix: `send_from_directory` (it uses `safe_join`) and look the file up by id
   rather than taking a name from the user. Also: no ownership check on statements.

## d2_partner_auth.py (Python)
1. **Signature not verified**: `verify_signature: False` means anyone can
   forge `{"tenant": "any-bank"}`. Checking `exp` by hand doesn't help.
   Fix: `jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=..., issuer=...)`.
2. **Timing-unsafe comparison** of the webhook HMAC (`==`). Fix:
   `hmac.compare_digest(expected, signature)`. Also check a timestamp in the
   signed payload to stop replays.

## d3_reports.py (Python)
1. **SQL injection via ORDER BY**: the value is parameterized, but `sort` is
   interpolated, and you can't bind an identifier. Fix: allowlist,
   e.g. `{"date": "posted_on", "amount": "amount_cents"}[sort]`.
2. **Insecure deserialization**: `pickle.loads` on a cookie means remote code
   execution. Fix: JSON, and sign it if it must live client-side.
3. **SSRF**: server fetches any URL, including `http://169.254.169.254/`.
   Fix: allowlist + resolved-IP check + IMDSv2 + egress proxy; or have the
   merchant upload the logo instead.

## d4_orders.js (Node / Express)
1. **IDOR**: `findById` with no owner check. Fix:
   `Order.findOne({ _id: req.params.id, userId: req.user.id })`.
2. **Mass assignment**: `req.body` straight into the update, so a user sends
   `{"role": "admin"}` or `{"tenantId": "..."}`. Fix: pick allowed fields
   explicitly (or validate with a schema like zod/joi that strips unknown keys).
3. **NoSQL injection** in login: `{"email": "a@b.c", "password": {"$ne": null}}`
   logs in without the password. Also passwords are compared in plain text,
   so they're stored unhashed. Fix: validate types (strings only), look up by
   email, verify with bcrypt/argon2.

## d5_tokens.js (Node / Express)
1. **`jwt.decode` instead of `jwt.verify`**: decode doesn't check the
   signature. Fix: `jwt.verify(token, key, { algorithms: ['RS256'], audience, issuer })`.
2. **Open redirect** on `/redirect`: phishing via your domain, and token theft
   if used in an OAuth flow. Fix: allow only relative paths or an allowlist.
3. **Reflected XSS** in `/api/search`: user input in HTML without encoding.
   Fix: return JSON, or render through a templating engine that auto-escapes; add CSP.
4. **Stack traces returned to clients** in the error handler. Fix: log them
   server-side, return a generic message with a correlation id.

## D6StatementService.java (Java)
1. **SQL injection** via string concatenation (both parameters). Fix:
   `PreparedStatement` with `?` placeholders; for LIKE, bind `"%" + merchant + "%"`
   as the parameter value.
2. **XXE**: the default `DocumentBuilderFactory` resolves external entities, so a
   bank file can read local files or trigger SSRF. Fix:
   `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
3. **Sensitive data in logs**: the first line of a bank file can contain
   account data. Fix: log the file name, size and row count, never content.
   Also watch for log injection: strip CR/LF from logged user input.
