# Findings log (worked examples from building this lab)

## 2026-10-02: PyJWT 2.14.0, CVE-2026-101918 (GHSA-42vr-xj54-vc7v)

- **Found by:** pip-audit in the SCA job.
- **What it is:** a deeply nested JSON payload makes PyJWT raise
  `RecursionError` instead of `DecodeError`, which can surface as an HTTP 500.
  CVSS 5.3, medium. The advisory says it's reachable before authentication
  only when signature verification is skipped (`verify_signature=False` or
  `PyJWKClient.get_signing_key_from_jwt`).
- **Reachability in our code:** we always call `jwt.decode` with signature
  verification and pinned algorithms (`app/auth.py`), and Semgrep rule
  `jwt-decode-unsafe` blocks any call that disables it. Confirmed by sending
  the advisory's reproduction token to the running API: **401, not 500**.
  Kept as a regression test (`test_deeply_nested_forged_payload_is_401_not_500`).
- **Decision:** medium, not reachable, not on KEV, so non-blocking. The fix
  was a patch-level upgrade to 2.15.0 with no API changes, so it went in the
  same day anyway. Cheap fixes don't wait for their SLA.

## 2026-10-02: Checkov first run on terraform/: 9 failed checks

| Check | Verdict | Action |
|---|---|---|
| CKV_AWS_109/111/356 on the KMS key policy | False positive: in a key policy, `Resource: "*"` means this key | Inline skip with reason |
| CKV_AWS_300 abort incomplete uploads | **Real**: rule covered only `incoming/` | Fixed: bucket-wide rule |
| CKV_AWS_145 log bucket not KMS | Not applicable: S3 access logs can't target SSE-KMS buckets | Inline skip with reason |
| CKV2_AWS_62 log bucket notifications | No consumer; no security value | Inline skip with reason |
| CKV2_AWS_57 secret rotation | Real gap | Exception SEC-151, expires 2026-11-30 |
| CKV_AWS_144 cross-region replication ×2 | Risk accepted: transient data | Exception SEC-142 |

Result: 120 passed, 3 failed (all under an active exception), 5 skipped with reasons.

## 2026-10-02: gitleaks hit in tests/test_authn.py

A made-up key used to test signature rejection. False positive; marked
`# gitleaks:allow` with a reason. The gate blocks every secret finding no
matter how old, because a real secret in history must be rotated, not baselined.
