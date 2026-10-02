# offerline-appsec-lab

A small, working replica of a card-linked-offers platform, built to practice
application security end to end: secure code, custom SAST rules, a
risk-based CI gate, DAST, IaC scanning, AWS hardening in Terraform, and a
threat model that drove the design.

**Offerline is fictional.** Banks drop transaction files into S3; partner
servers call a FastAPI service for transactions and cashback offers.

## Run it

```bash
make install        # Python deps + semgrep, checkov, pip-audit (gitleaks: install separately)
make test           # 54 tests + Semgrep rule tests
make scan           # every scanner -> results/ -> security gate
make demo-idor      # break authorization in one line, watch two controls catch it
make run            # API on :8000 (docs at /docs); then `make probe` in another shell
```

## Map

| Path | What it shows |
|---|---|
| `docs/threat-model.md` | DFD, trust boundaries, STRIDE, SR-1..SR-9, design changes |
| `app/` | The API. Each control is labelled with its SR number |
| `tests/` | Security tests: forged tokens, cross-tenant access, SSRF, file validation, the gate |
| `.semgrep/offerline.yml` | 4 custom rules (IDOR, unsafe JWT decode, SSRF, SQL strings) with tests |
| `security/gate.py` | Normalizes 6 tools' output; blocks only new, high-confidence, high+ findings; KEV/EPSS; expiring exceptions |
| `security/policy.yaml`, `exceptions.yaml` | The rules of the gate, readable by developers |
| `.github/workflows/pr-security.yml` | PR pipeline: gitleaks, Semgrep (diff-aware), pip-audit, Checkov, Trivy, tests, gate |
| `.github/workflows/nightly-dast.yml` | Authenticated ZAP API scan from OpenAPI + cross-tenant probe |
| `terraform/` | KMS, S3 ingest bucket, least-privilege IAM, GitHub OIDC, Secrets Manager, WAF |
| `docs/vuln-management.md` | Ranking, SLAs, exceptions, false-positive process, metrics |
| `docs/findings-log.md` | Real findings from building this, and how each was triaged |
| `docs/risk-escalation-example.md` | Rehearsal scenario for escalating a critical finding |
| `drills/` | Code-review drills in Python, JavaScript and Java, with answers |

## Not in the lab (and what I'd use)

- **IAST / runtime**: Contrast Security or Datadog ASM on the staging service,
  to confirm which SAST findings are actually exercised.
- **Real identity provider**: RS256 tokens from the IdP's JWKS instead of HS256.
- **Production deployment**: ECS service, ALB, CloudTrail organization trail,
  GuardDuty, Security Hub.
