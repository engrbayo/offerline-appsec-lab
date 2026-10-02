# Vulnerability management: how findings are ranked and fixed

## Ranking: severity is where we start, not where we stop

1. **Tool severity** (CVSS for CVEs, rule metadata for code findings).
2. **Exploitation evidence**: on CISA KEV → critical and blocking, whatever CVSS says.
   EPSS ≥ 10% → at least high.
3. **Reachability**: is the vulnerable function actually called on a path an
   attacker can reach? Not reachable → lowered and tracked, with the reasoning
   written down (see `findings-log.md` for a worked example).
4. **Exposure**: internet-facing partner API ranks above internal tooling.
5. **Data**: anything touching bank transaction data ranks above offer metadata.
6. **Compensating controls**: WAF rule, network isolation, feature flag off.
   These buy time; they don't close the finding.

## SLAs (from first detection)

| Severity | Fix within | Who's paged |
|---|---|---|
| Critical | 7 days (KEV: 48 hours) | Owning team lead + AppSec |
| High | 30 days | Owning team |
| Medium | 90 days | Backlog, reviewed monthly |
| Low | 180 days | Backlog |

## What blocks a pull request

Only new, high-confidence, high or critical findings; any committed secret;
any CVE on KEV. Everything else is posted to the PR and tracked against its
SLA. See `security/policy.yaml`.

## Exceptions

`security/exceptions.yaml`: owner, ticket, approver, reason, expiry no more
than 90 days out. Expired exceptions stop suppressing automatically.

## False-positive handling

- Developer marks it inline with a reason (`# nosemgrep: <rule>`,
  `# gitleaks:allow`, `#checkov:skip=<id>: <why>`). CODEOWNERS sends those
  lines to AppSec for review, so suppressions can't be self-approved silently.
- If a rule produces repeated false positives, fix the rule (a sanitizer
  pattern, a narrower match), don't keep suppressing.
- New tools run in warn-only mode until the false-positive rate on our own
  code is measured and below 10%.

## Metrics we report monthly

Mean time to remediate by severity, % within SLA, open criticals/highs by
team, false-positive rate per rule, gate block rate and override rate.
