# Worked scenario: escalating a serious finding

A rehearsal scenario for "tell me about a serious risk you raised". It's
fictional, built on this lab; say so if you use it.

**Situation.** Two days before a partner launch, the nightly cross-tenant
probe fails: a new endpoint, `GET /v1/accounts/{id}/statements`, returns
another bank's statement to a valid token. The team's PR passed because the
new route used `db.get_statement()`, which the custom Semgrep rule didn't cover yet.

**1. Confirm and size it (first hour).** Reproduce with two test tenants.
Check access logs and WAF logs for the route since it shipped to production
(3 days): did any partner request ids outside their tenant? Answer: no
cross-tenant 200s in the logs, so it's exposure, not a confirmed breach.

**2. Explain it in business terms.** To the engineering lead and product
owner: "Any bank partner can read other banks' customer statements by
changing a number in the URL. No one has done it yet that we can see. If one
does, it's a reportable incident to every affected bank."

**3. Give options, not a demand.**

| Option | Time | Risk left |
|---|---|---|
| A. Turn off the route with its feature flag now | 10 min | None; delays the statements feature |
| B. WAF rule blocking the route except for the launch partner | 30 min | Launch partner can still read others |
| C. Proper fix: `authorize_account` + test, ship today | ~3 hours | None after deploy |

Recommend A now, then C today. The launch is unaffected because the launch
partner doesn't use statements in week one.

**4. Shared ownership.** The API team owns the fix (C); AppSec pairs on it,
writes the Semgrep rule extension for `get_statement` and adds the route to
the probe. Ticket at critical, 48-hour SLA.

**5. Escalation path.** If option A was refused, escalate to the VP of
Engineering and the CISO the same day with the same one-paragraph impact
statement. Not as a threat, but because accepting this risk isn't a team-level decision.

**6. Close the loop.** Short blameless review: why did the rule miss it?
(It matched one function name.) Change: rule now matches any `db.get_*`
taking a caller-supplied id, and new routes need an entry in the probe's
object list (PR template checkbox).
