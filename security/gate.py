#!/usr/bin/env python3
"""Risk-based security gate.

Reads the raw output of every scanner in the pipeline, normalizes it into one
list of findings, applies security/policy.yaml and security/exceptions.yaml,
and decides: block the PR, or report and track.

    python security/gate.py --results results/ [--baseline security/baseline.json]
    python security/gate.py --results results/ --write-baseline security/baseline.json

Exit 1 = at least one blocking finding. A markdown summary goes to stdout
(CI appends it to the PR / job summary).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CONFIDENCES = ["low", "medium", "high"]


@dataclass
class Finding:
    tool: str
    rule: str
    title: str
    severity: str
    confidence: str
    location: str          # file, resource or package: never a line number,
    stable_key: str = ""   # so fingerprints survive unrelated edits
    cves: list = field(default_factory=list)
    fix_available: bool = True
    notes: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        raw = "|".join([self.tool, self.rule, self.location, self.stable_key])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _rank(value: str, scale: list) -> int:
    return scale.index(value) if value in scale else 0


def _bump(severity: str) -> str:
    return SEVERITIES[min(_rank(severity, SEVERITIES) + 1, len(SEVERITIES) - 1)]


# ---------- parsers: one per tool, each returns list[Finding] ----------

def parse_semgrep(data: dict, policy: dict) -> list:
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        impact = str(meta.get("impact", "")).lower()
        severity = sev.get(r["extra"].get("severity", "INFO"), "low")
        if severity == "high" and impact == "high" and str(meta.get("likelihood", "")).lower() == "high":
            severity = "critical"
        out.append(Finding(
            tool="semgrep", rule=r["check_id"], title=r["extra"].get("message", "")[:120],
            severity=severity, confidence=str(meta.get("confidence", "medium")).lower(),
            location=r["path"], stable_key=r.get("extra", {}).get("lines", "").strip(),
        ))
    return out


def parse_gitleaks(data: list, policy: dict) -> list:
    return [Finding(tool="gitleaks", rule=s.get("RuleID", "secret"), title=f"Possible secret ({s.get('RuleID')})",
                    severity="critical", confidence="high", location=s.get("File", "?"),
                    stable_key=s.get("Fingerprint", "")) for s in data or []]


def parse_pip_audit(data: dict, policy: dict) -> list:
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            cves = [a for a in [v["id"], *v.get("aliases", [])] if a.startswith("CVE-")]
            out.append(Finding(
                tool="pip-audit", rule=v["id"], title=f"{dep['name']} {dep['version']}: {v['id']}",
                # pip-audit reports no severity; KEV/EPSS enrichment below decides how urgent it is.
                severity="medium", confidence="high", location=f"pkg:pypi/{dep['name']}",
                cves=cves, fix_available=bool(v.get("fix_versions")),
            ))
    return out


def parse_trivy(data: dict, policy: dict) -> list:
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            vid = v["VulnerabilityID"]
            out.append(Finding(
                tool="trivy", rule=vid, title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {vid}",
                severity=v.get("Severity", "UNKNOWN").lower().replace("unknown", "medium"),
                confidence="high", location=f"{res.get('Target')}:{v.get('PkgName')}",
                cves=[vid] if vid.startswith("CVE-") else [], fix_available=bool(v.get("FixedVersion")),
            ))
    return out


def parse_checkov(data, policy: dict) -> list:
    ranking = policy.get("checkov_severity", {})
    level = {cid: sev for sev, ids in ranking.items() for cid in ids}
    out = []
    for block in data if isinstance(data, list) else [data]:
        for c in block.get("results", {}).get("failed_checks", []):
            out.append(Finding(
                tool="checkov", rule=c["check_id"], title=c.get("check_name", ""),
                severity=level.get(c["check_id"], "medium"), confidence="high",
                location=f"{c.get('file_path', '?')}:{c.get('resource', '?')}",
            ))
    return out


def parse_zap(data: dict, policy: dict) -> list:
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    conf = {"4": "high", "3": "high", "2": "medium", "1": "low", "0": "low"}  # 0 = marked false positive
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            uri = (a.get("instances") or [{}])[0].get("uri", site.get("@name", "?"))
            out.append(Finding(
                tool="zap", rule=str(a.get("pluginid")), title=a.get("alert", a.get("name", "")),
                severity=risk.get(str(a.get("riskcode")), "low"), confidence=conf.get(str(a.get("confidence")), "medium"),
                location=uri.split("?")[0],
            ))
    return out


PARSERS = {
    "semgrep.json": parse_semgrep,
    "gitleaks.json": parse_gitleaks,
    "pip-audit.json": parse_pip_audit,
    "trivy.json": parse_trivy,
    "checkov.json": parse_checkov,
    "zap.json": parse_zap,
}


# ---------- enrichment and decision ----------

def load_intel(intel_dir: Path):
    kev, epss = set(), {}
    kev_file, epss_file = intel_dir / "kev.json", intel_dir / "epss.csv"
    if kev_file.exists():
        kev = {v["cveID"] for v in json.loads(kev_file.read_text()).get("vulnerabilities", [])}
    if epss_file.exists():
        with epss_file.open() as fh:
            for row in csv.DictReader(line for line in fh if not line.startswith("#")):
                epss[row["cve"]] = float(row["epss"])
    return kev, epss


def enrich(f: Finding, policy: dict, kev: set, epss: dict) -> None:
    esc = policy.get("escalation", {})
    if any(c in kev for c in f.cves):
        f.severity = "critical"
        f.notes.append("on CISA KEV (known exploited)")
    score = max((epss.get(c, 0.0) for c in f.cves), default=0.0)
    if score >= esc.get("epss_threshold", 1.0) and _rank(f.severity, SEVERITIES) < _rank("high", SEVERITIES):
        f.severity = "high"
        f.notes.append(f"EPSS {score:.0%}")
    if esc.get("internet_facing_bump") and f.tool in ("semgrep", "zap") and not f.location.startswith(("app/", "http")):
        # Code outside the served app (scripts, tooling) is less exposed.
        if f.severity in ("high", "critical"):
            f.severity = SEVERITIES[_rank(f.severity, SEVERITIES) - 1]
            f.notes.append("not internet-facing: lowered one level")


def match_exception(f: Finding, exceptions: list, today: dt.date, max_days: int):
    for e in exceptions:
        m = e.get("match", {})
        hit = e.get("fingerprint") == f.fingerprint or (
            m and m.get("tool") == f.tool and m.get("rule") == f.rule and m.get("location", f.location) == f.location)
        if not hit:
            continue
        expires = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        too_long = (expires - today).days > max_days
        return e, (expires >= today and not too_long), expires, too_long
    return None, False, None, False


def decide(f: Finding, policy: dict, is_new: bool) -> bool:
    if f.tool in policy.get("warn_only_tools", []):
        return False
    always = policy.get("always_block", {})
    if f.tool in always.get("tools", []):
        return True
    if always.get("known_exploited") and any("KEV" in n for n in f.notes):
        return True
    b = policy.get("block", {})
    if b.get("only_new", True) and not is_new:
        return False
    if b.get("sca_requires_fix") and f.tool in ("pip-audit", "trivy") and not f.fix_available:
        return False
    return (_rank(f.severity, SEVERITIES) >= _rank(b.get("min_severity", "high"), SEVERITIES)
            and _rank(f.confidence, CONFIDENCES) >= _rank(b.get("min_confidence", "high"), CONFIDENCES))


def collect(results: Path, policy: dict) -> list:
    findings = []
    for name, parser in PARSERS.items():
        path = results / name
        if path.exists() and path.stat().st_size:
            findings += parser(json.loads(path.read_text()), policy)
    return findings


def main(argv=None) -> int:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--policy", type=Path, default=here / "policy.yaml")
    ap.add_argument("--exceptions", type=Path, default=here / "exceptions.yaml")
    ap.add_argument("--baseline", type=Path, default=here / "baseline.json")
    ap.add_argument("--intel", type=Path, default=here / "intel")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    ap.add_argument("--write-baseline", type=Path)
    args = ap.parse_args(argv)

    policy = yaml.safe_load(args.policy.read_text())
    exceptions = (yaml.safe_load(args.exceptions.read_text()) or {}).get("exceptions", []) if args.exceptions.exists() else []
    kev, epss = load_intel(args.intel)
    findings = collect(args.results, policy)
    for f in findings:
        enrich(f, policy, kev, epss)

    if args.write_baseline:
        args.write_baseline.write_text(json.dumps({"fingerprints": sorted({f.fingerprint for f in findings})}, indent=2) + "\n")
        print(f"baseline written: {len(findings)} findings")
        return 0

    baseline = set(json.loads(args.baseline.read_text())["fingerprints"]) if args.baseline.exists() else set()
    sla = policy.get("sla_days", {})
    blocking, new, debt, suppressed, expired = [], [], [], [], []
    for f in sorted(findings, key=lambda x: -_rank(x.severity, SEVERITIES)):
        exc, active, expires, too_long = match_exception(f, exceptions, args.today, policy.get("exceptions", {}).get("max_days", 90))
        if exc and active:
            suppressed.append((f, exc, expires))
            continue
        if exc and not active:
            expired.append((f, exc, expires, too_long))
        is_new = f.fingerprint not in baseline
        if decide(f, policy, is_new):
            blocking.append(f)
        elif is_new:
            new.append(f)
        else:
            debt.append(f)

    def row(f):
        due = args.today + dt.timedelta(days=sla.get(f.severity, 180)) if f.severity in sla else None
        note = "; ".join(f.notes)
        return f"| {f.severity} | {f.tool} | `{f.rule}` | {f.location} | {f.title[:70]} | {due or '-'} | {note} |"

    hdr = "| Severity | Tool | Rule | Where | What | Fix by | Notes |\n|---|---|---|---|---|---|---|"
    print("## Security gate\n")
    print(f"**{'BLOCKED' if blocking else 'PASSED'}**: {len(blocking)} blocking, {len(new)} new (non-blocking), "
          f"{len(debt)} existing debt, {len(suppressed)} accepted risk, {len(expired)} expired exceptions.\n")
    if blocking:
        print("### Blocking: fix before merge\n" + hdr)
        print("\n".join(row(f) for f in blocking) + "\n")
        print("Think one is a false positive? Mark it inline with a reason (`# nosemgrep: <rule>`, `# gitleaks:allow`, `#checkov:skip=<id>: why`; CODEOWNERS routes those lines to AppSec), or request an exception "
              "in `security/exceptions.yaml` (owner, ticket, expiry). AppSec reviews within one business day.\n")
    if new:
        print("### New, not blocking: tracked against SLA\n" + hdr)
        print("\n".join(row(f) for f in new) + "\n")
    if expired:
        print("### Exceptions that no longer apply\n")
        for f, e, exp, too_long in expired:
            why = f"longer than {policy['exceptions']['max_days']} days" if too_long else f"expired {exp}"
            print(f"- `{f.rule}` at {f.location} ({e.get('ticket')}, owner {e.get('owner')}): {why}")
        print()
    if suppressed:
        print("<details><summary>Accepted risks</summary>\n")
        for f, e, exp in suppressed:
            print(f"- `{f.rule}` at {f.location}: {e.get('ticket')}, owner {e.get('owner')}, expires {exp}")
        print("\n</details>")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
