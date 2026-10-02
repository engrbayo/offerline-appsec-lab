"""The gate is security tooling, so it gets tests like any other code."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security"))
import gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def semgrep_result(rule="offerline.account-route-missing-authz", path="app/main.py", sev="ERROR", conf="HIGH",
                   likelihood="HIGH", impact="HIGH", lines="account = db.get_account(conn, account_id)"):
    return {"check_id": rule, "path": path, "extra": {"severity": sev, "message": "msg", "lines": lines,
            "metadata": {"confidence": conf, "likelihood": likelihood, "impact": impact}}}


def run(tmp_path, files, baseline=(), exceptions=None, intel=None, today="2026-10-02", capsys=None):
    res = tmp_path / "results"
    res.mkdir()
    for name, data in files.items():
        (res / name).write_text(json.dumps(data))
    (tmp_path / "baseline.json").write_text(json.dumps({"fingerprints": list(baseline)}))
    exc = tmp_path / "exceptions.yaml"
    exc.write_text(json.dumps({"exceptions": exceptions or []}))
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    for name, text in (intel or {}).items():
        (intel_dir / name).write_text(text)
    code = gate.main(["--results", str(res), "--policy", str(ROOT / "security/policy.yaml"), "--exceptions", str(exc),
                      "--baseline", str(tmp_path / "baseline.json"), "--intel", str(intel_dir), "--today", today])
    return code, capsys.readouterr().out if capsys else ""


def test_new_high_confidence_critical_blocks(tmp_path, capsys):
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result()]}}, capsys=capsys)
    assert code == 1 and "BLOCKED" in out


def test_same_finding_in_baseline_does_not_block(tmp_path, capsys):
    f = gate.parse_semgrep({"results": [semgrep_result()]}, {})[0]
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result()]}}, baseline=[f.fingerprint], capsys=capsys)
    assert code == 0 and "1 existing debt" in out


def test_medium_confidence_reports_but_does_not_block(tmp_path, capsys):
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result(conf="MEDIUM")]}}, capsys=capsys)
    assert code == 0 and "1 new (non-blocking)" in out


def test_secret_always_blocks_even_if_old(tmp_path, capsys):
    leak = [{"RuleID": "aws-access-token", "File": "app/config.py", "Fingerprint": "abc"}]
    f = gate.parse_gitleaks(leak, {})[0]
    code, _ = run(tmp_path, {"gitleaks.json": leak}, baseline=[f.fingerprint], capsys=capsys)
    assert code == 1


def test_kev_cve_blocks_even_when_old_and_unrated(tmp_path, capsys):
    audit = {"dependencies": [{"name": "somelib", "version": "1.0", "vulns": [
        {"id": "GHSA-xxxx", "aliases": ["CVE-2099-0001"], "fix_versions": ["1.1"]}]}]}
    f = gate.parse_pip_audit(audit, {})[0]
    kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001"}]})
    code, out = run(tmp_path, {"pip-audit.json": audit}, baseline=[f.fingerprint], intel={"kev.json": kev}, capsys=capsys)
    assert code == 1 and "KEV" in out


def test_high_epss_escalates_medium_to_high(tmp_path, capsys):
    audit = {"dependencies": [{"name": "somelib", "version": "1.0", "vulns": [
        {"id": "PYSEC-1", "aliases": ["CVE-2099-0002"], "fix_versions": ["1.1"]}]}]}
    code, out = run(tmp_path, {"pip-audit.json": audit}, intel={"epss.csv": "cve,epss,percentile\nCVE-2099-0002,0.42,0.99\n"},
                    capsys=capsys)
    assert code == 1 and "EPSS 42%" in out


def test_no_fix_available_is_tracked_not_blocked(tmp_path, capsys):
    trivy = {"Results": [{"Target": "img", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-0003", "PkgName": "libfoo", "InstalledVersion": "1", "Severity": "HIGH"}]}]}
    code, _ = run(tmp_path, {"trivy.json": trivy}, capsys=capsys)
    assert code == 0


def test_dast_is_warn_only_during_rollout(tmp_path, capsys):
    zap = {"site": [{"@name": "http://app:8000", "alerts": [{"pluginid": "40018", "alert": "SQL Injection",
           "riskcode": "3", "confidence": "3", "instances": [{"uri": "http://app:8000/v1/offers"}]}]}]}
    code, out = run(tmp_path, {"zap.json": zap}, capsys=capsys)
    assert code == 0 and "SQL Injection" in out


def test_active_exception_suppresses(tmp_path, capsys):
    exc = [{"match": {"tool": "semgrep", "rule": "offerline.account-route-missing-authz"}, "owner": "x",
            "ticket": "SEC-1", "expires": "2026-11-01"}]
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result()]}}, exceptions=exc, capsys=capsys)
    assert code == 0 and "1 accepted risk" in out


def test_expired_exception_stops_suppressing(tmp_path, capsys):
    exc = [{"match": {"tool": "semgrep", "rule": "offerline.account-route-missing-authz"}, "owner": "x",
            "ticket": "SEC-1", "expires": "2026-09-01"}]
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result()]}}, exceptions=exc, capsys=capsys)
    assert code == 1 and "expired 2026-09-01" in out


def test_exception_longer_than_90_days_is_not_honored(tmp_path, capsys):
    exc = [{"match": {"tool": "semgrep", "rule": "offerline.account-route-missing-authz"}, "owner": "x",
            "ticket": "SEC-1", "expires": "2027-12-31"}]
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result()]}}, exceptions=exc, capsys=capsys)
    assert code == 1 and "longer than 90 days" in out


def test_fingerprint_ignores_line_numbers():
    a = gate.parse_semgrep({"results": [semgrep_result()]}, {})[0]
    b = gate.parse_semgrep({"results": [dict(semgrep_result(), start={"line": 999})]}, {})[0]
    assert a.fingerprint == b.fingerprint


def test_finding_outside_served_app_is_lowered(tmp_path, capsys):
    code, out = run(tmp_path, {"semgrep.json": {"results": [semgrep_result(path="scripts/oneoff.py")]}}, capsys=capsys)
    assert code == 1  # critical lowered to high: still blocks
    assert "not internet-facing" in out


def test_checkov_ranking_from_policy(tmp_path, capsys):
    ck = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_20", "check_name": "public read", "file_path": "/s3.tf", "resource": "aws_s3_bucket.x"},
        {"check_id": "CKV_AWS_18", "check_name": "access logging", "file_path": "/s3.tf", "resource": "aws_s3_bucket.x"}]}}
    findings = gate.parse_checkov(ck, gate.yaml.safe_load((ROOT / "security/policy.yaml").read_text()))
    assert {f.rule: f.severity for f in findings} == {"CKV_AWS_20": "critical", "CKV_AWS_18": "medium"}
