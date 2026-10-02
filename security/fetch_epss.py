#!/usr/bin/env python3
"""Look up EPSS scores (FIRST.org API) for every CVE in the scan results and
write security/intel/epss.csv for the gate. Usage: fetch_epss.py results/ out.csv"""
import json
import re
import sys
import urllib.request
from pathlib import Path

results, out = Path(sys.argv[1]), Path(sys.argv[2])
cves = sorted({m for f in results.glob("*.json") for m in re.findall(r"CVE-\d{4}-\d{4,}", f.read_text())})
rows = ["cve,epss,percentile"]
for i in range(0, len(cves), 100):
    url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 100])
    with urllib.request.urlopen(url, timeout=20) as resp:
        rows += [f"{d['cve']},{d['epss']},{d['percentile']}" for d in json.load(resp)["data"]]
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(rows) + "\n")
print(f"EPSS scores for {len(rows) - 1} of {len(cves)} CVEs")
