export OFFERLINE_JWT_SECRET ?= local-dev-only-secret-32-bytes-minimum-x
.PHONY: install test scan gate demo-idor run probe

install:
	pip install -r requirements-dev.txt semgrep checkov pip-audit

test:
	python3 -m pytest -q
	semgrep --test --metrics=off .semgrep/tests/

scan:
	mkdir -p results
	semgrep scan --metrics=off --config .semgrep/offerline.yml --json -o results/semgrep.json -q .
	pip-audit -r requirements.txt -f json -o results/pip-audit.json || true
	checkov -d terraform --quiet -o json > results/checkov.json || true
	gitleaks dir . --no-banner -f json -r results/gitleaks.json --exit-code 0 || echo "gitleaks not installed"
	$(MAKE) gate

gate:
	python3 security/gate.py --results results/

demo-idor:
	./demo/run-idor-demo.sh

run:
	OFFERLINE_ENABLE_DOCS=true uvicorn app.main:app --port 8000

probe:
	python3 security/authz_probe.py http://localhost:8000
