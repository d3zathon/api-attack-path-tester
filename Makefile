# Convenience commands for the API Attack-Path & Authorization Tester.
# Run `make help` to see everything available.

VENV_PY := .venv/bin/python
VENV_PIP := .venv/bin/pip
LAB_PID_FILE := .lab.pid
LAB_URL := http://localhost:8000

.PHONY: help setup lab lab-stop lab-scan scan test test-cov docker-demo clean

help:
	@echo "Common commands:"
	@echo "  make setup       - create .venv and install everything (same as ./setup.sh)"
	@echo "  make lab         - start the vulnerable lab in the background"
	@echo "  make lab-stop    - stop the background lab"
	@echo "  make lab-scan    - start the lab (if needed) and run a full demo scan"
	@echo "  make test        - run the unit + integration test suite"
	@echo "  make test-cov    - run tests with a coverage report"
	@echo "  make docker-demo - run the whole thing (lab + scan) via Docker Compose"
	@echo "  make clean       - remove venv, caches, and generated reports"

setup:
	./setup.sh

lab:
	@if [ -f $(LAB_PID_FILE) ] && kill -0 $$(cat $(LAB_PID_FILE)) 2>/dev/null; then \
		echo "Lab already running (pid $$(cat $(LAB_PID_FILE)))."; \
	else \
		echo "Starting lab on $(LAB_URL) ..."; \
		( cd lab; ../$(VENV_PY) app.py > ../lab.log 2>&1 & echo $$! > ../$(LAB_PID_FILE) ); \
		sleep 1; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			curl -sf $(LAB_URL)/health > /dev/null && break; \
			sleep 1; \
		done; \
		curl -sf $(LAB_URL)/health > /dev/null && echo "Lab is up (see lab.log)." || (echo "Lab failed to start - check lab.log"; exit 1); \
	fi

lab-stop:
	@if [ -f $(LAB_PID_FILE) ]; then \
		kill $$(cat $(LAB_PID_FILE)) 2>/dev/null || true; \
		rm -f $(LAB_PID_FILE); \
		echo "Lab stopped."; \
	else \
		echo "No running lab found."; \
	fi

lab-scan: lab
	$(VENV_PY) scripts/generate_lab_config.py $(LAB_URL)
	$(VENV_PY) -m apiattack.cli scan \
		--spec examples/openapi_lab.yaml \
		--config examples/roles_lab.yaml \
		--out ./report \
		--yes-i-am-authorized
	@echo ""
	@echo "Report written to ./report/report.html and ./report/report.md"

scan:
	@echo "Usage: apiattack scan --spec <spec> --config <roles.yaml> --out ./report --yes-i-am-authorized"
	@echo "(activate the venv first: source .venv/bin/activate)"

test:
	$(VENV_PY) -m pytest -q

test-cov:
	$(VENV_PY) -m pytest --cov=apiattack -q

docker-demo:
	docker compose build
	./scripts/run_demo.sh

clean:
	$(MAKE) lab-stop || true
	rm -rf .venv .pytest_cache report demo-report lab.log examples/roles_lab.yaml
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	@echo "Cleaned."
