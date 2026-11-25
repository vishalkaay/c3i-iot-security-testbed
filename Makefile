SHELL := /bin/bash
PY := python3
VENV := .venv
BACKEND := backend
WEB := web

.PHONY: help venv deps api web dev test lint fmt clean seed docker-up docker-down report

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtual environment
	# --system-site-packages: the BLE GATT modules need the distro dbus-python.
	$(PY) -m venv --system-site-packages $(VENV)
	$(VENV)/bin/pip install -U pip wheel

deps: venv ## Install backend dependencies (dev)
	$(VENV)/bin/pip install -e ".[dev]"

deps-hardware: ## Install hardware extras (Raspberry Pi 5 only)
	$(VENV)/bin/pip install -e ".[hardware]"

api: ## Run the API (dev, autoreload)
	cd $(BACKEND) && ../$(VENV)/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8080

web: ## Run the web console (dev)
	cd $(WEB) && npm install && npm run dev

test: ## Run the backend test suite
	cd $(BACKEND) && ../$(VENV)/bin/pytest -q

lint: ## Ruff + mypy
	$(VENV)/bin/ruff check $(BACKEND)
	cd $(BACKEND) && ../$(VENV)/bin/mypy app || true

fmt: ## Auto-format
	$(VENV)/bin/ruff check --fix $(BACKEND)

seed: ## Create DB + bootstrap admin
	cd $(BACKEND) && ../$(VENV)/bin/python -m app.cli seed

docker-up: ## Bring the whole stack up
	docker compose up --build -d

docker-down: ## Tear down
	docker compose down

report: ## Build the LaTeX report -> docs/C3i_IoT_Testbed_Report.pdf
	cd docs && pdflatex -interaction=nonstopmode -halt-on-error C3i_IoT_Testbed_Report.tex \
		&& pdflatex -interaction=nonstopmode -halt-on-error C3i_IoT_Testbed_Report.tex
	cd docs && rm -f C3i_IoT_Testbed_Report.aux C3i_IoT_Testbed_Report.log \
		C3i_IoT_Testbed_Report.out C3i_IoT_Testbed_Report.toc

clean: ## Remove caches and build artefacts
	rm -rf $(VENV) $(WEB)/node_modules $(WEB)/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
