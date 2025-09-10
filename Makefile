PY := python3
VENV := .venv
PIP := $(VENV)/bin/pip
PYTHON := $(VENV)/bin/python
FLAKE8 := $(VENV)/bin/flake8
PYTEST := $(VENV)/bin/pytest

.PHONY: venv install lint test dev reports clean

venv:
	$(PY) -m venv $(VENV)
	$(PYTHON) -m pip install -U pip

install: venv
	$(PIP) install -r requirements.txt

lint:
	$(FLAKE8) src tests

test:
	$(PYTEST) -q

dev: install lint test

reports: install
	mkdir -p reports
	$(PYTHON) src/cloudguard/cli.py --provider aws \
	  --input sample_data/aws/s3_buckets.json \
	  --report html --out reports/sample_s3.html || true
	$(PYTHON) src/cloudguard/cli.py --provider aws \
	  --input sample_data/aws/iam_policies.json \
	  --report html --out reports/sample_iam.html || true

clean:
	rm -rf $(VENV) reports __pycache__ .pytest_cache
