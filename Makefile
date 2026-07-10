.PHONY: install lint format typecheck test test-unit test-integration test-e2e \
        security lab scan report docker-build docker-up docker-down clean

install:
	pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy src/llmsec lab

test:
	pytest tests/ --cov=llmsec --cov-report=term-missing

test-unit:
	pytest tests/unit -q

test-integration:
	pytest tests/integration -q

test-e2e:
	pytest tests/e2e -q -m e2e

security:
	bandit -r src lab -c pyproject.toml
	pip-audit

lab:
	uvicorn lab.app.main:app --port 8000

scan:
	llmsec scan --target http://localhost:8000 --suite all --config configs/local.yaml --output reports

report:
	llmsec report --input $(INPUT) --format markdown --format html

docker-build:
	docker compose build

docker-up:
	docker compose up --build

docker-down:
	docker compose down

clean:
	find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov dist build
