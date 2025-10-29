# Makefile for SecureApp

.PHONY: help install install-dev test test-cov lint format type-check security clean build docker-build docker-run

# Default target
help:
	@echo "Available targets:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black"
	@echo "  type-check   Run type checking with mypy"
	@echo "  security     Run security checks"
	@echo "  clean        Clean temporary files"
	@echo "  build        Build package"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run Docker container"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy bandit safety pre-commit
	pre-commit install

# Testing
test:
	pytest tests/

test-cov:
	pytest tests/ --cov=app --cov-report=html --cov-report=xml

# Code Quality
lint:
	flake8 app/ tests/
	black --check app/ tests/

format:
	black app/ tests/
	isort app/ tests/

type-check:
	mypy app/

# Security
security:
	bandit -r app/
	safety check

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Build
build:
	python -m build

# Docker
docker-build:
	docker build -t secureapp .

docker-run:
	docker run -v $(PWD)/data:/app/data -v $(PWD)/logs:/app/logs secureapp

# Development
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify installation"

# CI/CD helpers
ci-test: test-cov lint type-check security

# Release helpers
release-check: clean test-cov lint type-check security build
	@echo "Release checks passed!"

# Database helpers
db-init:
	python -c "from app.models.database import DatabaseManager; from config.settings import DATABASE_URL; db = DatabaseManager(DATABASE_URL); db.create_tables(); print('Database initialized')"

# Application helpers
run:
	python main.py

debug:
	python debug_auth.py

verify:
	python verify_packages.py
