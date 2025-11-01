# Fix Missing Dependencies

## Issue

```
ModuleNotFoundError: No module named 'schedule'
```

## Solution

Install all dependencies from requirements.txt:

```bash
pip install -r requirements.txt
```

Or install just the missing package:

```bash
pip install schedule>=1.2.0
```

## Quick Fix Command

Run this in your terminal:

```bash
pip install -r requirements.txt
```

This will install:

- `schedule>=1.2.0` (for backup scheduler)
- `pytest-cov>=4.1.0` (for test coverage)
- All other dependencies

## Verify Installation

After installing, verify:

```bash
python -c "import schedule; print('schedule installed')"
python -c "import pytest_cov; print('pytest-cov installed')"
```

## Then Run Tests Again

```bash
python -m pytest tests/ --cov=app --cov-fail-under=95 --cov-report=html
```
