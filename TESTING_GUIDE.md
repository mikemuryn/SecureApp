# Testing Guide

## Issue: pytest "required file not found"

If you encounter the error:

```
-bash: /home/mikemuryn/miniconda3/envs/secureapp/bin/pytest: cannot execute: required file not found
```

This is typically a conda environment issue where the pytest binary is corrupted or missing.

## Solutions

### Option 1: Use `python -m pytest` (Recommended)

Instead of calling `pytest` directly, use:

```bash
python -m pytest tests/ --cov=app --cov-fail-under=95 --cov-report=html
```

This is more reliable and works regardless of pytest installation method.

### Option 2: Reinstall pytest

```bash
# Activate your conda environment
conda activate secureapp

# Reinstall pytest and coverage tools
pip install --force-reinstall pytest pytest-cov

# Verify installation
python -m pytest --version
```

### Option 3: Fix conda environment

```bash
# Deactivate environment
conda deactivate

# Recreate the environment (if needed)
conda env remove -n secureapp
conda create -n secureapp python=3.9
conda activate secureapp

# Install dependencies
pip install -r requirements.txt
```

### Option 4: Use Makefile commands

The Makefile already uses `python -m pytest`:

```bash
# Run tests
make test

# Run tests with coverage
make test-cov
```

## Running Tests

### All Tests

```bash
python -m pytest tests/ --cov=app --cov-fail-under=95 --cov-report=html
```

### Specific Test File

```bash
python -m pytest tests/test_backup_scheduler.py -v
```

### With Coverage Report

```bash
python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=html
# Open htmlcov/index.html in browser
```

### Quick Test (without coverage)

```bash
python -m pytest tests/ -v
```

## Verification

After fixing, verify pytest works:

```bash
python -m pytest --version
# Should output: pytest 7.x.x or higher

python -m pytest tests/test_simple.py -v
# Should run successfully
```

## Dependencies Required

Make sure these are installed:

- `pytest>=7.0.0`
- `pytest-cov>=4.1.0` (for coverage reports)

Both are now in `requirements.txt`.

## Notes

- Always use `python -m pytest` instead of `pytest` directly for better reliability
- The `--cov-fail-under=95` flag ensures coverage meets the engineering standard
- Coverage reports are generated in `htmlcov/` directory
