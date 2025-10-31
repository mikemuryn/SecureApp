# Contributing to SecureApp

Thank you for your interest in contributing to SecureApp! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Docker (optional, for containerized development)

### Development Setup

1. **Fork and Clone**

    ```bash
    git clone https://github.com/your-username/SecureApp.git
    cd SecureApp
    ```

2. **Create Virtual Environment**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4. **Install Development Dependencies**

    ```bash
    pip install pytest pytest-cov black flake8 mypy pre-commit
    ```

5. **Setup Pre-commit Hooks**
    ```bash
    pre-commit install
    ```

## Development Workflow

### Branching Strategy

- `main`: Production-ready code
- `develop`: Integration branch for features
- `feature/*`: New features
- `bugfix/*`: Bug fixes
- `hotfix/*`: Critical fixes

### Making Changes

1. **Create a Feature Branch**

    ```bash
    git checkout -b feature/your-feature-name
    ```

2. **Make Your Changes**
    - Write clean, readable code
    - Add tests for new functionality
    - Update documentation as needed

3. **Test Your Changes**

    ```bash
    # Run all tests
    pytest

    # Run with coverage
    pytest --cov=app

    # Run specific tests
    pytest tests/test_auth.py
    ```

4. **Code Quality Checks**

    ```bash
    # Format code
    black .

    # Lint code
    flake8 .

    # Type checking
    mypy app/
    ```

5. **Commit Your Changes**

    ```bash
    git add .
    git commit -m "feat: add new authentication feature"
    ```

6. **Push and Create Pull Request**
    ```bash
    git push origin feature/your-feature-name
    ```

## Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write docstrings for all functions and classes
- Keep functions small and focused
- Use meaningful variable and function names

### Security Guidelines

- Never commit sensitive data (passwords, keys, etc.)
- Validate all user inputs
- Use parameterized queries for database operations
- Follow secure coding practices
- Add security tests for new features

### Testing Requirements

- Write unit tests for all new functionality
- Aim for >90% code coverage
- Include integration tests for complex workflows
- Add security tests for authentication/encryption features
- Test error conditions and edge cases

## Pull Request Process

### Before Submitting

1. **Ensure Tests Pass**

    ```bash
    pytest
    ```

2. **Check Code Quality**

    ```bash
    black --check .
    flake8 .
    mypy app/
    ```

3. **Update Documentation**
    - Update README.md if needed
    - Add/update docstrings
    - Update CHANGELOG.md

### PR Description

Include:

- Description of changes
- Motivation for the change
- Testing performed
- Screenshots (for UI changes)
- Breaking changes (if any)

### Review Process

- All PRs require review from maintainers
- Address feedback promptly
- Keep PRs focused and reasonably sized
- Ensure CI/CD checks pass

## Issue Reporting

### Bug Reports

Include:

- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Screenshots/logs if applicable

### Feature Requests

Include:

- Clear description of the feature
- Use case and motivation
- Proposed implementation (if you have ideas)
- Any alternatives considered

## Security Issues

**Do not** report security vulnerabilities through public issues. Instead:

1. Email security issues to: security@example.com
2. Include detailed information about the vulnerability
3. Allow time for response before public disclosure

## Development Tools

### Pre-commit Hooks

Pre-commit hooks run automatically on commit:

- Code formatting (black)
- Linting (flake8)
- Type checking (mypy)
- Security scanning (bandit)

### Docker Development

```bash
# Build development image
docker build -t secureapp-dev .

# Run with volume mounting
docker run -v $(pwd):/app secureapp-dev
```

### Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m security

# Run with coverage
pytest --cov=app --cov-report=html
```

## Documentation

### Code Documentation

- Use Google-style docstrings
- Include type hints
- Document complex algorithms
- Add inline comments for non-obvious code

### API Documentation

- Document all public APIs
- Include usage examples
- Document parameters and return values
- Update when APIs change

## Release Process

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. GitHub Actions handles the rest

## Getting Help

- Check existing issues and discussions
- Join our community chat (if available)
- Contact maintainers directly
- Review documentation and examples

## Recognition

Contributors will be recognized in:

- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to SecureApp!
