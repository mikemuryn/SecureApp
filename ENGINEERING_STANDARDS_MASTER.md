# Engineering Standards Master Document

**Maintained by:** Mike Muryn

**Revision:** 3.0

**Last Updated:** October 29, 2025

---

## 📘 Table of Contents

- [Purpose & Scope](#purpose--scope)
- [Usage Across Repositories](#usage-across-repositories)
- [General Standards](#general-standards)
- [Naming & Style Rules](#naming--style-rules)
- [Documentation Standards](#documentation-standards)
- [Testing & CI/CD](#testing--cicd)
- [Security, Secrets & Dependency Hygiene](#security-secrets--dependency-hygiene)
- [Logging & Error Handling](#logging--error-handling)
- [Runtime Operations & Observability](#runtime-operations--observability)
- [Performance & Complexity](#performance--complexity)
- [Version Control & Code Review](#version-control--code-review)
- [Knowledge Transfer & Hand-off](#knowledge-transfer--hand-off)
- [Operational Enforcement Tools](#operational-enforcement-tools)
- [Appendix A – Software Craftsmanship Principles](#appendix-a--software-craftsmanship-principles)
- [Appendix B – Enforcement Checklist](#appendix-b--enforcement-checklist)

---

## 🎯 Purpose & Scope

This master document defines the unified engineering standards for all projects under my supervision.

It establishes enforceable rules for quality, reproducibility, and maintainability — guided by the principles of **Clean Code**, **The Pragmatic Programmer**, and **Code Complete**.

Every codebase, whether experimental or production, should:

- Be understandable by a strong junior engineer within one sitting.
- Pass automated linting, type-checking, and testing before merge.
- Maintain high observability, clean abstractions, and reproducibility.

---

## 🧭 Usage Across Repositories

To integrate these standards into any repository:

1. **Place this file in the project root** as `ENGINEERING_STANDARDS_MASTER.md`.
2. Add a link in your `README.md`:

    > _See [ENGINEERING_STANDARDS_MASTER.md](./ENGINEERING_STANDARDS_MASTER.md) for full coding and CI/CD standards._

3. Reference it in `CONTRIBUTING.md` under "Code Standards".
4. Optionally, enforce compliance with a simple pre-commit check:

    ```yaml
    - repo: local
      hooks:
          - id: standards-check
            name: Standards Reference Check
    ```

-           entry: bash -c 'grep -q "ENGINEERING_STANDARDS_MASTER" README.md || echo "⚠️ Missing standards reference"'
           language: system

    ```

    ```

5. Treat this file as the **single source of truth** — sync updates across repos.

---

## ⚙️ General Standards

<details><summary>Expand</summary>

- Use a professional CI/CD structure with linting, typing, and tests.
- Apply **semantic versioning** and **Conventional Commits** (`feat:`, `fix:`, `test:`, etc.).
- Organize all code under `/src` and mirror tests under `/tests`.
- Use **Conda** for environment management (pip only if conda-forge unavailable).
- Never hardcode credentials; use `.env` or secure OS keyrings.
- Profile key paths using `cProfile` or `line_profiler`.
- Functions should generally be **under 30 lines**.
- Maintain cyclomatic complexity ≤10 (flag >15 for review).
- Detect headless environments for UI operations; fallback gracefully (log, not fail).
- All alerting or outbound systems (email, SMS, Slack) must implement a common `AlertSender` interface with structured logging.

</details>

---

## ✏️ Naming & Style Rules

<details><summary>Expand</summary>

- Follow **PEP 8**, enforced via `black`, `flake8`, and `mypy`.
- All public functions include **type hints** (`mypy --strict`).
- Use **American English** exclusively.
- Naming:
    - Functions/variables: `snake_case`
    - Classes: `PascalCase`
    - Constants: `UPPER_CASE`
    - Booleans read like questions (`is_valid`, `should_alert`).
- Logger names must be module-qualified:

    ```python
    logger = logging.getLogger(__name__)
    ```

</details>

---

## 🧾 Documentation Standards

<details><summary>Expand</summary>

- Prefer **Google-style docstrings** (NumPy acceptable for analytical code).
- Validate completeness with `flake8-docstrings` or `pydocstyle`.
- Generate docs automatically using `pdoc` in CI.

**Example:**

```python
def calculate_alpha(prices: list[float]) -> float:
    """Compute alpha (excess return) of a strategy.

    Args:
        prices: Historical price data.

    Returns:
        The computed alpha as a float.

    Raises:
        ValueError: If prices are empty.
    """
```

</details>

---

## 🧪 Testing & CI/CD

<details><summary>Expand</summary>

- Use **pytest** with ≥95% coverage (`pytest-cov`).
- Include unit, integration, and regression tests.
- Isolate state using fixtures and temp dirs.
- Refactoring and new features belong in separate commits.
- All merges require passing: linting, typing, and testing in CI.

</details>

---

## 🔐 Security, Secrets & Dependency Hygiene

<details><summary>Expand</summary>

- No secrets in source control; use `.env` and `.gitignore`.
- Run `pip-audit` or `safety` weekly in CI.
- Pin dependencies in `environment.yml`.
- Secrets injected at runtime, never during import.
- Centralize credential access in `secrets_manager.py`.
- Mock secrets in tests; never use real credentials.

</details>

---

## 🪵 Logging & Error Handling

<details><summary>Expand</summary>

- Use structured logging:

    `ISO timestamp | level | module | message`

- Avoid bare `except:` clauses; catch specific exceptions.
- Log exceptions at source; propagate unless recovered.
- Consistent log levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.

</details>

---

## ⏱️ Runtime Operations & Observability

<details><summary>Expand</summary>

Every long-running process must provide:

- Health checks or a callable status method.
- Regular heartbeat logs (INFO).
- Error-rate tracking or recent-failure counts.

All alert logic must log:

- Trigger condition
- Data values causing trigger
- Timestamp
- Delivery result (success/fail + channel)

</details>

---

## 🚀 Performance & Complexity

<details><summary>Expand</summary>

- Prefer O(n log n) algorithms; avoid O(n²) when scalable.
- Profile performance bottlenecks.
- Document performance assumptions in README.
- Complexity >15 requires explicit justification in PR.

</details>

---

## 🧩 Version Control & Code Review

<details><summary>Expand</summary>

- Use feature branches (`feature/...`) and bugfix branches (`fix/...`).
- Protect `main` from direct commits; it must always be deployable.
- Tags follow **semantic versioning** (v1.3.0 etc.).
- All commits follow **Conventional Commits**.
- Require code reviews or structured self-reviews.

</details>

---

## 📄 Knowledge Transfer & Hand-off

<details><summary>Expand</summary>

Each repo must include:

- `README.md` (purpose, setup, usage)
- `CONTRIBUTING.md` (branching and review process)
- `ARCHITECTURE.md` (one-page data flow overview)
- Clear docstrings for all public classes/functions.
- A short section on “How to Extend” for any subsystem (alerts, data collector, etc.).

</details>

---

## 🧰 Operational Enforcement Tools

<details><summary>Expand</summary>

- **black** – Auto-formatting
- **flake8** – Linting
- **mypy** – Type checking
- **pytest + pytest-cov** – Testing
- **pydocstyle** – Doc validation
- **pre-commit** – Hook enforcement
- **pip-audit / safety** – Dependency security
- **radon** – Complexity measurement

</details>

---

## 📚 Appendix A – Software Craftsmanship Principles

<details><summary>Expand</summary>

**Unified Lessons from GPT-5 & Sonnet 4.5 Summaries:**

1. **Clean Code (Robert C. Martin)** – Readability and simplicity trump cleverness. Leave code cleaner than you found it.
2. **The Pragmatic Programmer (Hunt & Thomas)** – Avoid duplication, fix small issues early, keep learning.
3. **Code Complete (Steve McConnell)** – Manage complexity with design clarity and abstraction.
4. **The Clean Coder (Robert C. Martin)** – Professionalism means testing, ownership, and deliberate practice.
5. **Design Patterns (GoF)** – Favor composition over inheritance. Program to interfaces, not implementations.
6. **Introduction to Algorithms (CLRS)** – Efficiency and proper data structures determine scalability.
7. **Refactoring (Martin Fowler)** – Improve structure continuously without altering behavior.
8. **SICP (Abelson & Sussman)** – Abstraction is power. Programs are for humans first, machines second.
9. **The Art of Computer Programming (Knuth)** – Understand the why of algorithms, not just the how.
10. **Cracking the Coding Interview (McDowell)** – Communication and problem-solving clarity matter as much as correctness.

> 🧠 Meta-Lesson: Great programming is disciplined communication — between developers, systems, and future maintainers.

</details>

---

## ✅ Appendix B – Enforcement Checklist

**Before merging, confirm:**

- [x] Code passes `mypy --strict` and PEP 8 validation.
- [x] ≥95% test coverage.
- [x] Functions under 30 lines (or justified).
- [x] Logging uses ISO timestamps and explicit levels.
- [x] No hardcoded credentials or secrets.
- [x] Cyclomatic complexity ≤10.
- [x] Docstrings complete and Google-style.
- [x] Commits follow Conventional Commit format.
- [x] Dependencies pass `pip-audit`/`safety`.
- [x] Reviewer checklist signed off.

---

> _End of ENGINEERING_STANDARDS_MASTER.md — Revision 3.0, October 2025_
