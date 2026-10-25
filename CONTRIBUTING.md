# Contributing to Sherlock

We welcome contributions to Sherlock! Whether reporting bugs, proposing new defense heuristics, adding evaluation cases, or improving documentation, here is how you can help.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cheesecake70/sherlock.git
   cd sherlock
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

---

## Running Tests

Sherlock maintains automated test coverage across unit tests, API integration tests, and benchmark evaluations.

```bash
# Run pytest test suite
pytest -v tests

# Run empirical evaluation harness
python evals.py
```

All pull requests must pass the test suite and preserve deterministic evaluation reproducibility.

---

## Code Quality Standards

We use `ruff` for linting and code formatting:

```bash
# Check formatting and style
ruff check .
```

- Follow standard Python naming conventions (`snake_case` for functions/variables, `PascalCase` for classes).
- Maintain type hints where feasible (`from __future__ import annotations`).
- Keep the core engine (`engine.py`) dependency-free (standard library only).

---

## Pull Request Guidelines

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Write tests covering your modifications in `tests/`
3. Ensure all tests and evaluations pass
4. Commit with descriptive messages
5. Open a Pull Request with a clear summary of changes and rationale
