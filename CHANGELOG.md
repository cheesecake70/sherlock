# Changelog

All notable changes to the Sherlock project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - Initial Open-Source Release

### Added
- **Core Gate Engine (`engine.py`)**:
  - Pure Python stdlib implementation with zero third-party dependencies.
  - Multi-tier scoring: Contract validation (40%), Attributive provenance heuristic (40%), and Tripwire canary detection (20%).
  - Hard rules: Taint hard-block, canary leakage hard-block, and session lockout on BLOCK.
  - Policy enforcement: Automatic human approval step-up on sensitive sinks or large amounts.
  - Root-cause attribution diagnostics identifying steering documents.
  - Cryptographic append-only SHA-256 hash-chained audit ledger with tamper verification.
- **REST API Server (`app.py`)**:
  - FastAPI-powered gateway with endpoints for contract editing, scenario execution, interactive red-team attack lab, drop-in agent gating (`/api/gate`), and ledger export.
- **Mission Control Dashboard (`index.html`)**:
  - Single-file zero-dependency responsive UI with 7 views: Live Firewall, Cold-Start Race, Attack Lab, Audit Ledger, Policy Editor, Empirical Evidence, and Live Agent.
- **Empirical Evaluation Harness (`evals.py` & `eval_cases.py`)**:
  - 51 hand-labelled test cases (30 attacks, 21 benign) measuring block rates, false alarms, and ablation impact.
- **Python Agent SDK (`sdk/`)**:
  - `@dg.guard` decorator and client library for guarding existing Python agents.
- **Testing Suite (`tests/`)**:
  - Unit tests for engine, API integration tests with TestClient, and SDK client tests (29 passing tests).
- **Comprehensive Documentation**:
  - `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/POLICY_GUIDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, and MIT License.
