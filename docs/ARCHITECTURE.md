# Sherlock Architecture Deep Dive

Sherlock is a runtime zero-trust behavioral firewall designed to protect autonomous AI agents from indirect prompt injection, data exfiltration, and unauthorized actions.

Unlike learning-based anomaly detectors that require hundreds of interaction traces before achieving effective detection (the "cold-start gap"), Sherlock enforces policy from the agent's **first tool call** through deterministic role contracts, taint tracking, and provenance heuristics.

---

## High-Level Architecture

```
User Prompt ──┐
              ▼
┌───────────────────────────┐   1. Tool Call Intent   ┌────────────────────────────────┐
│         AI Agent          │ ──────────────────────▶ │        Sherlock Engine         │
│  (Claude, LangChain, etc) │                         │  - Contract Validation         │
│                           │ ◀────────────────────── │  - Provenance Attribution      │
└─────────────┬─────────────┘   2. ALLOW / STEP-UP /  │  - Tripwire Canary Matching    │
              │                    BLOCK Verdict      └───────────────┬────────────────┘
              │ Only if ALLOW                                         │
              ▼                                                       ▼ 3. Hash Chain
┌───────────────────────────┐                         ┌────────────────────────────────┐
│      Protected Tools      │                         │     SHA-256 Audit Ledger       │
│  (DB, Shell, Files, APIs) │                         │  (Tamper-Evident Append-Only)  │
└───────────────────────────┘                         └────────────────────────────────┘
```

---

## Core Components

### 1. Session State Machine (`engine.Session`)

Each agent workflow executes within an isolated `Session` context that tracks:
- **`prompt`**: The original trusted user objective.
- **`contract`**: The active role specification governing permissions.
- **`flags`**: Feature toggles enabling ablation analysis (contract, taint, attribution, tripwire, policy).
- **`canary`**: A unique cryptographically generated tripwire token (e.g., `CNRY-A8F2`).
- **`tainted`**: Boolean flag indicating whether the session has ingested untrusted external content.
- **`locked`**: Boolean flag set upon any `BLOCK` verdict, terminating subsequent execution permanently.
- **`untrusted_text`**: Aggregated text ingested from external sources.
- **`docs`**: Provenance registry mapping ingested document identifiers to raw text.
- **`calls`**: Sequential trace graph of executed tool calls and scores.

---

## 3-Tier Defense Mechanism

### Tier 1: Role Contract Validation (Score: 0 or 100)

Every agent operates under a formal contract specifying:
- **Allowed Tools (`allowed_tools`)**: Explicit whitelist of permissible tool names. Unlisted tools yield an immediate violation.
- **Forbidden Paths (`forbidden_paths`)**: Sensitive filesystem directories (e.g., `/hr`, `/payroll`, `/secrets`, `credentials`, `env`).
- **Allowed Egress (`allowed_egress`)**: Whitelist of permitted hostnames/domains for network communications.

Contract violations evaluate to a score of `100` (or `0` if clean).

### Tier 2: Attribution Provenance Heuristic (Score: 0 to 100)

When an agent reads third-party data (e.g., an RFQ, an email, or a web scraping result), that content may contain adversarial injection payloads instructing the agent to deviate from its mission.

Attribution measures the lexical overlap between the tool call parameters, the untrusted ingested documents, and the original user prompt:

$$\text{Attribution} = \frac{|T_{\text{call}} \cap T_{\text{untrusted}} \setminus T_{\text{prompt}}|}{|T_{\text{call}} \cap T_{\text{untrusted}} \setminus T_{\text{prompt}}| + |T_{\text{call}} \cap T_{\text{prompt}}|}$$

Where:
- $T_{\text{call}}$: Normalized tokens present in tool arguments.
- $T_{\text{untrusted}}$: Normalized tokens present across all ingested untrusted documents.
- $T_{\text{prompt}}$: Normalized tokens present in the user's initial objective.

**Attribution Damping:**
Because word overlap is a heuristic, Sherlock dampens attribution to half-weight on in-contract, non-sink calls, preventing benign paraphrasing from causing unnecessary false positives while maintaining full sensitivity on money-moving and out-of-contract operations.

### Tier 3: Tripwire Canary Tokens (Score: 0 or 100)

When an untrusted tool returns content (e.g., fetching a vendor quote), Sherlock injects a covert, per-session canary marker (e.g., `[ref:CNRY-7B2A]`) into the content at ingest.

If an adversarial instruction convinces the model to copy or exfiltrate document context, the canary leaks into downstream arguments. Any match between the active session canary and outbound arguments triggers an immediate **Tripwire Hard Block**.

---

## Scoring Model & Decision Logic

Sherlock combines check results using calibrated weights:

$$\text{Composite Score} = w_{\text{contract}} \cdot S_{\text{contract}} + w_{\text{attribution}} \cdot S_{\text{attrib}} + w_{\text{tripwire}} \cdot S_{\text{tripwire}}$$

Default weights:
- **Contract Weight:** `0.40`
- **Attribution Weight:** `0.40`
- **Tripwire Weight:** `0.20`

### Hard Rules (Overrides)
Regardless of the composite score, hard rules guarantee containment:
1. **Taint Hard-Block:** Any contract violation committed *after* ingesting untrusted data produces an immediate `BLOCK`.
2. **Canary Leak:** Any detection of the session canary produces an immediate `BLOCK`.
3. **Session Lockout:** Once a session receives a `BLOCK`, the session locks. All subsequent tool calls are blocked unconditionally.
4. **Sink Step-Up:** Tool calls moving funds above the threshold (e.g., `$5,000`) or shaped by untrusted content (`attribution >= 0.60`) require mandatory human approval (`STEP-UP`).

### Verdict Bands
- **`ALLOW`** (Score `0 - 29`): Call executes immediately.
- **`STEP-UP`** (Score `30 - 69` or Policy flag): Call is held pending human approval.
- **`BLOCK`** (Score `70 - 100` or Hard Rule): Call is aborted and session locked.

---

## Root-Cause Attribution

When a tool call is blocked, Sherlock interrogates its document provenance ledger to identify the specific document that steered the model:

```python
best = max(self.docs, key=lambda d: len(a & toks(d[1])))
culprit = {"file": best[0], "words": sorted(a & toks(best[1]))[:8]}
```

This returns human-interpretable diagnostics in the verdict payload:
```json
{
  "culprit": {
    "file": "poisoned_quote.txt",
    "words": ["access", "ignore", "salaries", "upload"]
  }
}
```

---

## Tamper-Evident SHA-256 Ledger

Every decision (ALLOW, STEP-UP, BLOCK, APPROVE, DENY) is appended to a cryptographic hash chain:

```
Entry 0 (Genesis: 000...000) ──▶ Entry 1 (Hash: a7f8...) ──▶ Entry 2 (Hash: e3b1...)
```

Each block computes:
$$\text{Hash}_i = \text{SHA256}(\text{CanonicalJSON}(\text{Index}_i, \text{Timestamp}_i, \text{Session}_i, \text{Tool}_i, \text{Verdict}_i, \text{Score}_i, \text{Hash}_{i-1}))$$

Verification runs in linear time $O(N)$ and pinpoints the exact entry where tampering occurred.
