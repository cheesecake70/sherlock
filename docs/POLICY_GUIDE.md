# Sherlock Policy & Role Contract Guide

Sherlock secures AI agents through written **Role Contracts**. A contract establishes the boundaries of what an agent is permitted to do before it interacts with any tool or external data source.

---

## Contract Schema

Every contract is a JSON structure with 8 mandatory fields:

```json
{
  "role": "procurement_agent",
  "allowed_tools": ["fetch_rfq", "read_file", "calculate_quote", "submit_po"],
  "untrusted_tools": ["fetch_rfq"],
  "sink_tools": ["submit_po"],
  "forbidden_paths": ["hr", "payroll", "secrets", "credentials", "ssh", "env"],
  "allowed_egress": ["api.internal-procure.corp"],
  "approval_over": 5000,
  "weights": {
    "contract": 0.4,
    "attribution": 0.4,
    "tripwire": 0.2
  },
  "bands": {
    "step_up_from": 30,
    "block_from": 70
  }
}
```

---

## Field Reference

### 1. `role` (string)
A descriptive identifier for the agent's role (e.g., `procurement_agent`, `customer_support_bot`, `code_assistant`).

### 2. `allowed_tools` (list of strings)
A strict whitelist of tool names this role is permitted to invoke.
- Any attempt to invoke a tool outside this list results in a contract violation score of `100`.
- If the session is already tainted, this triggers an immediate `BLOCK`.

### 3. `untrusted_tools` (list of strings)
Tools that ingest external or untrusted data into the agent's context (e.g., email readers, web scrapers, vendor quote downloaders).
- Invoking an untrusted tool marks the session as `tainted = true`.
- Content returned by untrusted tools is automatically tagged with a hidden tripwire canary marker.

### 4. `sink_tools` (list of strings)
Tools that perform sensitive, irreversible actions such as transferring funds, sending external emails, or modifying production databases.
- Sink operations are subject to monetary thresholds (`approval_over`) and higher scrutiny.
- Attribution scores are evaluated at full weight against sink tools.

### 5. `forbidden_paths` (list of strings)
Keywords or directory fragments representing sensitive files.
- If any path parameter (`path`, `file`, `filename`) contains a forbidden keyword token, it constitutes a contract breach.

### 6. `allowed_egress` (list of strings)
Whitelisted domain names or hostnames for network communication.
- Any tool taking destination parameters (`url`, `endpoint`, `webhook`, `to`, `dest`, `host`) must target an allowed egress host.

### 7. `approval_over` (number)
Threshold (e.g. currency value) above which sink tool calls automatically escalate to `STEP-UP` requiring human authorization.

### 8. `weights` and `bands`
- **`weights`**: Relative contribution of Contract, Attribution, and Tripwire checks (must sum to `1.0`).
- **`bands`**:
  - `step_up_from`: Minimum composite score requiring human approval (default `30`).
  - `block_from`: Minimum composite score triggering automated containment (default `70`).

---

## Best Practices for Custom Agents

1. **Principle of Least Privilege**: Only include tools that the agent needs for its specific primary objective.
2. **Tag Ingestion Tools**: Identify every tool that pulls data from the public internet or external senders and mark it in `untrusted_tools`.
3. **Protect Sinks**: Every tool that triggers side-effects (payment, email, deletion) must be in `sink_tools`.
4. **Calibrate Approval Thresholds**: Align `approval_over` with corporate spending limits or data sensitivity levels.
