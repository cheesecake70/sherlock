# Sherlock – build spec (shared by all builders)

Sherlock = runtime "zero-trust behavioural firewall" between an AI agent and its tools. Before each tool call
runs it returns ALLOW / STEP-UP (human approves) / BLOCK. Every decision goes into a SHA-256 hash-chained ledger.
Core claim: protection from the agent's FIRST call — no learning period — because the agent's job is a written
role contract. Hackathon prototype (D3COY Hackathon). Honesty rule: never claim more than the code does.
Attribution is a word-overlap heuristic (NOT CausalArmor/AttriGuard). Scripted scenarios are labelled scripted.

Run: `pip install -r requirements.txt` then `python -m uvicorn app:app --reload`, open http://127.0.0.1:8000.
Windows users run `py -m ...`. Python 3.10+ (user has 3.14). No Node, no build step.

## Files and owners (do NOT edit files you don't own; tell the coordinator if you need a change)
- engine.py, scenarios.py, app.py, SPEC.md — coordinator (Opus)
- evals.py, eval_cases.py, tests/test_engine.py — Eval builder
- index.html — UI builder (single file, vanilla JS, no build)
- live_agent.py, sdk/sherlock_client.py, examples/ — Live-agent builder
- README.md, DEMO.md, run.bat, run.sh — Docs builder

## Engine (engine.py) — read it, it is short
`Session(prompt, contract=None, flags=None, canary=None)`; `s.plant(text)` inserts marker; `s.check(tool, args, out=None, source_name=None)` → result dict:
```
{tool, args, verdict: "ALLOW"|"STEP-UP"|"BLOCK", score: 0-100,
 parts: {contract: 0|100, attribution: 0-100, tripwire: 0|100},
 why: [str...], culprit: {file, words[]} | null, tainted_before: bool, tainted_after: bool,
 locked: bool, out: str|null, canary: "CNRY-XXXX"}
```
Flags (ablations): `engine.PRESETS` = contract_only, contract_taint, plus_attrib, full.
Rules: hard BLOCK = contract violation while tainted, or tripwire hit. STEP-UP = sink over $5,000, or sink call
shaped by untrusted content (attribution ≥60 while tainted), or score ≥30. BLOCK locks the session.

## HTTP API (app.py)
- GET  /api/contract → contract JSON. PUT /api/contract (full JSON; weights must sum to 1; 422 on error). POST /api/contract/reset
- GET  /api/scenarios → [{id,title,blurb,kind:"benign"|"attack",prompt}] ids: clean, shift, poison, exfil, reword, fraud, bigpo
- POST /api/start {id, flags?} → {session, prompt, canary, kind}
- POST /api/step → {done:true} or {done:false, call:<result>, pending:bool, graph:[{tool,verdict,score,source,untrusted}]}; 409 while approval pending
- POST /api/resolve {decision:"APPROVED"|"DENIED"} → {ok}
- POST /api/lab {prompt, file_text, tool, args, flags?} → {calls:[fetch_result, your_call_result], canary}.
  In args the literal `{CANARY}` is replaced by the marker (lets a judge simulate "agent copied the marker").
- POST /api/gate {session_id?, prompt?, tool, args, out?} → {session_id, ...result, planted_out} (drop-in for any agent)
- POST /api/verify → {broken:-1|index, count, ledger:[{i,tool,verdict,session,mode,score,hash,prev}]}
- POST /api/tamper, POST /api/clear, GET /api/ledger/export (download JSON)
- GET  /api/eval → produced by evals.run_eval(contract) (shape below)
- GET  /api/live/status → {available:bool, model?, reason?}
- POST /api/live/start {file:"clean"|"poisoned"|"exfil", prompt?} → {run_id}
- GET  /api/live/{run_id} → {status:"running"|"done"|"error", events:[{type:"call", call:<result>} | {type:"text", text} | {type:"error", text}], final_text}

## /api/eval shape (evals.run_eval)
```
{"n_cases": int, "n_attack": int, "n_benign": int,
 "configs": [{"id":"contract_only","label":"Contract only", "attack_block_rate":0-1, "attack_stopped_rate":0-1 (BLOCK or STEP-UP),
              "false_positive_rate":0-1 (benign cases with any BLOCK), "friction_rate":0-1 (benign with any STEP-UP or BLOCK)}...],
 "baseline_cold_start": {"label":"Learning-based detector, first 200 traces", "attack_block_rate":0, "note": str},
 "cases": [{"id","kind","category","title","verdicts":{config_id: final_verdict}}],
 "categories": {category: {"n":int, "full_stopped":int}}}
```
Final verdict of a case = the most severe verdict across its calls (BLOCK > STEP-UP > ALLOW).
