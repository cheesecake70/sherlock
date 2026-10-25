"""Sherlock prototype server. Run: python -m uvicorn app:app --reload  then open http://127.0.0.1:8000"""
from __future__ import annotations

import copy
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import engine
from engine import Ledger, Session
from scenarios import BY_ID, SCENARIOS

HERE = Path(__file__).parent
app = FastAPI(title="Sherlock")
LEDGER = Ledger(HERE / "ledger.jsonl")
STATE = {"contract": copy.deepcopy(engine.DEFAULT_CONTRACT)}
RUN = {"session": None, "sid": "", "steps": [], "i": 0, "pending": None}
GATE_SESSIONS: dict[str, Session] = {}


def _sub(v, canary):
    return v.replace("{CANARY}", canary) if isinstance(v, str) else v


# ---------------------------------------------------------------- page
@app.get("/")
def index():
    return FileResponse(HERE / "index.html")


# ---------------------------------------------------------------- contract / policy editor
@app.get("/api/contract")
def get_contract():
    return STATE["contract"]


@app.put("/api/contract")
def put_contract(c: dict):
    need = ["role", "allowed_tools", "untrusted_tools", "sink_tools", "forbidden_paths", "allowed_egress",
            "approval_over", "weights", "bands"]
    miss = [k for k in need if k not in c]
    if miss:
        raise HTTPException(422, f"missing keys: {', '.join(miss)}")
    try:
        w = c["weights"]
        if abs(float(w["contract"]) + float(w["attribution"]) + float(w["tripwire"]) - 1) > 1e-6:
            raise HTTPException(422, "weights must add up to 1")
        float(c["approval_over"]); int(c["bands"]["step_up_from"]); int(c["bands"]["block_from"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(422, "weights/bands/approval_over malformed")
    STATE["contract"] = c
    return {"ok": True}


@app.post("/api/contract/reset")
def reset_contract():
    STATE["contract"] = copy.deepcopy(engine.DEFAULT_CONTRACT)
    return STATE["contract"]


# ---------------------------------------------------------------- scripted scenarios
@app.get("/api/scenarios")
def scenarios():
    return [{k: s[k] for k in ("id", "title", "blurb", "kind", "prompt")} for s in SCENARIOS]


class StartIn(BaseModel):
    id: str
    flags: dict | None = None


@app.post("/api/start")
def start(b: StartIn):
    sc = BY_ID.get(b.id)
    if not sc:
        raise HTTPException(404, "unknown scenario")
    s = Session(sc["prompt"], STATE["contract"], b.flags)
    RUN.update(session=s, sid="S-" + secrets.token_hex(3), steps=sc["steps"], i=0, pending=None)
    return {"session": RUN["sid"], "prompt": sc["prompt"], "canary": s.canary, "kind": sc["kind"]}


@app.post("/api/step")
def step():
    s: Session = RUN["session"]
    if RUN["pending"]:
        raise HTTPException(409, "resolve the pending approval first")
    if s is None or s.locked or RUN["i"] >= len(RUN["steps"]):
        return {"done": True}
    raw = RUN["steps"][RUN["i"]]
    RUN["i"] += 1
    args = {k: _sub(v, s.canary) for k, v in raw["args"].items()}
    out = raw["out"]
    if raw["tool"] in s.contract["untrusted_tools"]:
        out = s.plant(out)
    r = s.check(raw["tool"], args, out)
    if r["verdict"] == "STEP-UP":
        RUN["pending"] = r
    else:
        LEDGER.append(r["tool"], r["args"], r["tainted_before"], r["score"], r["verdict"], RUN["sid"])
    return {"done": False, "call": r, "pending": r["verdict"] == "STEP-UP", "graph": s.calls}


class ResolveIn(BaseModel):
    decision: str  # APPROVED | DENIED


@app.post("/api/resolve")
def resolve(b: ResolveIn):
    if not RUN["pending"]:
        raise HTTPException(409, "nothing pending")
    if b.decision not in ("APPROVED", "DENIED"):
        raise HTTPException(422, "decision must be APPROVED or DENIED")
    r = RUN["pending"]
    RUN["pending"] = None
    LEDGER.append(r["tool"], r["args"], r["tainted_before"], r["score"], b.decision, RUN["sid"])
    if b.decision == "DENIED":
        RUN["i"] = len(RUN["steps"])
    return {"ok": True}


# ---------------------------------------------------------------- attack lab
class LabIn(BaseModel):
    prompt: str
    file_text: str
    tool: str
    args: dict
    flags: dict | None = None


@app.post("/api/lab")
def lab(b: LabIn):
    """Judge-driven red team: your text becomes the vendor file, then your chosen next call is checked."""
    s = Session(b.prompt, STATE["contract"], b.flags)
    sid = "LAB-" + secrets.token_hex(2)
    out = s.plant(b.file_text[:4000])
    r1 = s.check("fetch_rfq", {"file": "your_file.txt"}, out)
    args = {k: _sub(v, s.canary) for k, v in b.args.items()}
    r2 = s.check(b.tool, args, None)
    for r in (r1, r2):
        LEDGER.append(r["tool"], r["args"], r["tainted_before"], r["score"], r["verdict"], sid, "lab")
    return {"calls": [r1, r2], "canary": s.canary}


# ---------------------------------------------------------------- drop-in gateway for any agent
class GateIn(BaseModel):
    session_id: str | None = None
    prompt: str | None = None
    tool: str
    args: dict = {}
    out: str | None = None   # for untrusted tools: the content the tool returned (ingested if allowed)


@app.post("/api/gate")
def gate(b: GateIn):
    """Generic pre-call check. First call with a new session_id must include the user's prompt."""
    sid = b.session_id or "G-" + secrets.token_hex(3)
    s = GATE_SESSIONS.get(sid)
    if s is None:
        s = GATE_SESSIONS[sid] = Session(b.prompt or "", STATE["contract"])
    out = s.plant(b.out) if (b.out is not None and b.tool in s.contract["untrusted_tools"]) else b.out
    r = s.check(b.tool, b.args, out)
    LEDGER.append(r["tool"], r["args"], r["tainted_before"], r["score"], r["verdict"], sid, "gate")
    return {"session_id": sid, **r, "planted_out": out}


# ---------------------------------------------------------------- ledger
@app.post("/api/verify")
def verify():
    br = LEDGER.verify()
    return {"broken": br, "count": len(LEDGER.entries),
            "ledger": [{"i": e["body"]["i"], "tool": e["body"]["tool"], "verdict": e["body"]["verdict"],
                        "session": e["body"].get("session", ""), "mode": e["body"].get("mode", ""),
                        "score": e["body"]["score"], "hash": e["hash"], "prev": e["body"]["prev"]}
                       for e in LEDGER.entries]}


@app.post("/api/tamper")
def tamper():
    return {"ok": True, "index": LEDGER.tamper()}


@app.post("/api/clear")
def clear():
    LEDGER.clear()
    return {"ok": True}


@app.get("/api/ledger/export")
def export():
    return JSONResponse({"verify": LEDGER.verify(), "entries": LEDGER.entries},
                        headers={"Content-Disposition": "attachment; filename=sherlock_audit.json"})


# ---------------------------------------------------------------- evaluation + live agent (optional modules)
@app.get("/api/eval")
def eval_results():
    import evals
    return evals.run_eval(STATE["contract"])


try:
    import live_agent
    app.include_router(live_agent.router)
except ImportError:  # module not present -> live mode simply reports unavailable
    @app.get("/api/live/status")
    def live_status():
        return {"available": False, "reason": "live_agent module missing"}
