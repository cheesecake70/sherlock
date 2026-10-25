"""Sherlock gate engine. Pure Python, no web framework, no third-party deps.

Everything a tool call is checked against lives here so the API server, the
evaluation harness and the live-agent mode all use exactly the same code.

Usage:
    s = Session(prompt="Read clean_quote.txt ...")       # one agent run
    r = s.check("fetch_rfq", {"file": "q.txt"}, out="...")  # before the call runs
    r["verdict"]  -> "ALLOW" | "STEP-UP" | "BLOCK"
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import time

DEFAULT_CONTRACT = {
    "role": "procurement_agent",
    "allowed_tools": ["fetch_rfq", "read_file", "calculate_quote", "submit_po"],
    "untrusted_tools": ["fetch_rfq"],      # output is outside content -> taints the session
    "sink_tools": ["submit_po"],           # tools that move money or data out
    "forbidden_paths": ["hr", "payroll", "secrets", "credentials", "ssh", "env"],
    "allowed_egress": ["api.internal-procure.corp"],
    "approval_over": 5000,
    "weights": {"contract": 0.4, "attribution": 0.4, "tripwire": 0.2},
    "bands": {"step_up_from": 30, "block_from": 70},
}

# Ablation flags. The evaluation harness switches these off one at a time.
ALL_ON = {"contract": True, "taint_hardblock": True, "attribution": True, "tripwire": True, "policy": True}
PRESETS = {
    "contract_only":  {"contract": True,  "taint_hardblock": False, "attribution": False, "tripwire": False, "policy": True},
    "contract_taint": {"contract": True,  "taint_hardblock": True,  "attribution": False, "tripwire": False, "policy": True},
    "plus_attrib":    {"contract": True,  "taint_hardblock": True,  "attribution": True,  "tripwire": False, "policy": True},
    "full":           dict(ALL_ON),
}

STOP = set("the a an to of and for in on is are was with from as at by it this that be or "
           "please your you our we can will all any".split())
URL_KEYS = ("url", "endpoint", "webhook", "to", "dest", "destination", "host")
PATH_KEYS = ("path", "file", "filename")


def toks(s) -> set:
    return {w for w in re.split(r"[^a-z0-9]+", str(s).lower()) if len(w) > 2 and w not in STOP}


def _flat(args) -> str:
    return " ".join(str(v) for v in (args or {}).values())


def _host(v: str) -> str:
    v = str(v).strip().lower()
    if "@" in v and "://" not in v:            # email address -> domain
        return v.split("@")[-1]
    return re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]


class Session:
    """One agent run. Holds taint, planted canary, documents read and the lock."""

    def __init__(self, prompt: str, contract: dict | None = None, flags: dict | None = None,
                 canary: str | None = None):
        self.prompt = prompt
        self.contract = copy.deepcopy(contract or DEFAULT_CONTRACT)
        self.flags = {**ALL_ON, **(flags or {})}
        self.canary = canary or "CNRY-" + secrets.token_hex(2).upper()
        self.tainted = False
        self.planted = False
        self.locked = False
        self.untrusted_text = ""
        self.docs: list[tuple[str, str]] = []   # (name, text) of untrusted docs
        self.calls: list[dict] = []             # history for the taint graph

    # -- planting -----------------------------------------------------------
    def plant(self, text: str) -> str:
        """Server-side: insert the tripwire marker into untrusted content at ingest."""
        if "{CANARY}" in text:
            return text.replace("{CANARY}", self.canary)
        return text + f" [ref:{self.canary}]"

    # -- the checkpoint -----------------------------------------------------
    def check(self, tool: str, args: dict, out: str | None = None, source_name: str | None = None) -> dict:
        """Score one call BEFORE it runs. If the call is allowed and comes from an
        untrusted tool, its output (`out`) is ingested and taints the session."""
        c, f = self.contract, self.flags
        args = args or {}
        why: list[str] = []
        flat = _flat(args)

        if self.locked:
            return self._result(tool, args, "BLOCK", 100, {"contract": 0, "attribution": 0, "tripwire": 0},
                                ["Session is locked after an earlier block"], None, self.tainted, out)

        # 1. Contract (0 or 100)
        viol: list[str] = []
        if f["contract"]:
            if tool not in c["allowed_tools"]:
                viol.append(f"'{tool}' is not an allowed tool for role {c['role']}")
            for k in PATH_KEYS:
                if k in args:
                    parts = set(re.split(r"[^a-z0-9_]+", str(args[k]).lower()))
                    for fp in c["forbidden_paths"]:
                        if fp in parts:
                            viol.append(f"{k} touches the restricted area '{fp}'")
            for k in URL_KEYS:
                if k in args and args[k]:
                    h = _host(args[k])
                    if h and h not in c["allowed_egress"]:
                        viol.append(f"'{h}' is not an approved destination")
        contract = 100 if viol else 0
        why += ["Contract: " + v for v in viol]

        # 2. Attribution (0-100): share of the call's words that come from untrusted text vs the user
        attr = 0.0
        a = toks(flat)
        if f["attribution"]:
            u, p = toks(self.untrusted_text), toks(self.prompt)
            uo, po = len((a & u) - p), len(a & p)
            attr = uo / (uo + po) if uo + po else 0.0
            if attr >= 0.6:
                why.append(f"Attribution: {round(attr * 100)}% of this call's words trace to untrusted content, not the user's request")

        # 3. Tripwire (0 or 100)
        leak = False
        if f["tripwire"]:
            leak = self.planted and self.canary.lower() in flat.lower()
            if leak:
                why.append(f"Tripwire: hidden marker {self.canary} planted in an untrusted file was copied into this call")
        trip = 100 if leak else 0

        w = c["weights"]
        # Attribution is a noisy heuristic: it escalates risky calls (sinks, contract breaks) at full weight,
        # but on an otherwise in-contract, non-sink call it only counts at half weight (cannot reach step-up alone).
        attr_eff = attr if (viol or tool in c["sink_tools"]) else attr * 0.5
        score = round(w["contract"] * contract + w["attribution"] * attr_eff * 100 + w["tripwire"] * trip)

        hard = False
        if viol and self.tainted and f["taint_hardblock"]:
            hard = True
            why.append("Hard block: out-of-contract action after reading untrusted content")
        if leak:
            hard = True
        policy = False
        if f["policy"] and tool in c["sink_tools"]:
            try:
                amt = float(args.get("amount", 0) or 0)
            except (TypeError, ValueError):
                amt = 0
            if amt > c["approval_over"]:
                policy = True
                why.append(f"Policy: {tool} over ${c['approval_over']:,} needs human approval")
            if self.tainted and not policy and attr >= 0.6:
                policy = True
                why.append("Policy: money-moving call shaped by untrusted content needs human approval")

        b = c["bands"]
        if hard or score >= b["block_from"]:
            v = "BLOCK"
        elif policy or score >= b["step_up_from"] or (viol and not f["taint_hardblock"]):
            v = "STEP-UP"
        else:
            v = "ALLOW"

        culprit = None
        if v == "BLOCK" and self.docs:
            best = max(self.docs, key=lambda d: len(a & toks(d[1])))
            shared = sorted(a & toks(best[1]))
            if shared or leak:
                culprit = {"file": best[0], "words": shared[:8]}
                why.append(f"Root cause: {best[0]} is the document that steered this call")

        tainted_before = self.tainted
        if v != "BLOCK" and tool in c["untrusted_tools"] and out is not None:
            self.tainted = self.planted = True
            name = source_name or str(args.get("file") or args.get("url") or tool)
            self.untrusted_text += " " + out
            self.docs.append((name, out))
        if v == "BLOCK":
            self.locked = True
        return self._result(tool, args, v, score, {"contract": contract, "attribution": round(attr * 100), "tripwire": trip},
                            why, culprit, tainted_before, out)

    def _result(self, tool, args, v, score, parts, why, culprit, tainted_before, out):
        r = {"tool": tool, "args": args, "verdict": v, "score": score, "parts": parts, "why": why,
             "culprit": culprit, "tainted_before": tainted_before, "tainted_after": self.tainted,
             "locked": self.locked, "out": out, "canary": self.canary}
        self.calls.append({"tool": tool, "verdict": v, "score": score,
                           "source": culprit["file"] if culprit else None,
                           "untrusted": tool in self.contract["untrusted_tools"]})
        return r


# ---------------------------------------------------------------- ledger
GENESIS = "0" * 64


def canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class Ledger:
    """Append-only, hash-chained log. Optionally persisted as JSON lines."""

    def __init__(self, path=None):
        self.path = path
        self.entries: list[dict] = []
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    self.entries = [json.loads(l) for l in fh if l.strip()]
            except FileNotFoundError:
                pass

    def append(self, tool, args, tainted, score, verdict, session_id="", mode="scripted"):
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"i": len(self.entries) + 1, "ts": round(time.time(), 3), "session": session_id, "mode": mode,
                "tool": tool, "args": args, "tainted": tainted, "score": score, "verdict": verdict, "prev": prev}
        e = {"body": body, "hash": sha(canon(body))}
        self.entries.append(e)
        self._save()
        return e

    def verify(self) -> int:
        """-1 if intact, else the 0-based index of the first broken entry."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e["body"]["prev"] != prev or sha(canon(e["body"])) != e["hash"]:
                return i
            prev = e["hash"]
        return -1

    def tamper(self):
        if not self.entries:
            return None
        i = next((n for n, e in enumerate(self.entries) if e["body"]["verdict"] == "BLOCK"), len(self.entries) - 1)
        self.entries[i]["body"]["verdict"] = "ALLOW"     # edited without re-hashing
        self._save()
        return i

    def clear(self):
        self.entries.clear()
        self._save()

    def _save(self):
        if self.path:
            with open(self.path, "w", encoding="utf-8") as fh:
                for e in self.entries:
                    fh.write(canon(e) + "\n")
