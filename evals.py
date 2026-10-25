"""Sherlock evaluation harness. Pure stdlib, deterministic, runs well under 1 s.

Runs every labelled case in eval_cases.py under each ablation preset and reports
attack-stop and false-alarm rates. Scripted agent; checks are the real engine.
"""
from __future__ import annotations

import copy

import engine
from eval_cases import CASES

CANARY = "CNRY-TEST"
CONFIGS = [("contract_only", "Contract only"), ("contract_taint", "+ Taint hard-block"),
           ("plus_attrib", "+ Attribution"), ("full", "Full Sherlock (+ Tripwire)")]
RANK = {"ALLOW": 0, "STEP-UP": 1, "BLOCK": 2}


def _sub(v, canary):
    if isinstance(v, str):
        return v.replace("{CANARY}", canary)
    if isinstance(v, dict):
        return {k: _sub(x, canary) for k, x in v.items()}
    return v


def run_case(case, flags, contract=None):
    """Returns (final_verdict, [per-call verdicts])."""
    s = engine.Session(case["prompt"], contract=contract, flags=flags, canary=CANARY)
    final, seen = "ALLOW", []
    for st in case["steps"]:
        args = _sub(st["args"], CANARY)
        out = st.get("out")
        if st["tool"] in s.contract["untrusted_tools"] and out is not None:
            out = s.plant(out)
        r = s.check(st["tool"], args, out=out)
        seen.append(r["verdict"])
        if RANK[r["verdict"]] > RANK[final]:
            final = r["verdict"]
        if r["verdict"] == "BLOCK":
            break
        if r["verdict"] == "STEP-UP" and case["kind"] == "attack":
            break   # human would see it: counted as stopped
    return final, seen


def run_eval(contract=None) -> dict:
    contract = copy.deepcopy(contract) if contract else None
    atk = [c for c in CASES if c["kind"] == "attack"]
    ben = [c for c in CASES if c["kind"] == "benign"]
    verd = {c["id"]: {} for c in CASES}
    configs = []
    for cid, label in CONFIGS:
        flags = engine.PRESETS[cid]
        for c in CASES:
            verd[c["id"]][cid] = run_case(c, flags, contract)[0]
        av = [verd[c["id"]][cid] for c in atk]
        bv = [verd[c["id"]][cid] for c in ben]
        na, nb = max(len(av), 1), max(len(bv), 1)
        configs.append({"id": cid, "label": label,
                        "attack_block_rate": round(av.count("BLOCK") / na, 4),
                        "attack_stopped_rate": round(sum(v != "ALLOW" for v in av) / na, 4),
                        "false_positive_rate": round(bv.count("BLOCK") / nb, 4),
                        "friction_rate": round(sum(v != "ALLOW" for v in bv) / nb, 4)})
    cats = {}
    for c in CASES:
        d = cats.setdefault(c["category"], {"n": 0, "full_stopped": 0, "kind": c["kind"]})
        d["n"] += 1
        if verd[c["id"]]["full"] != "ALLOW":
            d["full_stopped"] += 1
    return {"n_cases": len(CASES), "n_attack": len(atk), "n_benign": len(ben), "configs": configs,
            "baseline_cold_start": {"label": "Learning-based detector, first 200 traces", "attack_block_rate": 0,
                                    "note": "Illustrative model, not a measured competitor: assumes an anomaly detector that needs ~200 "
                                            "traces before issuing verdicts, so on a fresh agent it allows everything."},
            "cases": [{"id": c["id"], "kind": c["kind"], "category": c["category"], "title": c["title"],
                       "verdicts": verd[c["id"]]} for c in CASES],
            "categories": cats,
            "note": "Scripted agent on 'n_cases' hand-labelled cases; small slice, not a benchmark."}


if __name__ == "__main__":
    r = run_eval()
    print(f"{r['n_cases']} cases ({r['n_attack']} attack, {r['n_benign']} benign)\n")
    print(f"{'Config':32}{'block':>8}{'stopped':>9}{'FP':>7}{'friction':>10}")
    for c in r["configs"]:
        print(f"{c['label']:32}{c['attack_block_rate']:8.0%}{c['attack_stopped_rate']:9.0%}"
              f"{c['false_positive_rate']:7.0%}{c['friction_rate']:10.0%}")
    print(f"{'Cold-start learner (illustrative)':32}{0:8.0%}{0:9.0%}\n")
    print("Per category (full): stopped/n")
    for k, d in r["categories"].items():
        print(f"  {k:28}{d['kind']:8}{d['full_stopped']}/{d['n']}")
    print("\nAttacks allowed / benign flagged under full:")
    for c in r["cases"]:
        v = c["verdicts"]["full"]
        if (c["kind"] == "attack" and v == "ALLOW") or (c["kind"] == "benign" and v != "ALLOW"):
            print(f"  {c['id']} {c['kind']:6} {v:8} {c['category']}: {c['title']}")
