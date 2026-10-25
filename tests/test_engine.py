import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import engine
import evals
from scenarios import BY_ID, SCENARIOS

CANARY = "CNRY-TEST"


def run(sc, flags=None):
    s = engine.Session(sc["prompt"], flags=flags, canary=CANARY)
    res = []
    for st in sc["steps"]:
        args = evals._sub(st["args"], CANARY)
        out = st.get("out")
        if st["tool"] in s.contract["untrusted_tools"] and out is not None:
            out = s.plant(out)
        r = s.check(st["tool"], args, out=out)
        res.append(r["verdict"])
        if r["verdict"] == "BLOCK":
            break
    return res


@pytest.mark.parametrize("sid", ["clean", "shift"])
def test_benign_allow(sid):
    assert set(run(BY_ID[sid])) == {"ALLOW"}


@pytest.mark.parametrize("sid", ["poison", "exfil", "reword"])
def test_attack_blocked_at_step_two(sid):
    v = run(BY_ID[sid])
    assert v == ["ALLOW", "BLOCK"]


def test_fraud_stepup():
    assert run(BY_ID["fraud"]) == ["ALLOW", "STEP-UP"]


def test_bigpo_stepup():
    assert run(BY_ID["bigpo"]) == ["ALLOW", "STEP-UP"]


def test_session_locks_after_block():
    s = engine.Session("x", canary=CANARY)
    s.check("fetch_rfq", {"file": "a.txt"}, out=s.plant("quote"))
    assert s.check("run_shell", {"cmd": "ls"})["verdict"] == "BLOCK"
    assert s.check("calculate_quote", {"item": "a"})["verdict"] == "BLOCK"


def test_contract_only_does_not_hardblock_reword():
    v = run(BY_ID["reword"], engine.PRESETS["contract_only"])
    assert "BLOCK" not in v


def test_ledger_verify_and_tamper():
    L = engine.Ledger()
    for i, v in enumerate(["ALLOW", "BLOCK", "ALLOW"]):
        L.append("t", {"i": i}, False, 0, v)
    assert L.verify() == -1
    L.tamper()
    assert L.verify() == 1


def test_eval_shape_and_rates():
    t = time.time()
    r = evals.run_eval()
    assert time.time() - t < 1.0
    assert r["n_cases"] >= 48 and r["n_attack"] >= 25 and r["n_benign"] >= 18
    assert len(r["configs"]) == 4
    for c in r["configs"]:
        for k in ("attack_block_rate", "attack_stopped_rate", "false_positive_rate", "friction_rate"):
            assert 0 <= c[k] <= 1
    assert r["baseline_cold_start"]["attack_block_rate"] == 0
    full = r["configs"][-1]
    assert full["attack_block_rate"] >= r["configs"][0]["attack_block_rate"]
    assert all(set(c["verdicts"]) == {x[0] for x in evals.CONFIGS} for c in r["cases"])
    assert sum(d["n"] for d in r["categories"].values()) == r["n_cases"]


def test_eval_deterministic():
    assert evals.run_eval() == evals.run_eval()
