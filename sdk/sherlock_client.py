"""Tiny stdlib-only Sherlock client (urllib). Talks to POST /api/gate.

    dg = Sherlock("http://127.0.0.1:8000", prompt="Read quote.txt and summarise")
    dg.check("read_file", {"path": "/hr/salaries.csv"})      # -> result dict

    @dg.guard("read_file")                  # trusted tool: checked BEFORE it runs
    @dg.guard("fetch_rfq", untrusted=True)  # untrusted tool: runs FIRST, then checked

Trade-off for untrusted=True: /api/gate checks the args and ingests the tool output in ONE call, so the
output has to exist before the check. The function therefore runs before Sherlock sees it. Use this only
for tools whose side effects are harmless (reads / fetches); never for tools that write or send. If the
check returns BLOCK/STEP-UP the output is withheld from your agent (an exception is raised instead).
"""
from __future__ import annotations

import functools
import json
import urllib.error
import urllib.request


class SherlockBlocked(Exception):
    def __init__(self, result: dict):
        self.result = result
        super().__init__("Blocked by Sherlock: " + "; ".join(result.get("why") or ["policy"]))


class SherlockStepUp(Exception):
    def __init__(self, result: dict):
        self.result = result
        super().__init__("Sherlock requires human approval: " + "; ".join(result.get("why") or ["policy"]))


class Sherlock:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", prompt: str = "", session_id: str | None = None,
                 timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.prompt = prompt
        self.session_id = session_id
        self.timeout = timeout

    def check(self, tool: str, args: dict | None = None, out: str | None = None) -> dict:
        body = {"session_id": self.session_id, "prompt": self.prompt, "tool": tool, "args": args or {}, "out": out}
        req = urllib.request.Request(self.base_url + "/api/gate", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                res = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Sherlock gate returned HTTP {e.code}: {e.read().decode()[:200]}") from e
        self.session_id = res.get("session_id", self.session_id)
        return res

    def guard(self, tool: str, untrusted: bool = False):
        """Decorator. Keyword args of the wrapped call (plus positional ones, by name) become the `args` sent."""
        def deco(fn):
            names = fn.__code__.co_varnames[:fn.__code__.co_argcount]

            @functools.wraps(fn)
            def wrapper(*a, **kw):
                args = {**dict(zip(names, a)), **kw}
                if untrusted:
                    result = fn(*a, **kw)                                  # run first, see docstring
                    res = self.check(tool, args, out=str(result))
                else:
                    res = self.check(tool, args)
                    result = None
                if res["verdict"] == "BLOCK":
                    raise SherlockBlocked(res)
                if res["verdict"] == "STEP-UP":
                    raise SherlockStepUp(res)
                return result if untrusted else fn(*a, **kw)
            return wrapper
        return deco
