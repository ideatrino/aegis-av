"""
aegis.pickle_scan — static malicious-pickle scanner (design doc S23).

`torch.load`, joblib and pickle unpickle a stack VM that can import and call
anything: the canonical gadget is GLOBAL 'os' 'system' then REDUCE, which runs
a shell command the instant the model loads. This scanner decodes opcodes with
the stdlib `pickletools.genops` and NEVER executes them, flagging any
GLOBAL/STACK_GLOBAL that reaches a dangerous module, with a stronger verdict
when a REDUCE/NEWOBJ/BUILD actually *calls* it. Denylist precision, not
allowlist paranoia: an ordinary model imports torch/numpy/collections and
stays silent; only one reaching for code execution fires.
"""
from __future__ import annotations

import io
import pickletools
from dataclasses import dataclass, field
from typing import List, Tuple

# modules whose presence in a pickle's import surface means code execution.
_DANGEROUS = {
    "os", "subprocess", "sys", "socket", "ctypes", "runpy", "shutil",
    "posix", "nt", "pty", "commands", "importlib", "pickle", "builtins",
    "__builtin__", "operator", "webbrowser", "platform",
}
_DANGEROUS_CALLABLES = {
    "system", "popen", "call", "run", "check_output", "check_call", "Popen",
    "eval", "exec", "compile", "__import__", "getattr", "spawn", "spawnl",
    "spawnv", "execv", "execve", "load", "loads", "connect", "fromfd",
    "startfile", "remove", "unlink", "rmtree", "open",
}


@dataclass
class PickleReport:
    is_pickle: bool = False
    dangerous_globals: List[Tuple[str, str]] = field(default_factory=list)
    calls_dangerous: bool = False
    reasons: List[str] = field(default_factory=list)

    @property
    def malicious(self) -> bool:
        return bool(self.dangerous_globals)

    def probability(self) -> float:
        """Calibrated P(malicious) for the fusion (S23: fused, never forced)."""
        if not self.dangerous_globals:
            return 0.02
        return 0.97 if self.calls_dangerous else 0.85


def looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    # PROTO opcode (\x80) or a classic pickle opcode set at the start
    if data[:1] == b"\x80":
        return True
    return data[:1] in (b"(", b"c", b"]", b"}", b"\x95") and b"." in data[-2:]


# opcodes that push a string constant onto the stack (module / name for a
# modern STACK_GLOBAL, which takes both from the stack rather than an inline arg)
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
               "SHORT_BINSTRING", "BINSTRING", "STRING"}


def scan(data: bytes) -> PickleReport:
    rep = PickleReport()
    if not looks_like_pickle(data):
        return rep
    rep.is_pickle = True
    last_global = None
    recent = []                       # rolling window of recent string consts
    try:
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            name = opcode.name
            if name in _STRING_OPS and isinstance(arg, str):
                recent.append(arg)
                if len(recent) > 8:
                    recent.pop(0)
                continue
            mod = func = ""
            if name == "GLOBAL" and isinstance(arg, str):
                # protocol 0/1: arg is "module\nname" (or space-separated)
                parts = arg.replace("\n", " ").split(" ", 1)
                mod = parts[0]
                func = parts[1] if len(parts) > 1 else ""
            elif name == "STACK_GLOBAL":
                # protocol 2+: module and name are the two most recent strings
                if len(recent) >= 2:
                    mod, func = recent[-2], recent[-1]
            if mod or func:
                base = mod.split(".")[0] if mod else ""
                if base in _DANGEROUS or func in _DANGEROUS_CALLABLES:
                    rep.dangerous_globals.append((mod, func))
                    last_global = (mod, func)
                    rep.reasons.append(f"pickle imports {mod}.{func}")
                continue
            if name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD", "INST", "OBJ"):
                if last_global is not None:
                    rep.calls_dangerous = True
                    m, f = last_global
                    rep.reasons.append(f"pickle CALLS {m}.{f} at load time "
                                       f"(working gadget)")
                    last_global = None
    except Exception:
        # a corrupt/truncated pickle: surface the fact, don't crash a scan.
        rep.reasons.append("pickle stream is malformed/truncated")
    return rep
