"""
aegis.rules — the eighth signal (D8): a dependency-free YARA-lite engine
(design doc S20, S21, S22).

A detector you cannot teach is always one step behind the last incident. D8
lets an analyst express "this exact thing is bad" and have it *fused* under
the same log-odds core, allowlist override and text cap_review as D1-D7 —
extend the ensemble, never bypass it.

Grammar (S22): strings are text, /regex/, or { hex ?? wildcard }; a rule has a
meta severity (block|review|score) and weight, optional min/max filesize, and
a boolean condition compiled by a small recursive-descent parser:
    and or not ( )   #a >= 2   $a at 0   filesize < 2MB   N of them   any/all
A malformed pattern or condition is SKIPPED, never fatal (forgiving parser).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# --- pattern types ---------------------------------------------------------
@dataclass
class Pattern:
    ident: str
    kind: str           # "text" | "regex" | "hex"
    raw: str
    compiled: object = None

    def finditer(self, data: bytes):
        """Yield match offsets in data."""
        if self.kind == "text":
            needle = self.raw.encode("latin1", "replace")
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                yield i
                start = i + 1
        elif self.kind == "regex":
            for m in self.compiled.finditer(data):
                yield m.start()
        elif self.kind == "hex":
            for m in self.compiled.finditer(data):
                yield m.start()


@dataclass
class Rule:
    name: str
    patterns: List[Pattern]
    condition: str
    severity: str = "score"     # block | review | score
    weight: float = 0.8
    min_filesize: Optional[int] = None
    max_filesize: Optional[int] = None


# --- parsing ---------------------------------------------------------------
def _compile_hex(body: str) -> Optional[re.Pattern]:
    toks = body.replace("\n", " ").split()
    parts = []
    for t in toks:
        if t == "??":
            parts.append(b".")
        elif len(t) == 2:
            try:
                parts.append(re.escape(bytes([int(t, 16)])))
            except ValueError:
                return None
        else:
            return None
    if not parts:
        return None
    try:
        return re.compile(b"".join(parts), re.DOTALL)
    except re.error:
        return None


def _size_to_int(tok: str) -> Optional[int]:
    tok = tok.strip().upper()
    mult = 1
    for suf, m in (("KB", 1024), ("MB", 1024 ** 2), ("GB", 1024 ** 3)):
        if tok.endswith(suf):
            mult = m
            tok = tok[:-2]
            break
    try:
        return int(float(tok) * mult)
    except ValueError:
        return None


def parse_rules(text: str) -> List[Rule]:
    """Forgiving, line-oriented reader of the YARA-lite subset."""
    rules: List[Rule] = []
    i = 0
    lines = text.splitlines()
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"rule\s+([A-Za-z_][\w]*)\s*\{?", line)
        if not m:
            i += 1
            continue
        name = m.group(1)
        patterns: List[Pattern] = []
        condition = "any of them"
        severity = "score"
        weight = 0.8
        minfs = maxfs = None
        i += 1
        section = None
        while i < len(lines):
            l = lines[i].strip()
            if l.startswith("}"):
                break
            if l.startswith("meta:"):
                section = "meta"; i += 1; continue
            if l.startswith("strings:"):
                section = "strings"; i += 1; continue
            if l.startswith("condition:"):
                section = "condition"
                rest = l[len("condition:"):].strip()
                if rest:
                    condition = rest
                i += 1
                continue
            if section == "meta":
                mm = re.match(r'(\w+)\s*=\s*"?([^"]*)"?', l)
                if mm:
                    k, v = mm.group(1), mm.group(2).strip()
                    if k == "severity":
                        severity = v.lower()
                    elif k == "weight":
                        try: weight = float(v)
                        except ValueError: pass
                    elif k == "min_filesize":
                        minfs = _size_to_int(v)
                    elif k == "max_filesize":
                        maxfs = _size_to_int(v)
            elif section == "strings":
                sm = re.match(r'(\$\w+)\s*=\s*(.+)', l)
                if sm:
                    ident, val = sm.group(1), sm.group(2).strip()
                    pat = _make_pattern(ident, val)
                    if pat:               # malformed pattern skipped (S20)
                        patterns.append(pat)
            elif section == "condition":
                condition = (condition + " " + l).strip() if condition != "any of them" else l
            i += 1
        rules.append(Rule(name, patterns, condition, severity, weight, minfs, maxfs))
        i += 1
    return rules


def _make_pattern(ident: str, val: str) -> Optional[Pattern]:
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        return Pattern(ident, "text", val[1:-1].encode().decode("unicode_escape"))
    if val.startswith("/") and val.rstrip().endswith("/"):
        body = val.strip()[1:-1]
        try:
            return Pattern(ident, "regex", body,
                           re.compile(body.encode("latin1", "replace"), re.DOTALL))
        except re.error:
            return None
    if val.startswith("{") and val.rstrip().endswith("}"):
        body = val.strip()[1:-1]
        comp = _compile_hex(body)
        if comp is None:
            return None
        return Pattern(ident, "hex", body, comp)
    return None


# --- condition evaluation (recursive-descent, S22) -------------------------
class _CondEval:
    def __init__(self, matches: Dict[str, List[int]], patterns: List[Pattern],
                 filesize: int):
        self.matches = matches
        self.patterns = patterns
        self.filesize = filesize
        self.toks: List[str] = []
        self.pos = 0

    def evaluate(self, condition: str) -> bool:
        try:
            self.toks = self._tokenize(condition)
            self.pos = 0
            val = self._or()
            return bool(val)
        except Exception:
            # forgiving fallback: plain "any of them" count gate (S22)
            return any(self.matches.get(p.ident) for p in self.patterns)

    def _tokenize(self, s: str) -> List[str]:
        s = s.replace("(", " ( ").replace(")", " ) ")
        s = re.sub(r"(>=|<=|==|>|<)", r" \1 ", s)
        return s.split()

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self):
        t = self.toks[self.pos]; self.pos += 1; return t

    def _or(self):
        v = self._and()
        while self._peek() == "or":
            self._next(); v = self._and() or v
        return v

    def _and(self):
        v = self._not()
        while self._peek() == "and":
            self._next(); v = self._not() and v
        return v

    def _not(self):
        if self._peek() == "not":
            self._next(); return not self._not()
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t == "(":
            self._next(); v = self._or()
            if self._peek() == ")":
                self._next()
            return v
        # "N of them" / "any of them" / "all of them"
        if t in ("any", "all") or (t and t.isdigit()):
            return self._of_them()
        # "#a >= 2"
        if t and t.startswith("#"):
            ident = "$" + self._next()[1:]
            op = self._next()
            n = int(self._next())
            count = len(self.matches.get(ident, []))
            return self._cmp(count, op, n)
        # "filesize < 2MB"
        if t == "filesize":
            self._next(); op = self._next(); sz = _size_to_int(self._next()) or 0
            return self._cmp(self.filesize, op, sz)
        # "$a at 0"
        if t and t.startswith("$"):
            ident = self._next()
            hits = self.matches.get(ident, [])
            if self._peek() == "at":
                self._next(); off = int(self._next())
                return off in hits
            return bool(hits)
        # bare word we don't understand -> treat as False
        self._next()
        return False

    def _of_them(self):
        t = self._next()
        n = len(self.patterns) if t == "all" else (1 if t == "any" else int(t))
        if self._peek() == "of":
            self._next()
        if self._peek() == "them":
            self._next()
        hit = sum(1 for p in self.patterns if self.matches.get(p.ident))
        return hit >= n

    @staticmethod
    def _cmp(a, op, b):
        return {">=": a >= b, "<=": a <= b, "==": a == b,
                ">": a > b, "<": a < b}.get(op, False)


@dataclass
class RuleHit:
    name: str
    severity: str
    weight: float


def match_rules(data: bytes, rules: List[Rule]) -> List[RuleHit]:
    hits: List[RuleHit] = []
    fsize = len(data)
    for rule in rules:
        if rule.min_filesize is not None and fsize < rule.min_filesize:
            continue
        if rule.max_filesize is not None and fsize > rule.max_filesize:
            continue
        matches: Dict[str, List[int]] = {}
        for p in rule.patterns:
            offs = list(p.finditer(data))
            if offs:
                matches[p.ident] = offs
        if not rule.patterns:
            continue
        if _CondEval(matches, rule.patterns, fsize).evaluate(rule.condition):
            hits.append(RuleHit(rule.name, rule.severity, rule.weight))
    return hits


# --- built-in rules (S20): ship the EICAR self-check enabled ---------------
# The canonical EICAR file IS a 68-byte string. Detect the FILE, not a mention
# of its name (S21 fix): max_filesize keeps it from flagging a 12KB rule engine
# that merely quotes the string.
EICAR_BODY = (r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

BUILTIN_RULES_TEXT = r'''
rule EICAR_Test_File {
    meta:
        severity = "block"
        max_filesize = 128
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar and filesize < 128
}
'''


def builtin_rules() -> List[Rule]:
    return parse_rules(BUILTIN_RULES_TEXT)
