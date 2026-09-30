"""aegis.report — self-contained, offline, light/dark-aware HTML scan report
(design doc S4-phase4, S13). Every text file AEGIS writes is UTF-8 (S13)."""
from __future__ import annotations

import html
from pathlib import Path
from typing import List

from .core import Verdict

_COLORS = {"ALLOW": "#2e9e5b", "REVIEW": "#c9910a",
           "ESCALATE": "#c9910a", "BLOCK": "#d1435b"}


def _bar(contribs):
    rows = []
    for c in sorted(contribs, key=lambda x: -abs(x["contribution"])):
        val = c["contribution"]
        pct = max(-100, min(100, val * 30))
        color = "#d1435b" if val > 0 else "#2e9e5b"
        side = "left:50%" if val > 0 else f"right:50%"
        width = abs(pct)
        label = "abstain" if c["abstain"] else f"p={c['p']:.2f} w={c['weight']:.2f}"
        rows.append(f'''<tr><td class="det">{html.escape(c["detector"])}</td>
        <td class="barcell"><div class="axis"></div>
        <div class="bar" style="{side};width:{width/2}%;background:{color}"></div></td>
        <td class="num">{val:+.2f}</td><td class="meta">{label}</td></tr>''')
    return "\n".join(rows)


def render(verdicts: List[Verdict], out_path: str):
    parts = []
    for v in verdicts:
        color = _COLORS.get(v.decision, "#888")
        reasons = "".join(f"<li>{html.escape(r)}</li>" for r in v.reasons)
        parts.append(f'''<div class="card">
        <div class="head"><span class="path">{html.escape(v.path)}</span>
        <span class="verdict" style="background:{color}">{v.decision}</span></div>
        <div class="post">posterior P(malicious) = <b>{v.posterior:.4f}</b>
        &nbsp;·&nbsp; prior {v.prior:.4f} &nbsp;·&nbsp;
        disagreement {v.disagreement:.3f}</div>
        <ul class="reasons">{reasons}</ul>
        <table>{_bar(v.contributions())}</table></div>''')
    body = "\n".join(parts)
    doc = f'''<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS scan report</title><style>
:root{{--bg:#f7f7f8;--fg:#1c1c1e;--card:#fff;--line:#e3e3e6;}}
@media(prefers-color-scheme:dark){{:root{{--bg:#161618;--fg:#ececef;--card:#1f1f22;--line:#333;}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;}}
h1{{font-size:20px;}} .card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0;}}
.head{{display:flex;justify-content:space-between;align-items:center;gap:12px;}}
.path{{font-family:ui-monospace,monospace;word-break:break-all;}}
.verdict{{color:#fff;padding:3px 10px;border-radius:20px;font-weight:600;font-size:12px;}}
.post{{color:#888;font-size:13px;margin:8px 0;}} .reasons{{margin:8px 0;padding-left:20px;font-size:13px;}}
table{{width:100%;border-collapse:collapse;margin-top:10px;}}
td{{padding:3px 6px;font-size:12px;border-bottom:1px solid var(--line);}}
.det{{font-family:ui-monospace,monospace;width:110px;}}
.barcell{{position:relative;height:18px;}} .axis{{position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--line);}}
.bar{{position:absolute;top:3px;height:12px;border-radius:3px;}}
.num{{text-align:right;font-family:ui-monospace,monospace;width:60px;}} .meta{{color:#888;width:120px;}}
</style></head><body><h1>AEGIS scan report — {len(verdicts)} file(s)</h1>{body}</body></html>'''
    Path(out_path).write_text(doc, encoding="utf-8")
