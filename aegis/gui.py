"""
aegis.gui — AEGIS Security Center, a desktop app in the shape of a consumer
antivirus (Norton / Bitdefender style): a protection dashboard, scan actions, a
quarantine manager, real-time protection, and settings.

It is a thin Tkinter view over the engine; all the real work lives in
aegis.scanjob and aegis.scanner. Tkinter ships with standard Python, so this
needs no extra dependency. Worker threads never touch widgets — they push events
onto a queue that the Tk main loop drains via `after`, which keeps the UI
responsive and thread-safe.

Honest scope (shown in-app): AEGIS's "real-time protection" is a polling
on-access watcher, not a kernel filesystem minifilter (that needs a signed
driver), and definitions are your local signature/blocklist, not a cloud feed.
It is an original, educational engine — not a certified replacement for a
commercial AV on a machine that needs guaranteed protection.
"""
from __future__ import annotations

import queue
import threading
import time
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    _TK_OK = True
except Exception:  # pragma: no cover - depends on the platform build
    _TK_OK = False

import os
import sys as _sys

from . import scanjob
from .scanner import Scanner, Model, DEFAULT_PRIOR


def resource_path(rel: str) -> Path:
    """Resolve a bundled data file, in a PyInstaller build or from source."""
    base = getattr(_sys, "_MEIPASS", None)
    if base:
        return Path(base) / rel
    return Path(__file__).resolve().parent / rel


def bundled_model_path() -> Path:
    """A pre-trained model shipped with the app, so first launch is instant."""
    return resource_path("data/model.json")

# palette — a dark security-console look
C = {
    "bg": "#0d1016", "panel": "#161b23", "panel2": "#1d232d", "line": "#2b333f",
    "ink": "#eaeef4", "ink2": "#a9b4c2", "ink3": "#6f7d8f",
    "accent": "#3fc2bc", "allow": "#3ec37a", "review": "#e0a92a", "block": "#f0647e",
}
VERDICT_COLOR = {"ALLOW": C["allow"], "REVIEW": C["review"],
                 "ESCALATE": C["review"], "BLOCK": C["block"]}


def launch():
    if not _TK_OK:
        print("The GUI needs Tkinter, which isn't available in this Python build.\n"
              "On Windows/macOS it ships with python.org Python. On Linux install\n"
              "  sudo apt install python3-tk   (Debian/Ubuntu)\n"
              "Meanwhile the full engine is available on the command line: aegis scan …")
        return 2
    app = SecurityCenter()
    app.mainloop()
    return 0


if _TK_OK:
    class SecurityCenter(tk.Tk):
        def __init__(self):
            super().__init__()
            # import here so the module imports even where cli's paths differ
            from .cli import AEGIS_HOME, MODEL_PATH, ALLOW_PATH, BLOCK_PATH, QUAR_DIR
            from .allowlist import Allowlist
            from .intel import Blocklist
            from .quarantine import Quarantine
            self.AEGIS_HOME = AEGIS_HOME
            self.MODEL_PATH = MODEL_PATH
            self.allowlist = Allowlist(ALLOW_PATH)
            self.blocklist = Blocklist(BLOCK_PATH)
            self.quarantine = Quarantine(QUAR_DIR)

            self.title("AEGIS Security Center")
            self.geometry("980x660")
            self.minsize(820, 560)
            self.configure(bg=C["bg"])

            self.events = queue.Queue()
            self.scanner = None
            self.job = None
            self.watcher = None
            self.profile = tk.StringVar(value="balanced")
            self.auto_quar = tk.BooleanVar(value=False)
            self.last_scan = "never"

            self._init_style()
            self._build()
            self._load_engine()
            self.after(100, self._drain)
            self.protocol("WM_DELETE_WINDOW", self._on_close)

        # -- styling ------------------------------------------------------
        def _init_style(self):
            s = ttk.Style(self)
            try:
                s.theme_use("clam")
            except tk.TclError:
                pass
            s.configure(".", background=C["bg"], foreground=C["ink"],
                        fieldbackground=C["panel2"], bordercolor=C["line"])
            s.configure("TFrame", background=C["bg"])
            s.configure("Panel.TFrame", background=C["panel"])
            s.configure("TLabel", background=C["bg"], foreground=C["ink"])
            s.configure("Panel.TLabel", background=C["panel"], foreground=C["ink"])
            s.configure("Dim.TLabel", background=C["panel"], foreground=C["ink3"])
            s.configure("H.TLabel", background=C["bg"], foreground=C["ink"],
                        font=("Segoe UI", 15, "bold"))
            s.configure("Big.TLabel", background=C["panel"], foreground=C["ink"],
                        font=("Segoe UI", 26, "bold"))
            s.configure("TButton", background=C["panel2"], foreground=C["ink"],
                        borderwidth=0, focusthickness=0, padding=(14, 9),
                        font=("Segoe UI", 10, "bold"))
            s.map("TButton", background=[("active", C["line"])])
            s.configure("Accent.TButton", background=C["accent"], foreground="#06231f")
            s.map("Accent.TButton", background=[("active", "#5ad3cd")])
            s.configure("Nav.TButton", background=C["bg"], foreground=C["ink2"],
                        anchor="w", padding=(18, 12), font=("Segoe UI", 11))
            s.map("Nav.TButton", background=[("active", C["panel"])])
            s.configure("NavOn.TButton", background=C["panel"], foreground=C["accent"],
                        anchor="w", padding=(18, 12), font=("Segoe UI", 11, "bold"))
            s.configure("Treeview", background=C["panel2"], fieldbackground=C["panel2"],
                        foreground=C["ink"], borderwidth=0, rowheight=26)
            s.configure("Treeview.Heading", background=C["panel"], foreground=C["ink3"],
                        borderwidth=0, font=("Segoe UI", 9, "bold"))
            s.map("Treeview", background=[("selected", C["line"])])
            s.configure("TProgressbar", background=C["accent"], troughcolor=C["panel2"],
                        borderwidth=0)

        # -- layout -------------------------------------------------------
        def _build(self):
            nav = tk.Frame(self, bg=C["bg"], width=190)
            nav.pack(side="left", fill="y")
            nav.pack_propagate(False)
            brand = tk.Frame(nav, bg=C["bg"])
            brand.pack(fill="x", pady=(20, 24), padx=18)
            tk.Label(brand, text="◆ AEGIS", bg=C["bg"], fg=C["accent"],
                     font=("Segoe UI", 16, "bold")).pack(anchor="w")
            tk.Label(brand, text="SECURITY CENTER", bg=C["bg"], fg=C["ink3"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")

            self.nav_btns = {}
            self.views = {}
            content = tk.Frame(self, bg=C["bg"])
            content.pack(side="left", fill="both", expand=True)
            self.content = content

            for name in ("Dashboard", "Scan", "Quarantine", "Protection", "Settings"):
                b = ttk.Button(nav, text=name, style="Nav.TButton",
                               command=lambda n=name: self.show(n))
                b.pack(fill="x")
                self.nav_btns[name] = b
                f = tk.Frame(content, bg=C["bg"])
                self.views[name] = f

            ver = tk.Label(nav, text="v5.9.1", bg=C["bg"], fg=C["ink3"],
                           font=("Segoe UI", 8))
            ver.pack(side="bottom", pady=14)

            self._build_dashboard(self.views["Dashboard"])
            self._build_scan(self.views["Scan"])
            self._build_quarantine(self.views["Quarantine"])
            self._build_protection(self.views["Protection"])
            self._build_settings(self.views["Settings"])
            self.show("Dashboard")

        def show(self, name):
            for n, f in self.views.items():
                f.pack_forget()
                self.nav_btns[n].configure(
                    style="NavOn.TButton" if n == name else "Nav.TButton")
            self.views[name].pack(fill="both", expand=True, padx=26, pady=22)
            if name == "Quarantine":
                self._refresh_quarantine()
            if name == "Dashboard":
                self._refresh_dashboard()

        def _card(self, parent, **kw):
            f = tk.Frame(parent, bg=C["panel"], highlightbackground=C["line"],
                         highlightthickness=1, **kw)
            return f

        # -- dashboard ----------------------------------------------------
        def _build_dashboard(self, root):
            tk.Label(root, text="Dashboard", bg=C["bg"], fg=C["ink"],
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")

            self.banner = tk.Frame(root, bg=C["panel"], highlightbackground=C["line"],
                                   highlightthickness=1)
            self.banner.pack(fill="x", pady=(16, 18))
            self.shield = tk.Label(self.banner, text="🛡", bg=C["panel"],
                                   font=("Segoe UI", 40))
            self.shield.pack(side="left", padx=(22, 16), pady=18)
            btxt = tk.Frame(self.banner, bg=C["panel"])
            btxt.pack(side="left", pady=18)
            self.banner_title = tk.Label(btxt, text="Checking…", bg=C["panel"],
                                         fg=C["ink"], font=("Segoe UI", 17, "bold"))
            self.banner_title.pack(anchor="w")
            self.banner_sub = tk.Label(btxt, text="", bg=C["panel"], fg=C["ink2"],
                                       font=("Segoe UI", 10))
            self.banner_sub.pack(anchor="w")

            cards = tk.Frame(root, bg=C["bg"])
            cards.pack(fill="x")
            cards.columnconfigure((0, 1, 2), weight=1, uniform="c")
            self.stat_rt = self._stat_card(cards, 0, "Real-Time Protection", "—")
            self.stat_q = self._stat_card(cards, 1, "In Quarantine", "0")
            self.stat_def = self._stat_card(cards, 2, "Definitions", "0")

            actions = tk.Frame(root, bg=C["bg"])
            actions.pack(fill="x", pady=(22, 0))
            tk.Label(actions, text="Run a scan", bg=C["bg"], fg=C["ink3"],
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 10))
            row = tk.Frame(actions, bg=C["bg"])
            row.pack(fill="x")
            ttk.Button(row, text="⚡  Quick Scan", style="Accent.TButton",
                       command=self.quick_scan).pack(side="left", padx=(0, 10))
            ttk.Button(row, text="🖥  Full Scan",
                       command=self.full_scan).pack(side="left", padx=(0, 10))
            ttk.Button(row, text="📁  Custom…",
                       command=self.custom_scan).pack(side="left")

        def _stat_card(self, parent, col, label, value):
            f = self._card(parent)
            f.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0))
            val = tk.Label(f, text=value, bg=C["panel"], fg=C["ink"],
                           font=("Segoe UI", 22, "bold"))
            val.pack(anchor="w", padx=18, pady=(16, 0))
            tk.Label(f, text=label, bg=C["panel"], fg=C["ink3"],
                     font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(2, 16))
            return val

        def _refresh_dashboard(self):
            on = self.watcher is not None and self.watcher.running
            self.stat_rt.configure(text="On" if on else "Off",
                                   fg=C["allow"] if on else C["review"])
            self.stat_q.configure(text=str(len(self.quarantine.list())))
            ndef = len(self.scanner.model.bad_hashes) if self.scanner else 0
            self.stat_def.configure(text=str(ndef))
            if on:
                self.shield.configure(text="🛡", fg=C["allow"])
                self.banner.configure(highlightbackground=C["allow"])
                self.banner_title.configure(text="You're protected", fg=C["allow"])
                self.banner_sub.configure(
                    text=f"Real-time protection is on · last scan: {self.last_scan}")
            else:
                self.shield.configure(text="🛡", fg=C["review"])
                self.banner.configure(highlightbackground=C["review"])
                self.banner_title.configure(text="Protection is off", fg=C["review"])
                self.banner_sub.configure(
                    text="Turn on real-time protection, or run a scan · "
                         f"last scan: {self.last_scan}")

        # -- scan ---------------------------------------------------------
        def _build_scan(self, root):
            top = tk.Frame(root, bg=C["bg"]); top.pack(fill="x")
            tk.Label(top, text="Scan", bg=C["bg"], fg=C["ink"],
                     font=("Segoe UI", 20, "bold")).pack(side="left")
            tk.Label(top, text="Sensitivity:", bg=C["bg"], fg=C["ink3"]).pack(
                side="left", padx=(20, 6))
            om = ttk.OptionMenu(top, self.profile, "balanced", "max", "balanced",
                                "relaxed")
            om.pack(side="left")
            self.cancel_btn = ttk.Button(top, text="Cancel", command=self.cancel_scan)
            self.cancel_btn.pack(side="right")

            self.scan_status = tk.Label(root, text="Idle — choose a scan from the "
                                        "Dashboard.", bg=C["bg"], fg=C["ink2"],
                                        font=("Segoe UI", 10))
            self.scan_status.pack(anchor="w", pady=(14, 6))
            self.pbar = ttk.Progressbar(root, mode="determinate")
            self.pbar.pack(fill="x")
            self.scan_counts = tk.Label(root, text="", bg=C["bg"], fg=C["ink3"],
                                        font=("Segoe UI", 9))
            self.scan_counts.pack(anchor="w", pady=(6, 12))

            cols = ("verdict", "p", "path")
            self.scan_tree = ttk.Treeview(root, columns=cols, show="headings",
                                          height=12)
            self.scan_tree.heading("verdict", text="VERDICT")
            self.scan_tree.heading("p", text="P(mal)")
            self.scan_tree.heading("path", text="FILE")
            self.scan_tree.column("verdict", width=90, anchor="w")
            self.scan_tree.column("p", width=70, anchor="e")
            self.scan_tree.column("path", width=560, anchor="w")
            self.scan_tree.pack(fill="both", expand=True)
            for v, col in VERDICT_COLOR.items():
                self.scan_tree.tag_configure(v, foreground=col)

            act = tk.Frame(root, bg=C["bg"]); act.pack(fill="x", pady=(10, 0))
            ttk.Button(act, text="Quarantine selected",
                       command=self.quarantine_selected).pack(side="left")
            ttk.Button(act, text="Trust selected (allowlist)",
                       command=self.trust_selected).pack(side="left", padx=8)

        # -- quarantine ---------------------------------------------------
        def _build_quarantine(self, root):
            tk.Label(root, text="Quarantine", bg=C["bg"], fg=C["ink"],
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
            tk.Label(root, text="Blocked files are neutered on disk (header XOR-"
                     "corrupted) so they can't run. Restore rebuilds the original "
                     "byte-for-byte.", bg=C["bg"], fg=C["ink3"],
                     font=("Segoe UI", 9), wraplength=680, justify="left").pack(
                     anchor="w", pady=(6, 14))
            cols = ("verdict", "path", "qid")
            self.q_tree = ttk.Treeview(root, columns=cols, show="headings", height=14)
            for c, t, w in (("verdict", "VERDICT", 90), ("path", "ORIGINAL PATH", 560),
                            ("qid", "ID", 130)):
                self.q_tree.heading(c, text=t); self.q_tree.column(c, width=w)
            self.q_tree.pack(fill="both", expand=True)
            act = tk.Frame(root, bg=C["bg"]); act.pack(fill="x", pady=(10, 0))
            ttk.Button(act, text="Restore", command=self.restore_selected).pack(side="left")
            ttk.Button(act, text="Delete permanently",
                       command=self.delete_selected).pack(side="left", padx=8)
            ttk.Button(act, text="Refresh", command=self._refresh_quarantine).pack(side="right")

        def _refresh_quarantine(self):
            for i in self.q_tree.get_children():
                self.q_tree.delete(i)
            for m in self.quarantine.list():
                v = m.get("verdict", {}).get("decision", "BLOCK")
                self.q_tree.insert("", "end", values=(v, m.get("original_path", ""),
                                                       m.get("qid", "")))

        # -- protection ---------------------------------------------------
        def _build_protection(self, root):
            tk.Label(root, text="Real-Time Protection", bg=C["bg"], fg=C["ink"],
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
            tk.Label(root, text="Watches folders and scans new or changed files as "
                     "they appear. This is a polling on-access watcher — AEGIS's "
                     "stand-in for a kernel driver, which a pure-Python tool can't "
                     "provide.", bg=C["bg"], fg=C["ink3"], font=("Segoe UI", 9),
                     wraplength=680, justify="left").pack(anchor="w", pady=(6, 16))

            box = self._card(root); box.pack(fill="x")
            inner = tk.Frame(box, bg=C["panel"]); inner.pack(fill="x", padx=18, pady=16)
            self.rt_state = tk.Label(inner, text="OFF", bg=C["panel"], fg=C["review"],
                                     font=("Segoe UI", 15, "bold"))
            self.rt_state.pack(side="left")
            self.rt_toggle = ttk.Button(inner, text="Turn On", style="Accent.TButton",
                                        command=self.toggle_realtime)
            self.rt_toggle.pack(side="right")
            self.rt_folder = tk.StringVar(value=str(scanjob.quick_targets()[0]))
            fr = tk.Frame(root, bg=C["bg"]); fr.pack(fill="x", pady=(14, 0))
            tk.Label(fr, text="Watched folder:", bg=C["bg"], fg=C["ink2"]).pack(side="left")
            tk.Label(fr, textvariable=self.rt_folder, bg=C["bg"], fg=C["ink"]).pack(
                side="left", padx=8)
            ttk.Button(fr, text="Change…", command=self._pick_watch).pack(side="left")

            tk.Label(root, text="Live protection log", bg=C["bg"], fg=C["ink3"],
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(20, 6))
            self.rt_log = tk.Text(root, height=10, bg=C["panel2"], fg=C["ink"],
                                  bd=0, font=("Consolas", 9), wrap="none")
            self.rt_log.pack(fill="both", expand=True)
            self.rt_log.configure(state="disabled")

        def _pick_watch(self):
            d = filedialog.askdirectory(title="Choose a folder to protect")
            if d:
                self.rt_folder.set(d)

        # -- settings -----------------------------------------------------
        def _build_settings(self, root):
            tk.Label(root, text="Settings", bg=C["bg"], fg=C["ink"],
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
            box = self._card(root); box.pack(fill="x", pady=(16, 0))
            inner = tk.Frame(box, bg=C["panel"]); inner.pack(fill="x", padx=18, pady=16)
            ttk.Checkbutton(inner, text="Auto-quarantine files that BLOCK",
                            variable=self.auto_quar).pack(anchor="w")
            tk.Label(inner, text="Off by default — a scan surfaces threats for you to "
                     "review rather than acting on its own.", bg=C["panel"],
                     fg=C["ink3"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 12))
            self.def_lbl = tk.Label(inner, text="", bg=C["panel"], fg=C["ink2"],
                                    font=("Segoe UI", 9))
            self.def_lbl.pack(anchor="w")
            ttk.Button(inner, text="Update definitions (retrain)",
                       command=self.retrain).pack(anchor="w", pady=(10, 0))
            tk.Label(root, text=f"State folder: {self.AEGIS_HOME}", bg=C["bg"],
                     fg=C["ink3"], font=("Segoe UI", 8)).pack(anchor="w", pady=(16, 0))

        # -- engine -------------------------------------------------------
        def _load_engine(self):
            # 1) a model the user has trained/updated wins; 2) otherwise fall
            #    back to the model bundled with the app (instant first launch);
            #    3) otherwise prompt to train.
            src = None
            if self.MODEL_PATH.exists():
                src = self.MODEL_PATH
            elif bundled_model_path().exists():
                src = bundled_model_path()
            if src is not None:
                try:
                    model = Model.load(src)
                    self.scanner = Scanner(model, allowlist=self.allowlist,
                                           blocklist=self.blocklist)
                    if src != self.MODEL_PATH:
                        try:                       # seed the user's state folder
                            model.save(self.MODEL_PATH)
                        except Exception:
                            pass
                except Exception:
                    self.scanner = None
            self._refresh_dashboard()
            if hasattr(self, "def_lbl"):
                n = len(self.scanner.model.bad_hashes) if self.scanner else 0
                self.def_lbl.configure(text=f"Signature definitions: {n}")
            if self.scanner is None:
                self.after(300, self._prompt_train)

        def _prompt_train(self):
            if messagebox.askyesno("AEGIS", "No definitions found yet.\n\n"
                                   "Train the engine now? (a few seconds)"):
                self.retrain()

        def retrain(self):
            self.scan_status_note("Training engine…")
            def work():
                from . import train as trainmod
                model = trainmod.train()
                model.save(self.MODEL_PATH)
                self.events.put(("trained", None))
            threading.Thread(target=work, daemon=True).start()

        def scan_status_note(self, txt):
            if hasattr(self, "scan_status"):
                self.scan_status.configure(text=txt)

        # -- scans --------------------------------------------------------
        def quick_scan(self):
            self._start_scan(scanjob.quick_targets(), "Quick Scan")

        def full_scan(self):
            self._start_scan(scanjob.full_targets(), "Full Scan")

        def custom_scan(self):
            d = filedialog.askdirectory(title="Choose a folder to scan")
            if d:
                self._start_scan([Path(d)], "Custom Scan")

        def _start_scan(self, targets, label):
            if self.scanner is None:
                messagebox.showinfo("AEGIS", "Train the engine first (Settings → "
                                    "Update definitions).")
                return
            if self.job and self.job.is_running:
                messagebox.showinfo("AEGIS", "A scan is already running.")
                return
            self.show("Scan")
            for i in self.scan_tree.get_children():
                self.scan_tree.delete(i)
            self.pbar.configure(value=0, maximum=100)
            self.scan_status_note(f"{label} running…")
            self.job = scanjob.ScanJob(
                self.scanner, targets, profile=self.profile.get(),
                quarantine=self.quarantine, auto_quarantine=self.auto_quar.get())
            self._scan_label = label
            self.job.start(
                on_progress=lambda i, t, f: self.events.put(("progress", (i, t, f))),
                on_flagged=lambda r: self.events.put(("flagged", r)),
                on_done=lambda s: self.events.put(("scan_done", s)))

        def cancel_scan(self):
            if self.job and self.job.is_running:
                self.job.cancel()
                self.scan_status_note("Cancelling…")

        # -- realtime -----------------------------------------------------
        def toggle_realtime(self):
            if self.scanner is None:
                messagebox.showinfo("AEGIS", "Train the engine first.")
                return
            if self.watcher and self.watcher.running:
                self.watcher.stop()
                self.watcher = None
                self.rt_state.configure(text="OFF", fg=C["review"])
                self.rt_toggle.configure(text="Turn On")
                self._rt_write("real-time protection stopped")
            else:
                folder = Path(self.rt_folder.get())
                self.watcher = scanjob.RealtimeWatcher(
                    self.scanner, [folder], profile=self.profile.get(),
                    quarantine=self.quarantine)
                self.watcher.start(
                    on_threat=lambda r: self.events.put(("threat", r)))
                self.rt_state.configure(text="ON", fg=C["allow"])
                self.rt_toggle.configure(text="Turn Off")
                self._rt_write(f"watching {folder}")
            self._refresh_dashboard()

        def _rt_write(self, line):
            self.rt_log.configure(state="normal")
            self.rt_log.insert("end", time.strftime("[%H:%M:%S] ") + line + "\n")
            self.rt_log.see("end")
            self.rt_log.configure(state="disabled")

        # -- treeview actions --------------------------------------------
        def _selected_paths(self, tree, col=2):
            out = []
            for iid in tree.selection():
                vals = tree.item(iid, "values")
                if len(vals) > col:
                    out.append(vals[col])
            return out

        def quarantine_selected(self):
            for p in self._selected_paths(self.scan_tree, 2):
                if Path(p).exists():
                    try:
                        self.quarantine.store(p, {"decision": "BLOCK"})
                    except Exception as e:
                        messagebox.showerror("AEGIS", f"Could not quarantine:\n{e}")
            messagebox.showinfo("AEGIS", "Selected files quarantined.")

        def trust_selected(self):
            for p in self._selected_paths(self.scan_tree, 2):
                try:
                    self.allowlist.add_file(p)
                except Exception:
                    pass
            messagebox.showinfo("AEGIS", "Selected files added to the allowlist.")

        def restore_selected(self):
            for iid in self.q_tree.selection():
                qid = self.q_tree.item(iid, "values")[2]
                try:
                    self.quarantine.restore(qid)
                except Exception as e:
                    messagebox.showerror("AEGIS", f"Restore failed:\n{e}")
            self._refresh_quarantine()

        def delete_selected(self):
            if not messagebox.askyesno("AEGIS", "Permanently delete the selected "
                                       "quarantined items?"):
                return
            for iid in self.q_tree.selection():
                qid = self.q_tree.item(iid, "values")[2]
                for suffix in (".quar", ".json"):
                    p = self.quarantine.root / f"{qid}{suffix}"
                    try:
                        p.unlink()
                    except OSError:
                        pass
            self._refresh_quarantine()

        # -- event pump ---------------------------------------------------
        def _drain(self):
            try:
                while True:
                    kind, payload = self.events.get_nowait()
                    self._handle(kind, payload)
            except queue.Empty:
                pass
            self.after(100, self._drain)

        def _handle(self, kind, payload):
            if kind == "progress":
                i, t, f = payload
                self.pbar.configure(maximum=max(t, 1), value=i)
                self.scan_counts.configure(text=f"{i}/{t} files")
            elif kind == "flagged":
                r = payload
                self.scan_tree.insert("", "end", tags=(r["decision"],),
                                      values=(r["decision"], f"{r['posterior']:.3f}",
                                              r["path"]))
            elif kind == "scan_done":
                s = payload
                self.last_scan = time.strftime("%H:%M")
                verb = "cancelled" if s.cancelled else "complete"
                self.scan_status_note(
                    f"{getattr(self, '_scan_label', 'Scan')} {verb}: "
                    f"{s.scanned} scanned, {s.threats} flagged "
                    f"({s.block} block · {s.review} review · {s.escalate} escalate) "
                    f"in {s.elapsed:.1f}s")
                self.pbar.configure(value=self.pbar["maximum"])
                self._refresh_dashboard()
            elif kind == "threat":
                r = payload
                self._rt_write(f"THREAT {r['decision']} P={r['posterior']:.2f} "
                               f"{r['path']}")
                self.stat_q.configure(text=str(len(self.quarantine.list())))
            elif kind == "trained":
                self.scanner = Scanner(Model.load(self.MODEL_PATH),
                                       allowlist=self.allowlist,
                                       blocklist=self.blocklist)
                self.scan_status_note("Definitions updated.")
                self._refresh_dashboard()
                if hasattr(self, "def_lbl"):
                    self.def_lbl.configure(
                        text=f"Signature definitions: {len(self.scanner.model.bad_hashes)}")

        def _on_close(self):
            if self.watcher and self.watcher.running:
                self.watcher.stop()
            if self.job and self.job.is_running:
                self.job.cancel()
            self.destroy()
