"""
aegis.sandbox_runner — the child process that executes a Python sample under a
CPython audit hook (design doc §6 Phase 3, §3.3, §8, §12).

This runs as an ISOLATED subprocess (`python -I`), never in-process. It installs
an audit hook that records every OS-facing action and, in blocking mode, RAISES
before the underlying syscall so the escape is prevented at runtime — network,
process/shell, native (ctypes), and destructive/again-write filesystem. The
interpreter's own machinery (import/compile/exec/read) is deliberately NOT
watched: statics (D3/AST) judge code shape; the sandbox judges OS-facing
behavior, which the interpreter never fabricates (§8).

Containment vs. judgment (§12): the hook blocks EVERY escape for safety; whether
a blocked action counts as a *violation* is decided later by the envelope in
dynamic.py, not here.

The trace is written to the fd named by AEGIS_TRACE via os.write (which fires no
`open` audit event, so the logger can't trip its own hook).
"""
import os
import sys

_TRACE_PATH = os.environ.get("AEGIS_TRACE", "")
_BLOCK = os.environ.get("AEGIS_BLOCK", "1") == "1"

# audit events -> behavior category (a prefix match covers os.exec*, os.spawn*)
_WATCH = (
    ("socket.connect", "network"),
    ("socket.getaddrinfo", "network"),
    ("socket.gethostbyname", "network"),
    ("urllib.Request", "network"),
    ("subprocess.Popen", "process"),
    ("os.system", "process"),
    ("os.exec", "process"),
    ("os.spawn", "process"),
    ("os.posix_spawn", "process"),
    ("os.fork", "process"),
    ("os.forkpty", "process"),
    ("pty.spawn", "process"),
    ("ctypes.dlopen", "native"),
    ("ctypes.dlsym", "native"),
    ("ctypes.call_function", "native"),
    ("os.remove", "destructive_fs"),
    ("os.unlink", "destructive_fs"),
    ("os.rename", "destructive_fs"),
    ("os.replace", "destructive_fs"),
    ("os.rmdir", "destructive_fs"),
    ("shutil.rmtree", "destructive_fs"),
    ("shutil.move", "destructive_fs"),
)

try:
    _FD = os.open(_TRACE_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600) \
        if _TRACE_PATH else -1
except OSError:
    _FD = -1


def _emit(category, event, detail=""):
    if _FD < 0:
        return
    # keep the record tiny and JSON-ish without importing json (fewer events)
    detail = str(detail).replace("\\", "/").replace('"', "'")[:120]
    line = '{"category":"%s","event":"%s","detail":"%s"}\n' % (category, event, detail)
    try:
        os.write(_FD, line.encode("utf-8", "replace"))
    except OSError:
        pass


def _hook(event, args):
    category = None
    for name, cat in _WATCH:
        if event == name or event.startswith(name):
            category = cat
            break
    if category is None and event == "open":
        # a write-intent open is a filesystem mutation
        mode = args[1] if len(args) >= 2 else None
        if mode and any(m in str(mode) for m in ("w", "a", "x", "+")):
            category = "fs_write"
    if category:
        detail = ""
        try:
            detail = repr(args[0]) if args else ""
        except Exception:
            pass
        _emit(category, event, detail)
        if _BLOCK:
            raise PermissionError(f"AEGIS sandbox blocked {category} escape ({event})")


def _limits():
    # POSIX resource caps; a no-op on Windows (the parent enforces a timeout).
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (3, 4))
        soft = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (soft, soft))
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        except (ValueError, OSError):
            pass
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        _emit("error", "no_target", "")
        return
    target = sys.argv[1]
    _limits()
    sys.addaudithook(_hook)          # permanent; the sample cannot remove it
    _emit("start", "exec", os.path.basename(target))
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        code = compile(src, target, "exec")
        g = {"__name__": "__main__", "__file__": target, "__builtins__": __builtins__}
        exec(code, g)
        _emit("end", "clean_exit", "")
    except PermissionError as e:
        _emit("halt", "blocked", str(e))
    except SystemExit:
        _emit("end", "sys_exit", "")
    except BaseException as e:               # noqa: BLE001 — record, never crash silently
        _emit("end", "exception", type(e).__name__)


if __name__ == "__main__":
    main()
