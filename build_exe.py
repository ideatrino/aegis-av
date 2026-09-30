r"""
Build AEGIS Security Center into a standalone Windows .exe.

Why this script instead of the `pyinstaller` command: pip often installs
`pyinstaller.exe` into a Scripts folder that isn't on PATH (you likely saw that
warning), so the bare command "is not recognized". Calling PyInstaller through
Python avoids PATH entirely. The build targets aegis_app.py, which launches the
GUI normally and dispatches to the sandbox runner when the frozen exe is
re-invoked for contained dynamic analysis.

    pip install pyinstaller
    python build_exe.py                # windowed app (no console)
    python build_exe.py --console      # keep a console window (to see errors)

Output:  dist\AEGIS Security Center.exe   (a single double-clickable file)

Notes:
  * --collect-submodules aegis is essential: AEGIS imports several modules
    lazily inside functions (train, dynamic, documents, archives, detectors),
    which PyInstaller's static analysis would otherwise miss and the frozen app
    would crash with ModuleNotFoundError.
  * The .exe bundles a pre-trained model (aegis/data/model.json via
    --collect-data), so it works the instant it launches — no training step.
    At runtime a model you train yourself (%USERPROFILE%\.aegis) takes priority;
    quarantine and settings live there too.
  * If the windowed build launches and immediately vanishes, rebuild with
    --console to see the traceback.
"""
import os
import sys


def main():
    try:
        import PyInstaller.__main__ as pyi
    except ImportError:
        print("PyInstaller isn't installed. Run:  pip install pyinstaller")
        return 2

    here = os.path.dirname(os.path.abspath(__file__))
    console = "--console" in sys.argv

    args = [
        os.path.join(here, "aegis_app.py"),   # frozen entry: GUI + sandbox-child dispatch
        "--name", "AEGIS Security Center",
        "--onefile",
        "--collect-submodules", "aegis",   # lazily-imported modules (essential)
        "--collect-data", "aegis",         # ships aegis/data/model.json (instant first launch)
        "--noconfirm", "--clean",
    ]
    if not console:
        args.append("--windowed")
    icon = os.path.join(here, "aegis.ico")
    if os.path.exists(icon):
        args += ["--icon", icon]

    print("Building with PyInstaller:\n  " + " ".join(args) + "\n")
    pyi.run(args)
    print("\nDone. The app is at:  dist\\AEGIS Security Center.exe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
