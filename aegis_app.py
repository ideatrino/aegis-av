"""
AEGIS Security Center — frozen-app entry point (used by PyInstaller).

A PyInstaller onefile exe has one entry point but AEGIS needs two behaviors from
the same binary: normally it launches the GUI, but the dynamic sandbox needs to
re-invoke the exe as an isolated child process (there is no `python -I` inside a
frozen build). AEGIS_SANDBOX_CHILD, set by aegis.dynamic when frozen, selects the
sandbox runner; otherwise the GUI launches.
"""
import multiprocessing
import os
import sys


def main():
    if os.environ.get("AEGIS_SANDBOX_CHILD") == "1":
        # running as the contained-dynamics child: argv[1] is the sample path
        from aegis import sandbox_runner
        sandbox_runner.main()
        return 0
    from aegis import gui
    return gui.launch()


if __name__ == "__main__":
    multiprocessing.freeze_support()   # required before any worker spawn in a frozen build
    sys.exit(main())
