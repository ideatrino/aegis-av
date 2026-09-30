@echo off
REM Double-click to build AEGIS Security Center into a standalone .exe.
REM Needs PyInstaller:  python -m pip install pyinstaller
echo Building AEGIS Security Center...
python -m pip install pyinstaller --quiet
python "%~dp0build_exe.py" %*
echo.
echo If it succeeded, your app is in the "dist" folder next to this file.
pause
