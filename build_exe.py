#!/usr/bin/env python3
"""
Build a single Windows EXE for Domain Migration Builder (PyInstaller).

Usage (on Windows, with Python 3.8+ and deps installed):
  pip install pyinstaller pandas openpyxl PySide6
  python build_exe.py

Output: dist/DomainMigrationBuilder.exe

Optional:
  pyinstaller --clean DomainMigrationBuilder.spec   # clean build
  pyinstaller --distpath ./release DomainMigrationBuilder.spec   # custom output dir
"""
import subprocess
import sys
from pathlib import Path


def main():
    spec = Path(__file__).resolve().parent / "DomainMigrationBuilder.spec"
    if not spec.is_file():
        print(f"Spec file not found: {spec}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath", "dist",
        str(spec),
    ]
    print("Running:", " ".join(cmd))
    r = subprocess.call(cmd)
    if r != 0:
        sys.exit(r)
    dist = Path("dist")
    exe_win = dist / "DomainMigrationBuilder.exe"
    exe_other = dist / "DomainMigrationBuilder"
    if exe_win.exists():
        print(f"Built (Windows): {exe_win}")
    elif exe_other.exists():
        print(f"Built: {exe_other}")
    if dist.exists():
        print(f"Output in: {dist.absolute()}")


if __name__ == "__main__":
    main()
