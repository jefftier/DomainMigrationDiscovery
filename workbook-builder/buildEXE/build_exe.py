#!/usr/bin/env python3
"""
Build a Windows EXE for Domain Migration Builder (PyInstaller).

Usage (from workbook-builder/ with Python 3.8+ and deps installed):
  pip install pyinstaller pandas openpyxl PySide6
  python buildEXE/build_exe.py

Output: DomainMigrationBuilder.exe in workbook-builder/ root.
Build artifacts (dist/, build/) stay under buildEXE/.
"""
# CI: changes here trigger the build-and-release workflow.
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    script_dir = Path(__file__).resolve().parent  # buildEXE
    workbook_root = script_dir.parent  # workbook-builder
    spec = script_dir / "DomainMigrationBuilder.spec"
    if not spec.is_file():
        print(f"Spec file not found: {spec}", file=sys.stderr)
        sys.exit(1)

    dist_build = script_dir / "dist"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath", str(dist_build),
        "--workpath", str(script_dir / "build"),
        "--specpath", str(script_dir),
        str(spec),
    ]
    print("Running:", " ".join(cmd))
    r = subprocess.call(cmd, cwd=str(workbook_root))
    if r != 0:
        sys.exit(r)

    exe_win = dist_build / "DomainMigrationBuilder.exe"
    exe_other = dist_build / "DomainMigrationBuilder"
    exe_src = exe_win if exe_win.exists() else (exe_other if exe_other.exists() else None)
    if exe_src:
        exe_dest = workbook_root / exe_src.name
        shutil.copy2(exe_src, exe_dest)
        print(f"Built: {exe_dest}")
    if dist_build.exists():
        print(f"Build artifacts in: {dist_build.absolute()}")


if __name__ == "__main__":
    main()
