# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: single Windows EXE for Domain Migration Builder GUI.
# Build: pyinstaller DomainMigrationBuilder.spec
# Output: dist/DomainMigrationBuilder.exe (Windows)

import os

block_cipher = None

# Ensure project root is on path so build_migration_workbook is found
spec_dir = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    ['gui_app.py'],
    pathex=[spec_dir],
    binaries=[],
    datas=[],
    hiddenimports=[
        'build_migration_workbook',
        'pandas',
        'openpyxl',
        'openpyxl.cell._writer',
        'openpyxl.styles.stylesheet',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DomainMigrationBuilder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # --noconsole: no console window for GUI
    # Optional (uncomment and add files for Windows):
    # icon=os.path.join(spec_dir, 'resources', 'DomainMigrationBuilder.ico'),
    # version=os.path.join(spec_dir, 'version_info.txt'),
)
