# Packaging as Windows EXE

## Prerequisites (build machine)

- **Windows** (to produce a Windows EXE that runs without Python).  
  Building on macOS/Linux produces a native binary for that OS, not a Windows EXE.
- **Python 3.8+** with:
  - `pip install pyinstaller pandas openpyxl PySide6`
  - Or: `pip install PyInstaller pandas openpyxl PySide6` (capital P)

## Build

From the project root:

```bat
python build_exe.py
```

Or directly:

```bat
python -m PyInstaller --noconfirm --distpath dist DomainMigrationBuilder.spec
```

Output: **`dist/DomainMigrationBuilder.exe`** (single file, no console window).

## What gets bundled

- **gui_app.py** (entry point)
- **build_migration_workbook.py** (engine)
- **pandas**, **openpyxl**, **PySide6** and their dependencies

## Optional: icon and version

1. **Icon**: Create or add `resources/DomainMigrationBuilder.ico` (Windows .ico).  
   In `DomainMigrationBuilder.spec`, uncomment and set:
   ```python
   icon=os.path.join(spec_dir, 'resources', 'DomainMigrationBuilder.ico'),
   ```

2. **Version metadata**: Create `version_info.txt` (PyInstaller version-info format) and in the spec uncomment:
   ```python
   version=os.path.join(spec_dir, 'version_info.txt'),
   ```

## Validation

1. **Build succeeds on clean machine**  
   On a Windows PC with only Python and the above pip packages, run `python build_exe.py`. The build should finish without errors.

2. **EXE runs without Python installed**  
   Copy `dist/DomainMigrationBuilder.exe` to a machine (or VM) that has **no** Python installed. Double‑click the EXE (or run from cmd). The GUI should start.

3. **Processes sample JSON folder**  
   In the GUI, choose an input folder that contains one or more discovery JSON files, choose an output .xlsx path, click Run. The workbook should be generated (or validation report if “Validate only” is checked).

## Clean rebuild

```bat
pyinstaller --clean DomainMigrationBuilder.spec
```

This removes the `build/` cache and rebuilds from scratch.
