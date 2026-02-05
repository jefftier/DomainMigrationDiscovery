# Workbook Builder

Build a single **Excel workbook** (`.xlsx`) from domain migration discovery **JSON** files. Use the **CLI** for scripts and automation or the **GUI** for interactive use. You can also package the GUI as a standalone Windows **EXE** so others can run it without Python.

---

## Get running in 2 minutes

**Prerequisites:** Python 3.8+ and `pandas`, `openpyxl`. For the GUI you also need `PySide6`.

1. **Install dependencies:**
   ```bash
   pip install pandas openpyxl
   ```
   For the GUI:
   ```bash
   pip install PySide6
   ```

2. **Gather JSON:** Run [domain-discovery](../domain-discovery/README.md) (locally or remotely) so you have one or more `*_{MM-dd-yyyy}.json` files in a folder (e.g. `C:\temp\MigrationDiscovery\out` or a network share).

3. **Build the workbook (CLI):**
   ```bash
   python build_migration_workbook.py -i "C:\temp\MigrationDiscovery\out" -o "."
   ```
   This creates a timestamped `.xlsx` in the current directory (e.g. `MigrationDiscovery_2025-02-05.xlsx`).

4. **Or use the GUI:**
   ```bash
   python gui_app.py
   ```
   Choose **Input folder** (where the JSON files are), **Output file** (path to the `.xlsx`), then click **Run**.

---

## What the workbook contains

The builder reads all discovery JSON files in the input folder, keeps the **latest snapshot per computer** (by `Metadata.CollectedAt`), then produces one Excel file with many sheets. Summary and config-related sheets give a quick view; detail sheets list services, tasks, credentials, certificates, etc.

| Sheet / area | Content |
|--------------|--------|
| **Summary** | Per-computer overview: HasOldDomainRefs, security agent status (CrowdStrike, Qualys, SCCM, EnCase), counts by category. |
| **Metadata** | ComputerName, domain info, CollectedAt, PlantId, Version. |
| **ServiceAccountCandidates** | All service accounts from services, tasks, IIS, SQL, local admins, credentials, etc. |
| **Services, ScheduledTasks, LocalAdministrators, LocalGroupMembers** | Discovery details with old-domain flags. |
| **MappedDrives, Printers, OdbcDsn, CredentialManager, Certificates, FirewallRules** | Per-category findings. |
| **Config File Findings / Config Summary** | Application config files with domain/credential indicators (redacted). |
| **Oracle Summary / Oracle Details, RDS Licensing** | Oracle and RDS discovery. |
| **Local Admin Membership** | One row per Administrators group member per computer. |
| **SecurityAgents** | CrowdStrike, Qualys, SCCM, EnCase tenant/status. |
| **IIS, SqlServer** | Raw JSON-style content if present. |
| **Others** | Profiles, InstalledApps, SharedFolders, DNS, EventLog, etc. |

- **Security:** Sensitive snippets (passwords, tokens, connection strings) are redacted in JSON and in the workbook. Cells that could be interpreted as formulas (`=`, `+`, `-`, `@`) are escaped so Excel treats them as text.
- **Backward compatibility:** Older JSON without sections like Oracle or RDSLicensing still load; missing sections yield empty or default rows.

---

## Files in this folder

| File | Purpose |
|------|---------|
| **build_migration_workbook.py** | Core engine: load JSON, flatten, validate/sanitize, write Excel. Used by both CLI and GUI. |
| **gui_app.py** | PySide6 GUI: input folder, output path, options (validate only, sanitize report, etc.), progress and log. |
| **build_exe.py** | Helper script that runs PyInstaller to produce a single Windows EXE. |
| **DomainMigrationBuilder.spec** | PyInstaller spec for the GUI EXE (entry: gui_app.py). |

---

## CI: Building and publishing the EXE on GitHub

When anything under `workbook-builder/` changes on `main` (or `master`), GitHub Actions builds the Windows EXE and publishes it as a workflow artifact. To get the EXE: open the repo **Actions** tab → latest successful run → **Artifacts** → download **DomainMigrationBuilder-exe**.

---

## CLI — build_migration_workbook.py

### Quick reference

```bash
python build_migration_workbook.py -i <input_folder> -o <output_dir> [options]
```

### All arguments

| Argument | Short | Default | Description |
|----------|--------|---------|-------------|
| **--input** | **-i** | `results` | Folder containing discovery JSON files (searched recursively). |
| **--output-dir** | **-o** | `.` | Directory where the workbook will be written. |
| **--plant-id** | **-p** | — | Optional. If set, used for **output filename** (e.g. `Plant1_MigrationDiscovery_2025-02-05.xlsx`). *Note: As of this implementation, the workbook may still include all computers from the input folder; filter by plant in discovery or post-process if you need plant-only workbooks.* |
| **--include-sourcefile** | — | off | Add SourceFile (and source computer/section) to every sheet for traceability. |
| **--debug-provenance** | — | off | Same as --include-sourcefile. |
| **--validate-only** | — | off | Scan all sheets for Excel-illegal characters and emit a report CSV; **do not write the .xlsx**. Exit non-zero if any issues are found. |
| **--fail-fast** | — | off | Stop at the first sheet/cell with illegal characters and exit with an error. |
| **--strict-json** | — | off | Do not fall back to cp1252 for non-UTF-8 files; fail decode instead (useful for CI). |
| **--debug** | — | off | When validation finds issues, emit a sanitize report CSV (sheet/row/col + source file). |

### Examples

```bash
# Default: read from ./results, write to current dir
python build_migration_workbook.py

# Specify input and output
python build_migration_workbook.py -i "Y:\MigrationDiscovery\out" -o "C:\Reports"

# Optional plant id in output filename
python build_migration_workbook.py -i ".\out" -o "." -p PLANT001

# Validate only (no Excel), fail if any issues
python build_migration_workbook.py -i ".\out" -o "." --validate-only

# Strict UTF-8 only (no cp1252 fallback)
python build_migration_workbook.py -i ".\out" -o "." --strict-json
```

Input folder is walked recursively; every `.json` file is considered. For each **ComputerName**, the script keeps the record with the latest **Metadata.CollectedAt**; then it builds one workbook from that set.

---

## GUI — gui_app.py

- **Input folder:** Folder that contains (or recursively contains) discovery JSON files. Use **Browse…** to pick it.
- **Output file:** Full path for the `.xlsx` workbook. Use **Browse…** to choose name and location. Required unless **Validate only** is checked (then a dummy path is used internally).
- **Options (checkboxes):**
  - **Emit sanitize report when issues found (--debug):** If validation finds issues, write a sanitize report CSV.
  - **Validate only (no Excel output):** Run validation only; do not write the workbook. Useful to check JSON/Excel compatibility without generating the file.
  - **Include SourceFile in every sheet:** Same as CLI `--include-sourcefile`.
  - **Fail fast (stop on first issue):** Same as CLI `--fail-fast`.
- **Run:** Starts the build in a background thread; progress bar and status show activity; log area shows messages.
- **Cancel:** Sets a cancel flag so the build can stop (may stop after the current sheet).

The GUI uses the same `build_workbook()` function as the CLI, so behavior (sanitization, validation, sheet set) is the same.

---

## Validation and sanitization

- **Illegal characters:** Control characters `\x00-\x08`, `\x0B`, `\x0C`, `\x0E-\x1F` are stripped or replaced before writing to Excel.
- **Formula injection:** Cell values that start with `=`, `+`, `-`, or `@` are escaped so Excel does not evaluate them as formulas.
- **Cell length:** Values longer than 32,767 characters are truncated (with a truncation marker). Preflight validation can report cell-length issues.
- **--validate-only:** Scans all sheets and reports issues (illegal chars, cell length, etc.) and exits non-zero if any are found.
- **--fail-fast:** Stops at the first problematic cell and exits with an error.
- **--debug / Emit sanitize report:** When issues exist, writes a CSV (e.g. `*_excel_sanitize_report.csv`) with sheet, row, column, issue kind, and source file.

---

## Packaging as a Windows EXE

You can build a **standalone Windows executable** so users can run the GUI without installing Python. Build must be done on **Windows** to produce a Windows EXE.

### Prerequisites (build machine)

- Windows
- Python 3.8+ with: `pip install pyinstaller pandas openpyxl PySide6`

### Build

From the **project root**:

```bat
python workbook-builder\build_exe.py
```

Or from **workbook-builder/**:

```bat
cd workbook-builder
python build_exe.py
```

Or run PyInstaller directly:

```bat
cd workbook-builder
python -m PyInstaller --noconfirm --distpath dist DomainMigrationBuilder.spec
```

**Output:** `dist/DomainMigrationBuilder.exe` (relative to the directory you ran the command from). You can copy this EXE to any Windows machine; it does not require Python.

### What is bundled

- `gui_app.py` (entry point)
- `build_migration_workbook.py` (engine)
- pandas, openpyxl, PySide6 and their dependencies

### Optional: icon and version

- **Icon:** Add `resources/DomainMigrationBuilder.ico` and in `DomainMigrationBuilder.spec` uncomment the `icon=...` line.
- **Version metadata:** Create `version_info.txt` (PyInstaller version-info format) and in the spec uncomment the `version=...` line.

### Clean rebuild

```bat
cd workbook-builder
pyinstaller --clean DomainMigrationBuilder.spec
```

For more detail, see [PACKAGING.md](../docs/PACKAGING.md) in the repo.

---

## Requirements

- **Python:** 3.8 or newer.
- **CLI only:** `pandas`, `openpyxl`.
- **GUI:** Above plus `PySide6`.
- **EXE build:** Windows, PyInstaller, and the same Python packages.

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| "No module named 'pandas'" (or openpyxl) | `pip install pandas openpyxl`. For GUI: `pip install PySide6`. |
| "No module named 'build_migration_workbook'" when running GUI | Run from the `workbook-builder/` folder so `gui_app.py` can import `build_migration_workbook`, or ensure that folder is on `PYTHONPATH`. |
| Empty or missing sheets | Ensure JSON files are from the domain-discovery script and contain the expected schema (Metadata, Detection, etc.). Older JSON may omit some sections; they will appear empty. |
| Validate-only reports issues | Fix source data or rely on sanitization (illegal chars removed, formulas escaped, truncation). Use --debug to get the report CSV and locate cells. |
| EXE won’t build | Run on Windows with Python 3.8+ and `pip install pyinstaller pandas openpyxl PySide6`; use `pyinstaller --clean DomainMigrationBuilder.spec` from `workbook-builder/` for a clean rebuild. |
| EXE fails at runtime | Test the same input folder with `python gui_app.py` first; if it works, the issue may be path or permissions when running the EXE. |

For end-to-end workflow (discovery → JSON → workbook), see the main [README](../README.md) and [domain-discovery](../domain-discovery/README.md).
