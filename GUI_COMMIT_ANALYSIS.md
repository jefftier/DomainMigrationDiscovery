# Deep Analysis: "Create a GUI" vs Main (c73acf4)

**Branch:** `Python-GUI` (one commit ahead of main)  
**Commit:** `662f2ba` — "Create a GUI"  
**Base:** `c73acf4` — "Stop tracking generated xlsx; ignore *.xlsx" (merge base with `main`)

---

## 1. What Changed (Summary)

| Change | Type | Files |
|--------|------|--------|
| New GUI + packaging | **Add** | `gui_app.py`, `build_exe.py`, `DomainMigrationBuilder.spec`, `PACKAGING.md` |
| Refactor for GUI/cancel/progress | **Modify** | `build_migration_workbook.py` |

**Overlap:** There is no duplicated business logic. The GUI commit **refactored** the workbook builder into a single entry point (`build_workbook()`) used by both the CLI (`main()`) and the GUI. So overlap is intentional: one implementation, two UIs.

---

## 2. Sanitization: Was Anything Removed?

**Short answer: No. Sanitization behavior was preserved and extended.**

### What stayed the same

- **`sanitize_for_excel()`** — Same behavior: strip illegal control chars `[\x00-\x08\x0B\x0C\x0E-\x1F]`, normalize newlines, formula escaping (`=`, `+`, `-`, `@`), truncation at 32,767 chars. Logic is unchanged; a `_sanitize_for_excel_track()` helper was added to return `(value, was_modified)` for warning counts.
- **Preflight validation** — Still runs before writing each sheet; fail-fast and sanitize report still work.
- **Report CSV** — Still written when `--debug` (CLI) or “Emit sanitize report” (GUI) is used; same path pattern `*_excel_sanitize_report.csv`.

### What was extended

- **Preflight now includes cell-length issues:**  
  Original only reported **illegal control characters**. The new code also detects **values longer than 32,767 characters** and reports them (e.g. `issue_kind="cell_length"`, `cell_length=N`). So validation is strictly broader.
- **Truncation suffix:** Changed from `"...TRUNCATED"` to Unicode ellipsis `"…TRUNCATED"` (cosmetic).
- **Fail-fast:** Now distinguishes illegal-control vs cell-length in the error message and raises `RuntimeError` instead of `sys.exit(1)` (CLI still exits 1 via `main()`).

### One intentional reduction in the report (not sanitization logic)

- **`computer_name` column removed from the sanitize/validation report CSV.**  
  Original: CSV had `computer_name` and `source_file`.  
  Current: CSV has `source_file` (and new columns `issue_kind`, `cell_length`).  
  You can still identify the machine via `source_file` (and the row’s sheet/column/row_index). So this is a reporting convenience change, not a change in what gets sanitized or written to Excel.

**Conclusion:** Core sanitization (illegal chars, newlines, formula escape, truncation) is unchanged; validation was extended (cell length); only the report column `computer_name` was dropped.

---

## 3. Removed or Regressed Functionality

### 3.1 Plant filter no longer applied to the workbook (regression)

- **Original (main):**  
  `load_latest_records(input_path, explicit_plant_id=args.plant_id, ...)`  
  So `-p / --plant-id` filtered which records were loaded and built.
- **Current:**  
  `build_workbook()` always calls `load_latest_records(..., explicit_plant_id=None)`.  
  The CLI still uses `args.plant_id` only for the **output filename** (e.g. `Plant1_MigrationDiscovery_20260205.xlsx`), but the workbook is built from **all** JSON in the input folder, not just that plant.

**Impact:** If you pass `-p PLANT1`, you still get a file named with PLANT1 but containing data from all plants. **Recommendation:** Add an `explicit_plant_id` (or `plant_id`) argument to `build_workbook()` and pass it through to `load_latest_records()`, and have the CLI pass `args.plant_id` into `build_workbook()`.

### 3.2 Stricter `--strict-json` (intentional change)

- **Original:** When `--strict-json` was set and the file was not valid UTF-8, the code skipped cp1252 fallback and printed a warning and returned `None` (skipped the file).
- **Current:** In that case the code **raises** `ValueError` and stops. So `--strict-json` now means “fail hard on non-UTF-8” instead of “skip and warn.” This is a behavior change, but it makes the flag meaning clearer.

### 3.3 Warnings when decode fails

- **Original:** When UTF-8 failed and `strict_json` was False, after a failed cp1252 attempt the code printed:  
  `"WARNING: Could not decode ... as UTF-8. Use --strict-json to avoid fallback."`  
  and returned `None`.
- **Current:** Logging goes through `log_cb`. When cp1252 decode fails we still log the exception via `_log(...)`, but the specific “Use --strict-json to avoid fallback” message is no longer printed. So one specific warning string was dropped; the failure is still reported.

---

## 4. Overlap With Main

- **No duplicated logic.** Main had a single linear flow in `main()`: load → build sheet rows → validate or write. The GUI commit moved that flow into `build_workbook()` and left `main()` as a thin CLI that builds the output path and calls `build_workbook()`. The same functions (`load_latest_records`, `flatten_record`, `find_excel_issues`, `write_excel`, `sanitize_for_excel`, etc.) are used once; there are no parallel implementations.
- **New code:** `CancelledError`, `BuildResult`, `build_workbook()`, and callback parameters (`cancel_event`, `progress_cb`, `log_cb`, `status_cb`) were added to support the GUI and cancel/progress. The CLI passes no-op or print-based callbacks and does not use cancel.

---

## 5. Recommendations

1. **Restore plant filter:** Add `plant_id: Optional[str] = None` (or `explicit_plant_id`) to `build_workbook()` and pass it into `load_latest_records()`. In `main()`, pass `args.plant_id` into `build_workbook()`. Optionally support plant filter in the GUI (e.g. optional plant dropdown or field).
2. **Optional:** Re-add the `computer_name` column to the sanitize/validation CSV if you want it for diagnostics (e.g. from the row’s `ComputerName` or `SourceFile`). The data is still available in the DataFrame at report-writing time.
3. **Optional:** In the cp1252-failure path, add back a `_log(...)` line that mentions “Use --strict-json to avoid fallback” so behavior and messaging align with the original.

---

## 6. Summary Table

| Area | Overlap with main? | Core functionality removed? | Notes |
|------|--------------------|------------------------------|--------|
| Sanitization logic | Same code path | **No** | Extended (cell-length checks); report lost `computer_name` column only. |
| Validation / fail-fast | Same code path | **No** | Stricter and more informative. |
| Plant filter | N/A | **Yes** | `-p` no longer filters data, only filename. |
| strict-json | Same flag | **No** (stricter) | Now raises instead of skip+warn. |
| Logging | Refactored to callbacks | Minor | One specific warning phrase dropped on decode failure. |

Overall, the only clear **regression** is the plant filter not being applied when building the workbook; the rest is refactor, extension, or intentional tightening.
