"""Unit and integration tests for build_migration_workbook sanitization and write_excel."""
import csv
import os
import sys
import tempfile
from collections import defaultdict

import pandas as pd

from build_migration_workbook import (
    MAX_EXCEL_CELL_LEN,
    ExcelIllegalIssue,
    find_illegal_excel_chars,
    load_latest_records,
    sanitize_for_excel,
    write_excel,
    write_sanitize_report_csv,
    _load_json_file,
)


class TestSanitizeForExcel:
    """Unit tests for sanitize_for_excel()."""

    def test_none_returns_none(self):
        assert sanitize_for_excel(None) is None

    def test_removes_null_control_char(self):
        assert sanitize_for_excel("Microsoft\x00P") == "MicrosoftP"

    def test_removes_multiple_control_chars(self):
        # \x01\x01\x00 should be removed from BXML\x01\x01\x00hosts
        assert sanitize_for_excel("BXML\x01\x01\x00hosts") == "BXMLhosts"

    def test_very_long_string_truncated_to_max_len(self):
        long_s = "a" * (MAX_EXCEL_CELL_LEN + 1000)
        result = sanitize_for_excel(long_s)
        assert len(result) <= MAX_EXCEL_CELL_LEN
        assert result.endswith("...TRUNCATED")

    def test_truncated_length_exactly_within_limit(self):
        long_s = "x" * (MAX_EXCEL_CELL_LEN + 500)
        result = sanitize_for_excel(long_s)
        assert len(result) == MAX_EXCEL_CELL_LEN
        assert result.endswith("...TRUNCATED")

    def test_string_starting_with_equals_prefixed_with_apostrophe(self):
        result = sanitize_for_excel("=1+1")
        assert result == "'=1+1"

    def test_string_starting_with_plus_prefixed(self):
        result = sanitize_for_excel("+A1")
        assert result == "'+A1"

    def test_string_starting_with_minus_prefixed(self):
        result = sanitize_for_excel("-1")
        assert result == "'-1"

    def test_string_starting_with_at_prefixed(self):
        result = sanitize_for_excel("@SUM(A1:A2)")
        assert result == "'@SUM(A1:A2)"

    def test_normal_string_unchanged(self):
        assert sanitize_for_excel("Normal text") == "Normal text"

    def test_newlines_normalized(self):
        result = sanitize_for_excel("a\r\nb\rc\n")
        assert result == "a\nb\nc\n"

    def test_dict_converted_to_json_then_sanitized(self):
        # json.dumps escapes control chars as \u0000; result is still sanitized (no literal \x00 in output)
        result = sanitize_for_excel({"x": 1, "y": "ab"})
        assert result == '{"x": 1, "y": "ab"}'

    def test_list_converted_to_json_then_sanitized(self):
        # list -> JSON string then sanitized (control chars in JSON are escaped by dumps)
        result = sanitize_for_excel([1, "ab"])
        assert result == '[1, "ab"]'

    def test_non_string_non_container_returned_asis(self):
        assert sanitize_for_excel(42) == 42
        assert sanitize_for_excel(3.14) == 3.14
        assert sanitize_for_excel(True) is True


class TestWriteExcelIntegration:
    """Integration test: write_excel with sanitized content does not raise."""

    def test_write_excel_with_illegal_chars_and_formulas_no_raise(self):
        sheet_rows = defaultdict(list)
        sheet_rows["Data"] = [
            {
                "ComputerName": "HOST1",
                "PlantId": "P1",
                "CollectedAt": "2025-02-01T12:00:00",
                "Notes": "Microsoft\x00P",
            },
            {
                "ComputerName": "HOST2",
                "PlantId": "P1",
                "CollectedAt": "2025-02-01T12:01:00",
                "Notes": "BXML\x01\x01\x00hosts",
            },
            {
                "ComputerName": "HOST3",
                "PlantId": "P1",
                "CollectedAt": "2025-02-01T12:02:00",
                "Notes": "=1+1",
            },
            {
                "ComputerName": "HOST4",
                "PlantId": "P1",
                "CollectedAt": "2025-02-01T12:03:00",
                "Notes": "x" * (MAX_EXCEL_CELL_LEN + 100),
            },
        ]
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            path = f.name
        try:
            write_excel(sheet_rows, path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


class TestFindIllegalExcelChars:
    """Tests for find_illegal_excel_chars and report content."""

    def test_finds_illegal_char_and_returns_correct_sheet_col_row(self):
        df = pd.DataFrame([
            {"ComputerName": "HOST1", "SourceFile": "/path/to/a.json", "Notes": "Microsoft\x00P"},
        ])
        issues = find_illegal_excel_chars(df, "Summary")
        assert len(issues) == 1
        i = issues[0]
        assert i.sheet_name == "Summary"
        assert i.column == "Notes"
        assert i.row_index == 0
        assert i.computer_name == "HOST1"
        assert i.source_file == "/path/to/a.json"
        assert i.illegal_count >= 1
        assert "0x0" in i.illegal_codepoints
        assert "Microsoft" in i.value_repr

    def test_report_csv_contains_sheet_col_row_and_source_file(self):
        sheet_rows = defaultdict(list)
        sheet_rows["Data"] = [
            {
                "ComputerName": "HOST1",
                "SourceFile": "results/host1.json",
                "PlantId": "P1",
                "CollectedAt": "2025-02-01T12:00:00",
                "Notes": "bad\x00value",
            },
        ]
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            xlsx_path = f.name
        report_path = xlsx_path.replace(".xlsx", "_excel_sanitize_report.csv")
        try:
            write_excel(
                sheet_rows, xlsx_path,
                fail_fast=False, report_path=report_path, emit_sanitize_report=True,
            )
            assert os.path.isfile(report_path)
            with open(report_path, newline="", encoding="utf-8") as fp:
                rows = list(csv.DictReader(fp))
            assert len(rows) == 1
            row = rows[0]
            assert row["sheet_name"] == "Data"
            assert row["column"] == "Notes"
            assert row["row_index"] == "0"
            assert row["row_display"] == "1"
            assert row["computer_name"] == "HOST1"
            assert row["source_file"] == "results/host1.json"
            assert "bad" in row["value_repr"]
            assert int(row["illegal_count"]) >= 1
        finally:
            for p in (xlsx_path, report_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_validate_only_exits_nonzero_when_issues_found(self):
        """With --validate-only, script exits non-zero if any illegal chars found."""
        import subprocess
        test_dir = os.path.join(os.path.dirname(__file__), "..")
        input_dir = os.path.join(test_dir, "test_input")
        # Ensure we have a JSON that yields a cell with \x00: use a file with \u0000 in JSON
        bad_json = os.path.join(input_dir, "bad_unicode.json")
        try:
            os.makedirs(input_dir, exist_ok=True)
            with open(bad_json, "w", encoding="utf-8") as f:
                f.write('{"Metadata": {"ComputerName": "BADHOST", "CollectedAt": "2025-01-01T00:00:00", "PlantId": "P1", "Notes": "text\\u0000here"}}')
            out_dir = tempfile.mkdtemp()
            report_path = os.path.join(out_dir, "excel_validate_report.csv")
            result = subprocess.run(
                [sys.executable, "-m", "build_migration_workbook", "-i", input_dir, "-o", out_dir, "--validate-only"],
                cwd=test_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 1
            assert os.path.isfile(report_path)
            with open(report_path, newline="", encoding="utf-8") as fp:
                rows = list(csv.DictReader(fp))
            assert len(rows) >= 1
            assert any("0x0" in r.get("illegal_codepoints", "") for r in rows)
        finally:
            if os.path.isfile(bad_json):
                os.unlink(bad_json)
            for f in os.listdir(out_dir):
                os.unlink(os.path.join(out_dir, f))
            os.rmdir(out_dir)


class TestJsonEncodingFallback:
    """Tests for JSON file encoding fallback (utf-8, utf-8-sig, cp1252) and --strict-json."""

    def test_cp1252_encoded_umlaut_loads_under_fallback_mode(self):
        """A file with cp1252-encoded umlaut text loads when strict_json is False."""
        import json as json_mod
        obj = {
            "Metadata": {
                "ComputerName": "CP1252Host",
                "CollectedAt": "2025-01-01T12:00:00",
                "PlantId": "P1",
            },
            "Note": "Grüße mit Umlaut äöü",
        }
        # Encode as UTF-8 string then encode that string's characters as cp1252 bytes
        content_utf8 = json_mod.dumps(obj, ensure_ascii=False)
        content_cp1252_bytes = content_utf8.encode("cp1252")
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".json", delete=False
        ) as f:
            f.write(content_cp1252_bytes)
            path = f.name
        try:
            result = _load_json_file(path, strict_json=False)
            assert result is not None
            assert result.get("Metadata", {}).get("ComputerName") == "CP1252Host"
            assert result.get("Note") == "Grüße mit Umlaut äöü"
        finally:
            os.unlink(path)

    def test_cp1252_file_fails_with_strict_json(self):
        """With strict_json=True, a cp1252-only file does not load (no fallback)."""
        import json as json_mod
        obj = {"Metadata": {"ComputerName": "X"}, "Note": "äöü"}
        content_utf8 = json_mod.dumps(obj, ensure_ascii=False)
        content_cp1252_bytes = content_utf8.encode("cp1252")
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
            f.write(content_cp1252_bytes)
            path = f.name
        try:
            result = _load_json_file(path, strict_json=True)
            assert result is None
        finally:
            os.unlink(path)

    def test_load_latest_records_includes_cp1252_file_when_not_strict(self):
        """Full load_latest_records with a cp1252 JSON in a folder loads it."""
        import json as json_mod
        obj = {
            "Metadata": {
                "ComputerName": "CP1252Host",
                "CollectedAt": "2025-01-01T12:00:00",
                "PlantId": "P1",
            },
        }
        content_cp1252 = json_mod.dumps(obj, ensure_ascii=False).encode("cp1252")
        tmpdir = tempfile.mkdtemp()
        json_path = os.path.join(tmpdir, "cp1252host.json")
        with open(json_path, "wb") as f:
            f.write(content_cp1252)
        try:
            records, plant_ids = load_latest_records(tmpdir, strict_json=False)
            assert len(records) == 1
            assert records[0]["computer_key"] == "CP1252Host"
        finally:
            os.unlink(json_path)
            os.rmdir(tmpdir)
