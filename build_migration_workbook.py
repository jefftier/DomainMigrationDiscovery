"""
Build migration discovery Excel workbook from JSON snapshots.

Internal note - JSON schema keys relevant to enhancements (Phase 0):
- Metadata: ComputerName, PlantId, CollectedAt, Version, Domain, OldDomainFqdn, NewDomainFqdn, OldDomainNetBIOS
- ApplicationConfigFiles: FilesWithDomainReferences, FilesWithCredentials (each file: FilePath, FileName, MatchedLines, TotalDomainMatches, CredentialPatterns, HasDomainReference, HasCredentials). MatchedLines = raw text; must be redacted.
- EventLogDomainReferences: list of { LogName, TimeCreated, Id, MessageSnippet }. MessageSnippet = raw text; must be redacted.
- SqlServer.ConfigFilesWithDomainReferences (per instance): MatchedLines = raw text; must be redacted.
- LocalAdministrators: list of { Name, SID, ObjectClass, PrincipalSource, IsGroup, IsDomain, Domain, Account, Source }
- LocalGroupMembers: list of { Group, Name, ObjectClass, PrincipalSource, SID }
- Detection.OldDomain, Detection.Summary, Detection.Summary.Counts
- New sections (this branch): Oracle, RDSLicensing; Config worksheets use ApplicationConfigFiles data.
"""
import csv
import os
import re
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, List, NamedTuple, Optional, Tuple

# Check Python version before heavier imports so we can show a clear message
if sys.version_info < (3, 8):
    print("This script requires Python 3.8 or newer.")
    print("Current version: {}".format(sys.version.split()[0]))
    print("Please update Python from https://www.python.org/downloads/ and try again.")
    sys.exit(1)

import json
import argparse
import datetime
from collections import defaultdict

# Minimum Python version required (3.8+ for datetime.fromisoformat behavior and modern pandas/openpyxl)
_REQUIRED_PYTHON_VERSION = (3, 8)


class CancelledError(Exception):
    """Raised when the build is cancelled via cancel_event."""


@dataclass
class BuildResult:
    """Result of build_workbook()."""

    workbook_path: Optional[str]
    report_path: Optional[str]
    warnings: int
    errors: int
    cancelled: bool


def _check_python_version():
    """Ensure Python version is sufficient; exit with a clear message if not."""
    if sys.version_info < _REQUIRED_PYTHON_VERSION:
        required_str = ".".join(map(str, _REQUIRED_PYTHON_VERSION))
        current_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        print("This script requires Python {} or newer.".format(required_str), file=sys.stderr)
        print("You are running Python {}.".format(current_str), file=sys.stderr)
        print(file=sys.stderr)
        print("Please update Python and try again.", file=sys.stderr)
        print("  - Windows: https://www.python.org/downloads/", file=sys.stderr)
        print("  - Check your version with: python --version", file=sys.stderr)
        sys.exit(1)


_check_python_version()

_REQUIRED_MODULES = [
    ("pandas", "pandas"),
    ("openpyxl", "openpyxl"),
]


def _check_dependencies():
    """Ensure required modules are installed; exit with a friendly message if not."""
    missing = []
    for _import_name, _pip_name in _REQUIRED_MODULES:
        try:
            __import__(_import_name)
        except ImportError:
            missing.append(_pip_name)
    if missing:
        print("This script requires the following Python packages to be installed:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print(file=sys.stderr)
        print("Install them with pip before running:", file=sys.stderr)
        print("  pip install " + " ".join(missing), file=sys.stderr)
        sys.exit(1)


_check_dependencies()
import pandas as pd  # noqa: E402

DEFAULT_INPUT_FOLDER = "results"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build a migration discovery Excel workbook from JSON snapshots."
    )
    parser.add_argument(
        "-i",
        "--input",
        default=DEFAULT_INPUT_FOLDER,
        help="Folder containing discovery JSON files (default: ./results)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Folder to write the Excel workbook into (default: current dir)",
    )
    parser.add_argument(
        "-p",
        "--plant-id",
        default=None,
        help="Optional PlantId to use for naming/filtering. "
             "If omitted, will infer from JSON Metadata.PlantId.",
    )
    parser.add_argument(
        "--include-sourcefile",
        action="store_true",
        default=False,
        dest="include_sourcefile",
        help="Include SourceFile (and SourceComputerKey, SourceSection) in every sheet for traceability. "
             "When off, provenance appears only in the Diagnostics sheet.",
    )
    parser.add_argument(
        "--debug-provenance",
        action="store_true",
        default=False,
        dest="debug_provenance",
        help="Alias for --include-sourcefile (include SourceFile in every sheet).",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Scan all sheets for Excel-illegal characters, emit report CSV, and do not write XLSX. "
             "Exits with non-zero status if any issues are found.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        default=False,
        help="Stop at the first sheet/cell with illegal characters and exit with a clear message.",
    )
    parser.add_argument(
        "--strict-json",
        action="store_true",
        default=False,
        help="Do not fall back to cp1252 for non-UTF-8 files; fail decode instead (for CI).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Emit sanitize report CSV when issues were found (sheet/row/col + source file).",
    )
    return parser.parse_args()


def safe_iso_parse(value):
    """Parse ISO8601 datetime, return datetime or None."""
    if not isinstance(value, str):
        return None
    try:
        # Python 3.11+ handles the .NET-style fractional seconds + offset
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def _load_json_file(
    fpath: str,
    strict_json: bool = False,
    log_cb: Optional[Callable[[str], None]] = None,
):
    """
    Load a JSON file with encoding fallback. Tries utf-8, then utf-8-sig.
    If decoding fails and not strict_json, falls back to cp1252 with errors="replace"
    and logs via log_cb. On JSON parse failure, logs file path, exception type, and
    a small excerpt around the error. Returns the parsed dict or None on any failure.
    """
    def _log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    content = None
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            with open(fpath, "r", encoding=encoding) as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            continue
    if content is None and strict_json:
        raise ValueError(
            f"Could not decode {fpath!r} as UTF-8. Use default encoding (omit --strict-json) or fix the file."
        )
    if content is None:
        try:
            with open(fpath, "r", encoding="cp1252", errors="replace") as f:
                content = f.read()
            _log(f"WARNING: Decoded {fpath} using cp1252 (replace); file was not valid UTF-8.")
        except Exception as e:
            _log(f"WARNING: Could not decode {fpath}: {type(e).__name__}: {e}")
            return None
    if content is None:
        return None

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        excerpt_len = 80
        start = max(0, e.pos - excerpt_len // 2)
        end = min(len(content), e.pos + excerpt_len // 2)
        excerpt = content[start:end]
        if start > 0:
            excerpt = "..." + excerpt
        if end < len(content):
            excerpt = excerpt + "..."
        excerpt_repr = repr(excerpt)
        _log(f"WARNING: JSON parse failed for {fpath}: {type(e).__name__}: {e}")
        _log(f"  Excerpt around error (pos={e.pos}): {excerpt_repr}")
        return None
    except Exception as e:
        _log(f"WARNING: JSON parse failed for {fpath}: {type(e).__name__}: {e}")
        return None


def load_latest_records(
    input_folder: str,
    explicit_plant_id: Optional[str] = None,
    strict_json: bool = False,
    cancel_event: Optional[threading.Event] = None,
    log_cb: Optional[Callable[[str], None]] = None,
):
    """
    Load all JSON files, group by ComputerName, and keep the latest snapshot
    (by Metadata.CollectedAt). Returns (records_with_provenance, plant_ids_seen).
    Optionally filter by PlantId if explicit_plant_id is provided.
    Raises CancelledError if cancel_event is set.

    Each record in records_with_provenance is a dict with:
      - computer_key: str
      - data: parsed JSON dict
      - path: str  (full file path of the source JSON; preserved for provenance/traceability)
    """
    latest_by_computer = {}
    plant_ids_seen = set()
    ev = cancel_event or threading.Event()

    for root, _, files in os.walk(input_folder):
        if ev.is_set():
            raise CancelledError()
        for fname in files:
            if ev.is_set():
                raise CancelledError()
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(root, fname)
            data = _load_json_file(fpath, strict_json=strict_json, log_cb=log_cb)
            if data is None:
                continue

            meta = data.get("Metadata", {}) or {}
            comp_name = meta.get("ComputerName") or os.path.splitext(fname)[0]
            plant_id = meta.get("PlantId") or ""
            collected_raw = meta.get("CollectedAt")
            collected_dt = safe_iso_parse(collected_raw)

            if explicit_plant_id and plant_id and plant_id != explicit_plant_id:
                continue

            if plant_id:
                plant_ids_seen.add(plant_id)

            existing = latest_by_computer.get(comp_name)
            if existing is None:
                latest_by_computer[comp_name] = {
                    "data": data,
                    "collected_dt": collected_dt,
                    "path": fpath,
                }
            else:
                prev_dt = existing.get("collected_dt")
                if prev_dt is None and collected_dt is None:
                    continue
                if prev_dt is None and collected_dt is not None:
                    latest_by_computer[comp_name] = {
                        "data": data,
                        "collected_dt": collected_dt,
                        "path": fpath,
                    }
                elif prev_dt is not None and collected_dt is not None:
                    if collected_dt > prev_dt:
                        latest_by_computer[comp_name] = {
                            "data": data,
                            "collected_dt": collected_dt,
                            "path": fpath,
                        }

    records_with_provenance = [
        {"computer_key": k, "data": v["data"], "path": v["path"]}
        for k, v in latest_by_computer.items()
    ]
    return records_with_provenance, plant_ids_seen


# Excel cell character limit (openpyxl/Excel)
MAX_EXCEL_CELL_LEN = 32767

# Truncation suffix (Unicode ellipsis)
_TRUNCATE_SUFFIX = "\u2026TRUNCATED"  # …TRUNCATED

# Control characters disallowed in Excel XML: \x00-\x08, \x0B, \x0C, \x0E-\x1F
_EXCEL_ILLEGAL_CONTROL_RE = None


def _get_excel_illegal_control_re():
    global _EXCEL_ILLEGAL_CONTROL_RE
    if _EXCEL_ILLEGAL_CONTROL_RE is None:
        _EXCEL_ILLEGAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
    return _EXCEL_ILLEGAL_CONTROL_RE


def _escape_excel_formula(value: str) -> str:
    """
    Prevent Excel formula injection: prefix string with apostrophe if it starts
    with =, +, -, or @ so the cell is treated as text, not a formula.
    """
    if not value:
        return value
    s = value.strip()
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def sanitize_for_excel(value: Any) -> Any:
    """
    Make a value safe for Excel/openpyxl: strip illegal control chars, normalize
    newlines, escape formula injection, truncate long strings. Prevents
    openpyxl.utils.exceptions.IllegalCharacterError.

    - None -> None
    - str: remove [\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F], normalize newlines to \\n,
      escape = + - @ at start, truncate to 32,767 chars and append '…TRUNCATED'
    - dict/list: json.dumps then sanitize the string
    - else: return value unchanged
    """
    out, _ = _sanitize_for_excel_track(value)
    return out


def _sanitize_for_excel_track(value: Any) -> Tuple[Any, bool]:
    """
    Same as sanitize_for_excel but returns (sanitized_value, was_modified).
    Used to count how many values were changed for BuildResult.warnings.
    """
    if value is None:
        return None, False
    if isinstance(value, str):
        re_illegal = _get_excel_illegal_control_re()
        s = re_illegal.sub("", value)
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        truncated = False
        if len(s) > MAX_EXCEL_CELL_LEN:
            s = s[: MAX_EXCEL_CELL_LEN - len(_TRUNCATE_SUFFIX)] + _TRUNCATE_SUFFIX
            truncated = True
        s = _escape_excel_formula(s)
        modified = s != value or truncated
        return s, modified
    if isinstance(value, (dict, list)):
        s = json.dumps(value, ensure_ascii=False)
        out, inner_modified = _sanitize_for_excel_track(s)
        return out, inner_modified
    return value, False


# Maximum length of value_repr in preflight report (first ~100 chars)
_PREFLIGHT_VALUE_REPR_MAX = 100


class ExcelPreflightIssue(NamedTuple):
    """
    One preflight issue: illegal control characters or value exceeding Excel cell length.
    Used for diagnostics report and fail-fast.
    """

    sheet_name: str
    column: str
    row_index: int  # 0-based
    value_repr: str  # repr of first ~100 chars
    source_file: Optional[str]
    issue_kind: str  # "illegal_control" | "cell_length"
    illegal_count: int  # 0 for cell_length issues
    illegal_codepoints: str  # "" for cell_length issues
    cell_length: int  # actual length when issue_kind=="cell_length"; 0 otherwise


def _string_for_validation(value):  # noqa: C901
    """Return string form of value for illegal-char/length check (str or json.dumps)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _get_source_file_from_row(df, row_index: int) -> Optional[str]:
    """Return SourceFile from row if column present."""
    if "SourceFile" not in df.columns:
        return None
    sf = df.iloc[row_index]["SourceFile"]
    if sf is None or (isinstance(sf, float) and pd.isna(sf)):
        return None
    return str(sf)


def find_excel_issues(df: Any, sheet_name: str) -> List[ExcelPreflightIssue]:
    """
    Preflight validation: detect issues BEFORE writing Excel.
    - Excel-illegal control characters [\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]
    - Values exceeding Excel cell length (32767)
    Returns list of issues with sheet_name, column, row_index, value_repr (~100 chars), SourceFile if present.
    """
    re_illegal = _get_excel_illegal_control_re()
    issues: List[ExcelPreflightIssue] = []
    has_source = "SourceFile" in df.columns

    for col in df.columns:
        if df[col].dtype != object:
            continue
        for row_index in range(len(df)):
            val = df.iloc[row_index][col]
            s = _string_for_validation(val)
            source_file = _get_source_file_from_row(df, row_index) if has_source else None
            sample = s[:_PREFLIGHT_VALUE_REPR_MAX]
            if len(s) > _PREFLIGHT_VALUE_REPR_MAX:
                sample += "..."
            value_repr = repr(sample)

            # 1) Excel-illegal control characters
            matches = re_illegal.findall(s)
            if matches:
                illegal_count = len(matches)
                codepoints = ",".join(sorted(set(hex(ord(m)) for m in matches)))
                issues.append(
                    ExcelPreflightIssue(
                        sheet_name=sheet_name,
                        column=col,
                        row_index=row_index,
                        value_repr=value_repr,
                        source_file=source_file,
                        issue_kind="illegal_control",
                        illegal_count=illegal_count,
                        illegal_codepoints=codepoints,
                        cell_length=0,
                    )
                )

            # 2) Value exceeding Excel cell length
            if len(s) > MAX_EXCEL_CELL_LEN:
                issues.append(
                    ExcelPreflightIssue(
                        sheet_name=sheet_name,
                        column=col,
                        row_index=row_index,
                        value_repr=value_repr,
                        source_file=source_file,
                        issue_kind="cell_length",
                        illegal_count=0,
                        illegal_codepoints="",
                        cell_length=len(s),
                    )
                )

    return issues


def write_sanitize_report_csv(
    issues: List[ExcelPreflightIssue], report_path: str
) -> None:
    """Write preflight issues to <output>_excel_sanitize_report.csv."""
    if not issues:
        return
    with open(report_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "sheet_name", "column", "row_index", "row_display",
            "source_file", "value_repr", "issue_kind",
            "illegal_count", "illegal_codepoints", "cell_length",
        ])
        for i in issues:
            w.writerow([
                i.sheet_name,
                i.column,
                i.row_index,
                i.row_index + 1,
                i.source_file or "",
                i.value_repr,
                i.issue_kind,
                i.illegal_count,
                i.illegal_codepoints,
                i.cell_length,
            ])


def filter_search_criteria_fields(row_dict, section_name=None):
    """
    Remove search criteria and anecdotal fields, keeping only output data.
    Search criteria fields indicate HOW something was found, not WHAT was found.
    """
    if not isinstance(row_dict, dict):
        return row_dict
    
    # Fields to remove (search criteria/anecdotal, not output data)
    fields_to_remove = [
        # Detection/search criteria fields
        "MatchedField",
        "MatchedFields",
        "DetectionMethod",
        "EvidenceType",
        "LocationType",  # When used for detection method, not actual location
        # Encase search criteria
        "ServiceName",  # Only for Encase - it's the search criteria, not output
    ]
    
    # Create filtered copy
    filtered = {}
    for k, v in row_dict.items():
        # Remove search criteria fields
        if k in fields_to_remove:
            continue
        # For Encase specifically, also check prefixed field names
        if section_name == "SecurityAgents" and k.startswith("Encase_") and k.endswith("_ServiceName"):
            continue
        filtered[k] = v
    
    return filtered


def add_row(sheet_rows, sheet_name, row_dict, include_source_section=False):
    """
    Append a row (dict) to the given sheet name in the rows dict.
    Filters out search criteria fields before adding.
    If include_source_section is True (e.g. for --debug-provenance), add SourceSection = sheet_name to the row.
    """
    if row_dict is None:
        return
    # Filter out search criteria fields
    filtered_row = filter_search_criteria_fields(row_dict, sheet_name)
    if include_source_section:
        filtered_row["SourceSection"] = sheet_name
    sheet_rows[sheet_name].append(filtered_row)


def parse_account_identity(account_identity):
    """
    Parse AccountIdentity object to extract account information.
    Returns dict with: Name, Domain, Type, IsOldDomain, IsDomainAccount
    """
    if not isinstance(account_identity, dict):
        return {}
    result = {}
    result["AccountName"] = account_identity.get("Name") or account_identity.get("Raw")
    result["AccountDomain"] = account_identity.get("Domain")
    result["AccountType"] = account_identity.get("Type")
    result["IsOldDomainAccount"] = account_identity.get("IsOldDomain", False)
    # Determine if it's a domain account (has domain and not built-in)
    domain = result.get("AccountDomain", "").strip()
    account_type = result.get("AccountType", "").lower()
    result["IsDomainAccount"] = bool(domain and account_type not in ("builtin", "wellknown"))
    return result


def flatten_record(computer_name, record, sheet_rows, source_file=None, source_computer_key=None, debug_provenance=False):
    """
    Flatten a single JSON record into multiple sheet rows.

    - Adds rows into sheet_rows[...] for sections:
      Summary (first for quick overview), Metadata, System, Profiles,
      SharedFolders_Shares, SharedFolders_Errors, InstalledApps, Services,
      ScheduledTasks, LocalGroupMembers, LocalAdministrators, MappedDrives,
      Printers, OdbcDsn, AutoAdminLogon, CredentialManager, Certificates,
      FirewallRules, DnsSummary, DnsSuffixSearchList, DnsAdapters, IIS,
      SqlServer, EventLogDomainReferences, ApplicationConfigFiles,
      SecurityAgents, ServiceAccountCandidates.

    - source_file: path to the JSON file this record came from (for provenance).
    - source_computer_key: dict key used (computer name from dedup); may differ from Metadata.ComputerName.
    - debug_provenance: if True, add SourceFile, SourceComputerKey (and SourceSection in add_row) to every row.
    """
    meta = record.get("Metadata", {}) or {}
    system = record.get("System", {}) or {}

    # Base row - only include domain info in Metadata tab
    # For other tabs, only include domain info if it's specific to that line
    base = {
        "ComputerName": meta.get("ComputerName", computer_name),
        "PlantId": meta.get("PlantId"),
        "CollectedAt": meta.get("CollectedAt"),
        "ScriptVersion": meta.get("Version"),
    }
    if debug_provenance:
        base["SourceFile"] = source_file or ""
        base["SourceComputerKey"] = source_computer_key or computer_name
    
    # Store domain info separately for use where needed
    old_domain_fqdn = meta.get("OldDomainFqdn")
    old_domain_netbios = meta.get("OldDomainNetBIOS")
    new_domain_fqdn = meta.get("NewDomainFqdn")
    current_domain = meta.get("Domain")

    # --- Detection Summary (create first for quick overview) ---
    detection = record.get("Detection") or {}
    detection_flags = detection.get("OldDomain") or {}
    summary = detection.get("Summary") or {}
    counts = summary.get("Counts") or {}
    
    # Get SecurityAgents info for summary
    sec = record.get("SecurityAgents") or {}
    crowdstrike = sec.get("CrowdStrike") or {}
    qualys = sec.get("Qualys") or {}
    sccm = sec.get("SCCM") or {}
    encase = sec.get("Encase") or {}

    # Count potential service accounts from all sources (for summary)
    # This is a quick count - detailed extraction happens later in ServiceAccountCandidates
    def count_non_builtin_accounts(source_list, account_field, account_identity_field=None):
        """Count non-built-in accounts from a source list."""
        count = 0
        if not source_list:
            return count
        if isinstance(source_list, dict):
            source_list = [source_list]
        if not isinstance(source_list, list):
            return count
        
        for item in source_list:
            if not isinstance(item, dict):
                continue
            account_value = item.get(account_field) or ""
            account_identity = item.get(account_identity_field) if account_identity_field else None
            
            if account_identity and isinstance(account_identity, dict):
                account_value = account_identity.get("Raw") or account_identity.get("Name") or account_value
            
            if not account_value or not isinstance(account_value, str):
                continue
            
            account_lower = account_value.lower().strip()
            if account_lower and not (
                account_lower in ("localsystem", "localservice", "networkservice")
                or account_lower.startswith("nt authority\\")
                or account_lower.startswith("nt service\\")
                or account_lower.startswith(".\\")
            ):
                count += 1
        return count
    
    # Count from all sources
    services = record.get("Services") or []
    tasks = record.get("ScheduledTasks") or []
    iis = record.get("IIS") or {}
    sql_server = record.get("SqlServer")
    local_admins = record.get("LocalAdministrators") or []
    local_groups = record.get("LocalGroupMembers") or []
    cred_mgr = record.get("CredentialManager") or []
    
    potential_service_account_count = (
        count_non_builtin_accounts(services, "StartName", "AccountIdentity")
        + count_non_builtin_accounts(services, "Account", "AccountIdentity")
        + count_non_builtin_accounts(tasks, "UserId", "AccountIdentity")
        + count_non_builtin_accounts(iis.get("AppPools") or [], "IdentityUser", "AccountIdentity")
        + count_non_builtin_accounts(
            [lg for lg in (local_admins if isinstance(local_admins, list) else [local_admins]) 
             if isinstance(lg, dict) and lg.get("Type") == "Domain"],
            "Name"
        )
    )
    
    # Count SQL Server domain logins
    if sql_server:
        sql_instances = sql_server if isinstance(sql_server, list) else [sql_server]
        for instance in sql_instances:
            if isinstance(instance, dict):
                domain_logins = instance.get("DomainLogins") or []
                for login in domain_logins:
                    if isinstance(login, dict) and login.get("LoginType") in ("WindowsUser", "WindowsGroup"):
                        potential_service_account_count += 1
    
    # Count local group members (domain accounts)
    if isinstance(local_groups, dict):
        local_groups = [local_groups]
    for group in local_groups:
        if isinstance(group, dict):
            members = group.get("Members") or []
            for member in members:
                if isinstance(member, dict) and member.get("PrincipalSource") == "ActiveDirectory":
                    potential_service_account_count += 1
    
    # Count credential manager entries (domain accounts)
    # Use the same logic as extraction to ensure consistency
    for cred in (cred_mgr if isinstance(cred_mgr, list) else [cred_mgr]):
        if isinstance(cred, dict):
            user_name = cred.get("UserName")
            account_identity = cred.get("AccountIdentity")
            # Use parse_account_identity to derive IsDomainAccount (same as extraction logic)
            # This matches the logic in extract_account_info used during extraction
            if isinstance(account_identity, dict):
                account_info = parse_account_identity(account_identity)
                if account_info.get("IsDomainAccount"):
                    potential_service_account_count += 1
            elif user_name and isinstance(user_name, str):
                # Parse account value format: DOMAIN\User indicates domain account
                user_name = user_name.strip()
                if "\\" in user_name:
                    # Has domain prefix, treat as domain account
                    potential_service_account_count += 1

    row_det = base.copy()
    row_det["HasOldDomainRefs"] = summary.get("HasOldDomainRefs")
    row_det["PotentialServiceAccounts"] = potential_service_account_count
    
    # Add security agent status information (output data only, no issue flags)
    row_det["CrowdStrike_Tenant"] = crowdstrike.get("Tenant")
    row_det["Qualys_Tenant"] = qualys.get("Tenant")
    row_det["SCCM_Tenant"] = sccm.get("Tenant")
    row_det["SCCM_HasDomainReference"] = sccm.get("HasDomainReference", False)
    
    # Parse SCCM AllowedMPs if available in DomainReferences
    sccm_allowed_mps = None
    sccm_allowed_mp_domains = []
    if sccm.get("DomainReferences"):
        for ref in sccm.get("DomainReferences", []):
            if isinstance(ref, dict) and ref.get("ValueName") == "AllowedMPs":
                sccm_allowed_mps = ref.get("Value")
                # Parse AllowedMPs value to extract domain FQDNs
                if sccm_allowed_mps and isinstance(sccm_allowed_mps, str):
                    # AllowedMPs is typically a semicolon-separated list of MP URLs
                    # Format: https://mp1.domain.com/CCM_Proxy_MutualAuth/72057594037927939
                    # Extract domain FQDNs from URLs
                    domain_pattern = r'https?://([^/:\s]+)'
                    matches = re.findall(domain_pattern, sccm_allowed_mps)
                    for match in matches:
                        # Remove port if present and clean up
                        domain = match.split(':')[0].strip()
                        if domain and domain not in [d.split(' (')[0] for d in sccm_allowed_mp_domains]:
                            # Check if it matches old or new domain
                            domain_lower = domain.lower()
                            domain_display = domain
                            if old_domain_fqdn and domain_lower == old_domain_fqdn.lower():
                                domain_display = f"{domain} (OldDomain)"
                            elif new_domain_fqdn and domain_lower == new_domain_fqdn.lower():
                                domain_display = f"{domain} (NewDomain)"
                            sccm_allowed_mp_domains.append(domain_display)
                break
    
    if sccm_allowed_mps:
        row_det["SCCM_AllowedMPs"] = sccm_allowed_mps
    if sccm_allowed_mp_domains:
        row_det["SCCM_AllowedMPDomains"] = "; ".join(sccm_allowed_mp_domains)
    
    row_det["Encase_Installed"] = encase.get("Installed", False)
    row_det["Encase_Tenant"] = encase.get("Tenant")

    # SQL / Oracle / RDS presence (always listed regardless of domain)
    row_det["SqlServerInstalled"] = record.get("SqlServerInstalled", False)
    row_det["SqlServerVersion"] = record.get("SqlServerVersion")
    _ora = record.get("Oracle")
    # Summary indicates only if machine is likely an Oracle DB server (not just ODBC/client)
    row_det["IsOracleServerLikely"] = _ora.get("IsOracleServerLikely", False) if isinstance(_ora, dict) else False
    row_det["OracleVersion"] = _ora.get("OracleVersion") if isinstance(_ora, dict) else None
    _rds = record.get("RDSLicensing")
    row_det["RdsLicensingRoleInstalled"] = _rds.get("RdsLicensingRoleInstalled", False) if isinstance(_rds, dict) else False

    for k, v in counts.items():
        # Prefix with Count_ to make it obvious in Excel
        col_name = f"Count_{k}"
        row_det[col_name] = v

    add_row(sheet_rows, "Summary", row_det, include_source_section=debug_provenance)

    # --- Metadata (one row per computer) ---
    # Metadata tab should include all domain info for reference
    row_meta = base.copy()
    row_meta["Domain"] = current_domain
    row_meta["OldDomainFqdn"] = old_domain_fqdn
    row_meta["OldDomainNetBIOS"] = old_domain_netbios
    row_meta["NewDomainFqdn"] = new_domain_fqdn
    # Include all metadata fields explicitly
    for k, v in meta.items():
        if k not in row_meta:
            row_meta[k] = v
    add_row(sheet_rows, "Metadata", row_meta, include_source_section=debug_provenance)

    # --- System (one row per computer) ---
    row_sys = base.copy()
    row_sys.update(system)
    add_row(sheet_rows, "System", row_sys, include_source_section=debug_provenance)

    # Helper to flatten simple list-of-dict arrays
    def flatten_list_section(section_name):
        items = record.get(section_name)
        if not items:
            return
        if isinstance(items, dict):
            # Some sections might be a single dict instead of list
            items = [items]
        if not isinstance(items, list):
            return
        for entry in items:
            if not isinstance(entry, dict):
                entry = {"Value": entry}
            row = base.copy()
            row.update(entry)
            # Add helper columns for sections that might have domain references
            if section_name in ("MappedDrives", "OdbcDsn", "CredentialManager", 
                               "Certificates", "LocalAdministrators", "LocalGroupMembers"):
                # Check if entry has HasDomainReference or IsOldDomain flags
                if "HasDomainReference" not in row and "HasOldDomainReference" not in row:
                    # Try to infer from AccountIdentity if present
                    account_identity = entry.get("AccountIdentity")
                    if isinstance(account_identity, dict):
                        row["IsOldDomainAccount"] = account_identity.get("IsOldDomain", False)
                        row["NeedsAttention"] = row["IsOldDomainAccount"]
            add_row(sheet_rows, section_name, row, include_source_section=debug_provenance)

    # --- Simple list sections with enhanced processing ---
    # Services: Add helper columns for old domain detection
    services_list = record.get("Services") or []
    if isinstance(services_list, dict):
        services_list = [services_list]
    services_run_as_old = set(detection_flags.get("ServicesRunAsOldDomain") or [])
    services_path_old = set(detection_flags.get("ServicesOldPathRefs") or [])
    
    for svc in services_list:
        if not isinstance(svc, dict):
            continue
        row = base.copy()
        row.update(svc)
        # Fix: Use State not Status
        if "Status" in row and "State" not in row:
            row["State"] = row.pop("Status")
        # Add helper columns
        service_name = svc.get("Name") or svc.get("ServiceName")
        row["HasOldDomainAccount"] = service_name in services_run_as_old
        row["HasOldDomainPath"] = service_name in services_path_old
        row["NeedsAttention"] = row["HasOldDomainAccount"] or row["HasOldDomainPath"]
        add_row(sheet_rows, "Services", row, include_source_section=debug_provenance)
    
    # ScheduledTasks: Add helper columns
    tasks_list = record.get("ScheduledTasks") or []
    if isinstance(tasks_list, dict):
        tasks_list = [tasks_list]
    tasks_old_accounts = set(detection_flags.get("ScheduledTasksWithOldAccounts") or [])
    tasks_old_actions = set(detection_flags.get("ScheduledTasksWithOldActionRefs") or [])
    
    for task in tasks_list:
        if not isinstance(task, dict):
            continue
        row = base.copy()
        row.update(task)
        task_path = task.get("Path") or task.get("TaskName")
        row["HasOldDomainAccount"] = task_path in tasks_old_accounts
        row["HasOldDomainAction"] = task_path in tasks_old_actions
        row["NeedsAttention"] = row["HasOldDomainAccount"] or row["HasOldDomainAction"]
        add_row(sheet_rows, "ScheduledTasks", row, include_source_section=debug_provenance)
    
    # Other simple list sections
    # --- Local Admin Membership: one row per (ComputerName, Administrators, member) ---
    local_admins_list = record.get("LocalAdministrators") or []
    if isinstance(local_admins_list, dict):
        local_admins_list = [local_admins_list]
    for admin in local_admins_list:
        if not isinstance(admin, dict):
            continue
        row_lam = base.copy()
        row_lam["GroupName"] = "Administrators"
        row_lam["MemberName"] = admin.get("Name")
        row_lam["MemberType"] = admin.get("ObjectClass")
        row_lam["DomainOrScope"] = admin.get("Domain")
        row_lam["SID"] = admin.get("SID")
        row_lam["Source"] = admin.get("Source")
        add_row(sheet_rows, "Local Admin Membership", row_lam, include_source_section=debug_provenance)
    # If no local admins collected (e.g. error), still add one row per computer so every computer appears
    if not local_admins_list:
        row_lam = base.copy()
        row_lam["GroupName"] = "Administrators"
        row_lam["MemberName"] = None
        row_lam["MemberType"] = None
        row_lam["DomainOrScope"] = None
        row_lam["SID"] = None
        row_lam["Source"] = "Not collected or error"
        add_row(sheet_rows, "Local Admin Membership", row_lam, include_source_section=debug_provenance)

    for section in [
        "Profiles",
        "InstalledApps",
        "LocalGroupMembers",
        "LocalAdministrators",
        "MappedDrives",
        "OdbcDsn",
        "CredentialManager",
        "Certificates",
        "FirewallRules",
        "EventLogDomainReferences",
    ]:
        flatten_list_section(section)

    # --- SharedFolders (Shares + Errors) ---
    shared = record.get("SharedFolders") or {}
    shares = shared.get("Shares") or []
    errors = shared.get("Errors") or []

    for share in shares:
        row = base.copy()
        if isinstance(share, dict):
            row.update(share)
        else:
            row["Share"] = share
        
        # Check Identity field for domain references and accounts of interest
        identity = share.get("Identity") if isinstance(share, dict) else None
        if identity:
            identity_str = str(identity)
            # Check for domain references
            has_domain_ref = False
            is_old_domain = False
            is_domain_account = False
            
            if "\\" in identity_str:
                is_domain_account = True
                parts = identity_str.split("\\", 1)
                if len(parts) == 2:
                    domain_part = parts[0].lower()
                    old_fqdn_lower = (old_domain_fqdn or "").lower()
                    old_netbios_lower = (old_domain_netbios or "").lower()
                    new_fqdn_lower = (new_domain_fqdn or "").lower()
                    
                    if domain_part == old_fqdn_lower or domain_part == old_netbios_lower:
                        has_domain_ref = True
                        is_old_domain = True
                    elif domain_part == new_fqdn_lower:
                        has_domain_ref = True
            
            row["HasDomainReference"] = has_domain_ref
            row["IsOldDomainAccount"] = is_old_domain
            row["IsDomainAccount"] = is_domain_account
            row["NeedsAttention"] = is_old_domain  # Flag old domain accounts for attention
        
        add_row(sheet_rows, "SharedFolders_Shares", row, include_source_section=debug_provenance)

    for err in errors:
        row = base.copy()
        if isinstance(err, dict):
            row.update(err)
        else:
            row["Error"] = err
        add_row(sheet_rows, "SharedFolders_Errors", row, include_source_section=debug_provenance)

    # --- Printers: can be dict or list ---
    printers = record.get("Printers")
    printers_to_old = set(detection_flags.get("PrintersToOldDomain") or [])
    
    if printers:
        if isinstance(printers, list):
            for prn in printers:
                row = base.copy()
                if isinstance(prn, dict):
                    row.update(prn)
                else:
                    row["Printer"] = prn
                printer_name = row.get("Name")
                row["HasOldDomainReference"] = printer_name in printers_to_old
                row["NeedsAttention"] = row["HasOldDomainReference"]
                add_row(sheet_rows, "Printers", row, include_source_section=debug_provenance)
        elif isinstance(printers, dict):
            row = base.copy()
            row.update(printers)
            printer_name = row.get("Name")
            row["HasOldDomainReference"] = printer_name in printers_to_old
            row["NeedsAttention"] = row["HasOldDomainReference"]
            add_row(sheet_rows, "Printers", row, include_source_section=debug_provenance)

    # --- AutoAdminLogon: single object ---
    auto = record.get("AutoAdminLogon")
    if auto:
        row = base.copy()
        if isinstance(auto, dict):
            row.update(auto)
        else:
            row["Value"] = auto
        add_row(sheet_rows, "AutoAdminLogon", row, include_source_section=debug_provenance)

    # --- DNS Configuration ---
    dns = record.get("DnsConfiguration") or {}
    if dns:
        # Suffix search list - simplified to only show suffix
        for suffix in dns.get("SuffixSearchList") or []:
            row = base.copy()
            row["Suffix"] = suffix
            add_row(sheet_rows, "DnsSuffixSearchList", row, include_source_section=debug_provenance)

        # Adapters
        adapters = dns.get("Adapters") or []
        for adapter in adapters:
            row = base.copy()
            if isinstance(adapter, dict):
                row.update(adapter)
            else:
                row["Adapter"] = adapter
            add_row(sheet_rows, "DnsAdapters", row, include_source_section=debug_provenance)

    # --- IIS & SqlServer: store raw JSON per machine for now ---
    iis = record.get("IIS")
    if iis is not None:
        row = base.copy()
        row["RawJson"] = json.dumps(iis, ensure_ascii=False)
        add_row(sheet_rows, "IIS", row, include_source_section=debug_provenance)

    # SqlServer: always one row with Installed + Version; RawJson when detail present
    row_sql = base.copy()
    row_sql["SqlServerInstalled"] = record.get("SqlServerInstalled", False)
    row_sql["SqlServerVersion"] = record.get("SqlServerVersion")
    sql = record.get("SqlServer")
    if sql is not None:
        row_sql["RawJson"] = json.dumps(sql, ensure_ascii=False)
    add_row(sheet_rows, "SqlServer", row_sql, include_source_section=debug_provenance)

    # --- RDS Licensing (one row per computer; always list) ---
    rds = record.get("RDSLicensing")
    row_rds = base.copy()
    if rds is not None and isinstance(rds, dict):
        row_rds["IsRDSSessionHost"] = rds.get("IsRDSSessionHost", False)
        row_rds["RDSRoleInstalled"] = rds.get("RDSRoleInstalled")
        row_rds["RdsLicensingRoleInstalled"] = rds.get("RdsLicensingRoleInstalled", False)
        row_rds["LicensingMode"] = rds.get("LicensingMode", "Unknown")
        row_rds["LicenseServerConfigured"] = "; ".join(rds.get("LicenseServerConfigured") or [])
        row_rds["RDSLicensingEvidence"] = "; ".join(rds.get("RDSLicensingEvidence") or [])
        row_rds["IsRDSLicensingLikelyInUse"] = rds.get("IsRDSLicensingLikelyInUse", False)
        row_rds["Errors"] = "; ".join(rds.get("Errors") or []) if rds.get("Errors") else ""
    else:
        row_rds["IsRDSSessionHost"] = False
        row_rds["RDSRoleInstalled"] = None
        row_rds["RdsLicensingRoleInstalled"] = False
        row_rds["LicensingMode"] = "Unknown"
        row_rds["LicenseServerConfigured"] = ""
        row_rds["RDSLicensingEvidence"] = ""
        row_rds["IsRDSLicensingLikelyInUse"] = False
        row_rds["Errors"] = ""
    add_row(sheet_rows, "RDS Licensing", row_rds, include_source_section=debug_provenance)

    # --- Oracle discovery (Summary + Details; always one row per computer) ---
    oracle = record.get("Oracle")
    row_ora_sum = base.copy()
    row_ora_sum["OracleInstalled"] = False
    row_ora_sum["OracleVersion"] = None
    row_ora_sum["IsOracleServerLikely"] = False
    row_ora_sum["OracleClientInstalled"] = False
    row_ora_sum["OracleHomesCount"] = 0
    row_ora_sum["OracleServicesCount"] = 0
    row_ora_sum["OracleODBCDriversCount"] = 0
    row_ora_sum["TnsnamesFilesCount"] = 0
    row_ora_sum["OracleHomes"] = ""
    row_ora_sum["OracleODBCDrivers"] = ""
    row_ora_sum["Errors"] = ""
    if oracle is not None and isinstance(oracle, dict):
        row_ora_sum["OracleInstalled"] = oracle.get("OracleInstalled", False)
        row_ora_sum["OracleVersion"] = oracle.get("OracleVersion")
        row_ora_sum["IsOracleServerLikely"] = oracle.get("IsOracleServerLikely", False)
        row_ora_sum["OracleClientInstalled"] = oracle.get("OracleClientInstalled", False)
        row_ora_sum["OracleHomesCount"] = len(oracle.get("OracleHomes") or [])
        row_ora_sum["OracleServicesCount"] = len(oracle.get("OracleServices") or [])
        row_ora_sum["OracleODBCDriversCount"] = len(oracle.get("OracleODBCDrivers") or [])
        row_ora_sum["TnsnamesFilesCount"] = len(oracle.get("TnsnamesFiles") or [])
        row_ora_sum["OracleHomes"] = "; ".join(oracle.get("OracleHomes") or [])[:500]
        row_ora_sum["OracleODBCDrivers"] = "; ".join(oracle.get("OracleODBCDrivers") or [])
        row_ora_sum["Errors"] = "; ".join(oracle.get("Errors") or []) if oracle.get("Errors") else ""
    add_row(sheet_rows, "Oracle Summary", row_ora_sum, include_source_section=debug_provenance)
    if oracle is not None and isinstance(oracle, dict):
        for svc in oracle.get("OracleServices") or []:
            if isinstance(svc, dict):
                row_svc = base.copy()
                row_svc["ServiceName"] = svc.get("Name")
                row_svc["DisplayName"] = svc.get("DisplayName")
                row_svc["Status"] = svc.get("Status")
                row_svc["StartType"] = svc.get("StartType")
                add_row(sheet_rows, "Oracle Details", row_svc, include_source_section=debug_provenance)

    # --- ApplicationConfigFiles: raw row + Config File Findings + Config Summary ---
    app_cfg = record.get("ApplicationConfigFiles")
    if app_cfg is not None:
        row = base.copy()
        if isinstance(app_cfg, dict):
            for k, v in app_cfg.items():
                if not isinstance(v, (list, dict)):
                    row[k] = v
            row["RawJson"] = json.dumps(app_cfg, ensure_ascii=False)
        else:
            row["RawJson"] = json.dumps(app_cfg, ensure_ascii=False)
        add_row(sheet_rows, "ApplicationConfigFiles", row, include_source_section=debug_provenance)

        # Config File Findings: one row per machine per file finding (readable in Excel)
        if isinstance(app_cfg, dict):
            files_with_refs = app_cfg.get("FilesWithDomainReferences") or []
            files_with_creds = app_cfg.get("FilesWithCredentials") or []
            if not isinstance(files_with_refs, list):
                files_with_refs = [files_with_refs] if files_with_refs else []
            if not isinstance(files_with_creds, list):
                files_with_creds = [files_with_creds] if files_with_creds else []
            # Merge by file path: collect all file entries (path -> combined info)
            by_path = {}
            for f in files_with_refs + files_with_creds:
                if not isinstance(f, dict):
                    continue
                path = f.get("FilePath") or f.get("FileName") or ""
                if not path:
                    continue
                ext = os.path.splitext(path)[1] if path else ""
                matched_lines = list(f.get("MatchedLines") or [])
                match_count = f.get("TotalDomainMatches") or len(matched_lines)
                has_creds = f.get("HasCredentials", False)
                cred_patterns = f.get("CredentialPatterns") or []
                matched_tokens = "; ".join(str(p) for p in cred_patterns[:10]) if isinstance(cred_patterns, list) else (str(cred_patterns) if cred_patterns else "")
                if path in by_path:
                    existing = by_path[path]
                    existing_lines = existing.get("_lines") or []
                    existing_lines = list(dict.fromkeys(existing_lines + [str(x) for x in matched_lines]))
                    match_count = max(match_count, existing.get("MatchCount", 0), len(existing_lines))
                    has_creds = has_creds or existing.get("HasCredentialIndicators", False)
                    matched_lines = existing_lines
                    if (existing.get("MatchedTokens") or "") and matched_tokens:
                        matched_tokens = (existing.get("MatchedTokens") or "") + "; " + matched_tokens
                cap_lines = 10
                lines_redacted = "\n".join(str(x) for x in matched_lines[:cap_lines])
                if len(matched_lines) > cap_lines:
                    lines_redacted += "\n...TRUNCATED"
                # Sanitize for Excel (MatchedLines can contain binary-ish content)
                lines_redacted = sanitize_for_excel(lines_redacted)
                by_path[path] = {
                    "FilePath": path,
                    "Extension": ext,
                    "MatchCount": match_count,
                    "HasCredentialIndicators": has_creds,
                    "OldDomainIndicator": f.get("HasDomainReference", False),
                    "MatchedTokens": matched_tokens,
                    "MatchedLinesRedacted": lines_redacted,
                    "_lines": matched_lines,
                }
            for _path, info in by_path.items():
                row_cfg = base.copy()
                row_cfg.update({k: v for k, v in info.items() if k != "_lines"})
                add_row(sheet_rows, "Config File Findings", row_cfg, include_source_section=debug_provenance)

            # Config Summary: one row per computer
            total_files = len(by_path)
            total_hits = sum(info.get("MatchCount", 0) for info in by_path.values())
            cred_flagged = sum(1 for info in by_path.values() if info.get("HasCredentialIndicators"))
            top5 = list(by_path.keys())[:5]
            row_summary = base.copy()
            row_summary["TotalFilesWithHits"] = total_files
            row_summary["TotalMatchCount"] = total_hits
            row_summary["FilesCredentialFlagged"] = cred_flagged
            row_summary["Top5FilePaths"] = "; ".join(top5) if top5 else ""
            add_row(sheet_rows, "Config Summary", row_summary, include_source_section=debug_provenance)

    # --- SecurityAgents (CrowdStrike, Qualys, SCCM, Encase) ---
    # Only include output data, not search criteria or anecdotal information
    sec = record.get("SecurityAgents") or {}
    if sec:
        row = base.copy()
        for agent_name, agent_obj in sec.items():
            if isinstance(agent_obj, dict):
                for k, v in agent_obj.items():
                    # Filter out search criteria and anecdotal fields
                    # Encase: ServiceName is search criteria, not output data
                    if agent_name == "Encase" and k == "ServiceName":
                        continue
                    # Only include actual output/configuration data
                    col = f"{agent_name}_{k}"
                    row[col] = v
            else:
                row[agent_name] = agent_obj
        # Filter will be applied in add_row function
        add_row(sheet_rows, "SecurityAgents", row, include_source_section=debug_provenance)

    # --- Service Account Candidates ---
    # Comprehensive extraction of ALL service accounts and domain accounts from all sources
    # This provides a unified view of all accounts that may need migration attention
    # Sources: Services, Scheduled Tasks, IIS App Pools, SQL Logins, Local Admins,
    #         Local Group Members, Credential Manager, AutoAdminLogon
    
    def extract_account_info(account_value, account_identity=None, old_domain_fqdn=None, old_domain_netbios=None):
        """Extract account information from value and/or AccountIdentity object."""
        account_info = {}
        
        # Start with AccountIdentity if available (most reliable)
        if isinstance(account_identity, dict):
            account_info = parse_account_identity(account_identity)
            account_value = account_info.get("AccountName") or account_value or ""
        elif account_value:
            # Parse account value (format: DOMAIN\User or just User)
            if isinstance(account_value, str):
                account_value = account_value.strip()
                if "\\" in account_value:
                    parts = account_value.split("\\", 1)
                    if len(parts) == 2:
                        account_info["AccountDomain"] = parts[0]
                        account_info["AccountName"] = parts[1]
                        account_info["IsDomainAccount"] = True
                        # Check if it's old domain
                        if old_domain_fqdn or old_domain_netbios:
                            domain_lower = parts[0].lower()
                            old_fqdn_lower = (old_domain_fqdn or "").lower()
                            old_netbios_lower = (old_domain_netbios or "").lower()
                            account_info["IsOldDomainAccount"] = (
                                domain_lower == old_fqdn_lower
                                or domain_lower == old_netbios_lower
                            )
                else:
                    account_info["AccountName"] = account_value
                    account_info["IsDomainAccount"] = False
                    account_info["IsOldDomainAccount"] = False
        
        return account_info, account_value
    
    def is_builtin_account(account_value):
        """Check if account is a built-in Windows account."""
        if not isinstance(account_value, str):
            return False
        lower = account_value.lower()
        return (
            lower in ("localsystem", "localservice", "networkservice")
            or lower.startswith("nt authority\\")
            or lower.startswith("nt service\\")
            or lower.startswith(".\\")
        )
    
    def add_service_account_row(source_type, account_value, account_identity, context_info, 
                                needs_attention_flag=False):
        """Add a service account candidate row."""
        if not account_value and not account_identity:
            return
        
        # Extract account info first to get the normalized account information
        account_info, parsed_account = extract_account_info(
            account_value, account_identity, old_domain_fqdn or "", old_domain_netbios or ""
        )
        
        # Determine the account name to check (prioritize AccountIdentity if available)
        if account_info.get("AccountName"):
            account_name_to_check = account_info.get("AccountName", "")
        else:
            account_name_to_check = parsed_account or ""
        
        # Skip built-in accounts, but prioritize AccountIdentity if it indicates a domain account
        # This handles cases where the raw account_value might look like a built-in but
        # AccountIdentity has the correct domain account information
        if account_name_to_check and is_builtin_account(account_name_to_check):
            # If AccountIdentity says it's a domain account, include it (AccountIdentity is more reliable)
            if account_identity and isinstance(account_identity, dict):
                if account_identity.get("IsDomainAccount", False):
                    # AccountIdentity indicates domain account, so include it
                    pass
                else:
                    # Confirmed built-in account, skip it
                    return
            else:
                # No AccountIdentity to verify, and it looks like a built-in, skip it
                return
        
        if not parsed_account and not account_info.get("AccountName"):
            return
        
        row = base.copy()
        row["SourceType"] = source_type
        row.update(context_info)
        row.update(account_info)
        row["AccountValue"] = parsed_account  # Original account value
        row["NeedsAttention"] = needs_attention_flag or account_info.get("IsOldDomainAccount", False)
        
        add_row(sheet_rows, "ServiceAccountCandidates", row, include_source_section=debug_provenance)
    
    # Get detection flags for flagging
    services_run_as_old_domain = set(detection_flags.get("ServicesRunAsOldDomain") or [])
    services_old_path_refs = set(detection_flags.get("ServicesOldPathRefs") or [])
    tasks_old_accounts = set(detection_flags.get("ScheduledTasksWithOldAccounts") or [])
    iis_apppools_old = set(detection_flags.get("IISAppPoolsOldDomain") or [])
    sql_old_domain = set(detection_flags.get("SqlServerOldDomain") or [])
    local_admins_old = set(detection_flags.get("LocalAdministratorsOldDomain") or [])
    local_groups_old = set(detection_flags.get("LocalGroupsOldDomainMembers") or [])
    cred_mgr_old = set(detection_flags.get("CredentialManagerOldDomain") or [])
    
    # 1. Windows Services
    services = record.get("Services") or []
    if isinstance(services, dict):
        services = [services]
    for svc in services:
        if not isinstance(svc, dict):
            continue
        service_name = svc.get("Name") or svc.get("ServiceName")
        # Check multiple possible field names for service account
        start_name = svc.get("StartName") or svc.get("StartNameRaw") or svc.get("Account") or ""
        account_identity = svc.get("AccountIdentity")
        
        # Include if we have either account value or AccountIdentity
        # AccountIdentity is more reliable as it's normalized by the PowerShell script
        if start_name or account_identity:
            needs_attention = (
                service_name in services_run_as_old_domain
                or service_name in services_old_path_refs
            )
            add_service_account_row(
                "Service",
                start_name,
                account_identity,
                {
                    "ServiceName": service_name,
                    "DisplayName": svc.get("DisplayName"),
                    "State": svc.get("State") or svc.get("Status"),
                    "StartMode": svc.get("StartMode"),
                    "PathName": svc.get("PathName") or svc.get("Path") or svc.get("BinaryPathName"),
                },
                needs_attention
            )
    
    # 2. Scheduled Tasks
    tasks = record.get("ScheduledTasks") or []
    if isinstance(tasks, dict):
        tasks = [tasks]
    for task in tasks:
        if not isinstance(task, dict):
            continue
        task_path = task.get("Path") or task.get("TaskName")
        # Check multiple possible field names for task account
        user_id = task.get("UserId") or task.get("Principal") or task.get("RunAs") or ""
        account_identity = task.get("AccountIdentity")
        
        # Include if we have either account value or AccountIdentity
        # AccountIdentity is more reliable as it's normalized by the PowerShell script
        if user_id or account_identity:
            needs_attention = task_path in tasks_old_accounts
            add_service_account_row(
                "ScheduledTask",
                user_id,
                account_identity,
                {
                    "TaskPath": task_path,
                    "TaskEnabled": task.get("Enabled"),
                    "LogonType": task.get("LogonType"),
                },
                needs_attention
            )
    
    # 3. IIS Application Pools
    iis = record.get("IIS")
    if iis and isinstance(iis, dict):
        app_pools = iis.get("AppPools") or []
        # Handle both list and dict formats (consistent with count logic)
        if isinstance(app_pools, dict):
            app_pools = [app_pools]
        if isinstance(app_pools, list):
            for pool in app_pools:
                if not isinstance(pool, dict):
                    continue
                pool_name = pool.get("Name")
                identity_type = pool.get("Identity") or pool.get("IdentityType")
                identity_user = pool.get("IdentityUser")
                account_identity = pool.get("AccountIdentity")
                
                # Only include custom identities (not ApplicationPoolIdentity, NetworkService, etc.)
                if identity_type and identity_type.lower() not in ("applicationpoolidentity", "networkservice", "localservice"):
                    if identity_user or account_identity:
                        needs_attention = pool_name in iis_apppools_old if pool_name else False
                        add_service_account_row(
                            "IISAppPool",
                            identity_user,
                            account_identity,
                            {
                                "AppPoolName": pool_name,
                                "IdentityType": identity_type,
                                "AppPoolState": pool.get("State"),
                            },
                            needs_attention
                        )
    
    # 4. SQL Server Domain Logins
    sql_server = record.get("SqlServer")
    if sql_server:
        if isinstance(sql_server, list):
            sql_instances = sql_server
        elif isinstance(sql_server, dict):
            sql_instances = [sql_server]
        else:
            sql_instances = []
        
        for instance in sql_instances:
            if not isinstance(instance, dict):
                continue
            instance_name = instance.get("InstanceName")
            domain_logins = instance.get("DomainLogins") or []
            
            for login in domain_logins:
                if not isinstance(login, dict):
                    continue
                login_name = login.get("LoginName")
                login_type = login.get("LoginType")
                account_identity = login.get("AccountIdentity")
                
                # Only include Windows logins (not SQL logins)
                if login_type in ("WindowsUser", "WindowsGroup"):
                    if login_name or account_identity:
                        # Check if this login is flagged
                        login_key = f"{instance_name}: Login {login_name}" if instance_name else login_name
                        needs_attention = login_key in sql_old_domain
                        add_service_account_row(
                            "SqlServerLogin",
                            login_name,
                            account_identity,
                            {
                                "InstanceName": instance_name,
                                "ServiceName": instance.get("ServiceName"),
                                "LoginType": login_type,
                            },
                            needs_attention
                        )
    
    # 5. Local Administrators (domain accounts only)
    local_admins = record.get("LocalAdministrators") or []
    if isinstance(local_admins, dict):
        local_admins = [local_admins]
    for admin in local_admins:
        if not isinstance(admin, dict):
            continue
        admin_name = admin.get("Name")
        admin_type = admin.get("Type")
        is_old_domain = admin.get("IsOldDomain", False)
        
        # Only include domain accounts
        if admin_type == "Domain" and admin_name:
            needs_attention = is_old_domain or admin_name in local_admins_old
            add_service_account_row(
                "LocalAdministrator",
                admin_name,
                None,  # Local admins may not have AccountIdentity
                {
                    "AdminSid": admin.get("Sid"),
                    "Source": admin.get("Source"),
                },
                needs_attention
            )
    
    # 6. Local Group Members (domain accounts only)
    local_groups = record.get("LocalGroupMembers") or []
    if isinstance(local_groups, dict):
        local_groups = [local_groups]
    for group in local_groups:
        if not isinstance(group, dict):
            continue
        group_name = group.get("GroupName")
        members = group.get("Members") or []
        
        for member in members:
            if not isinstance(member, dict):
                continue
            account_identity = member.get("AccountIdentity")
            member_name = member.get("Name")
            principal_source = member.get("PrincipalSource", "")
            
            # Only include domain accounts (ActiveDirectory source)
            if principal_source == "ActiveDirectory" and (member_name or account_identity):
                needs_attention = group_name in local_groups_old if group_name else False
                add_service_account_row(
                    "LocalGroupMember",
                    member_name,
                    account_identity,
                    {
                        "GroupName": group_name,
                        "MemberSid": member.get("SID"),
                        "ObjectClass": member.get("ObjectClass"),
                    },
                    needs_attention
                )
    
    # 7. Credential Manager (domain accounts only)
    cred_mgr = record.get("CredentialManager") or []
    if isinstance(cred_mgr, dict):
        cred_mgr = [cred_mgr]
    for cred in cred_mgr:
        if not isinstance(cred, dict):
            continue
        user_name = cred.get("UserName")
        account_identity = cred.get("AccountIdentity")
        target = cred.get("Target")
        
        if user_name or account_identity:
            # Only include if it's a domain account
            account_info, _ = extract_account_info(
                user_name, account_identity, old_domain_fqdn or "", old_domain_netbios or ""
            )
            if account_info.get("IsDomainAccount"):
                needs_attention = target in cred_mgr_old if target else False
                add_service_account_row(
                    "CredentialManager",
                    user_name,
                    account_identity,
                    {
                        "Target": target,
                        "Profile": cred.get("Profile"),
                        "CredentialType": cred.get("Type"),
                        "Source": cred.get("Source"),
                    },
                    needs_attention
                )
    
    # 8. AutoAdminLogon (system logon account)
    auto_logon = record.get("AutoAdminLogon")
    if auto_logon and isinstance(auto_logon, dict):
        if auto_logon.get("Enabled"):
            user_name = auto_logon.get("DefaultUserName")
            domain_name = auto_logon.get("DefaultDomainName")
            
            if user_name:
                # Combine domain and username if domain is present
                full_account = f"{domain_name}\\{user_name}" if domain_name else user_name
                needs_attention = auto_logon.get("HasDomainReference", False)
                add_service_account_row(
                    "AutoAdminLogon",
                    full_account,
                    None,
                    {
                        "ForceAutoLogon": auto_logon.get("ForceAutoLogon"),
                    },
                    needs_attention
                )


def write_excel(
    sheet_rows: dict,
    output_path: str,
    fail_fast: bool = False,
    report_path: Optional[str] = None,
    emit_sanitize_report: bool = False,
    cancel_event: Optional[threading.Event] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Tuple[List[ExcelPreflightIssue], int]:
    """
    Write sheet_rows (dict of sheet_name -> list[dict]) to an XLSX file.
    Before writing each sheet, runs preflight validation (find_excel_issues): detects
    Excel-illegal control characters and values exceeding cell length. If fail_fast and
    any issue is found, raises RuntimeError. All object columns are sanitized immediately
    before to_excel(). If any issues were found and emit_sanitize_report, writes
    <output>_excel_sanitize_report.csv. Returns (issues, sanitization_modified_count).
    """
    def _log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    ev = cancel_event or threading.Event()
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    preferred_order = [
        "Summary",
        "Diagnostics",
        "Metadata",
        "System",
        "ServiceAccountCandidates",
        "Services",
        "ScheduledTasks",
        "LocalAdministrators",
        "Local Admin Membership",
        "LocalGroupMembers",
        "MappedDrives",
        "Printers",
        "OdbcDsn",
        "CredentialManager",
        "Certificates",
        "FirewallRules",
        "Profiles",
        "InstalledApps",
        "SharedFolders_Shares",
        "SharedFolders_Errors",
        "DnsSuffixSearchList",
        "DnsAdapters",
        "AutoAdminLogon",
        "EventLogDomainReferences",
        "ApplicationConfigFiles",
        "Config File Findings",
        "Config Summary",
        "Oracle Summary",
        "Oracle Details",
        "RDS Licensing",
        "SecurityAgents",
        "IIS",
        "SqlServer",
    ]

    all_sheets = set(sheet_rows.keys())
    ordered_sheets = [s for s in preferred_order if s in all_sheets]
    remaining_sheets = sorted(all_sheets - set(preferred_order))
    final_sheet_order = ordered_sheets + remaining_sheets
    total_sheets = len([s for s in final_sheet_order if sheet_rows.get(s)])

    all_issues: List[ExcelPreflightIssue] = []
    written = 0
    sanitization_modified_count = 0

    def apply_sanitize_counted(series: Any, counter: list) -> Any:
        def one(val: Any) -> Any:
            out, modified = _sanitize_for_excel_track(val)
            if modified:
                counter[0] += 1
            return out
        return series.apply(one)

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for sheet_name in final_sheet_order:
            if ev.is_set():
                raise CancelledError()
            rows = sheet_rows.get(sheet_name, [])
            if not rows:
                continue
            df = pd.DataFrame(rows)

            # Preflight validation before writing each sheet
            sheet_issues = find_excel_issues(df, sheet_name)
            all_issues.extend(sheet_issues)
            if fail_fast and sheet_issues:
                first = sheet_issues[0]
                value_preview = (
                    (first.value_repr[:80] + "...") if len(first.value_repr) > 80 else first.value_repr
                )
                if first.issue_kind == "illegal_control":
                    msg = (
                        f"fail-fast: illegal Excel character(s) at sheet={first.sheet_name!r} "
                        f"row={first.row_index + 1} col={first.column!r} "
                        f"(illegal_count={first.illegal_count}). "
                        f"source_file={first.source_file or 'N/A'} "
                        f"value_repr={value_preview}"
                    )
                else:
                    msg = (
                        f"fail-fast: cell length exceeded at sheet={first.sheet_name!r} "
                        f"row={first.row_index + 1} col={first.column!r} "
                        f"(cell_length={first.cell_length}, max={MAX_EXCEL_CELL_LEN}). "
                        f"source_file={first.source_file or 'N/A'} "
                        f"value_repr={value_preview}"
                    )
                raise RuntimeError(msg)

            # Apply Excel-safe sanitization to ALL object columns immediately before to_excel
            mod_count = [0]
            for col in df.columns:
                if df[col].dtype == object:
                    df[col] = apply_sanitize_counted(df[col], mod_count)
            sanitization_modified_count += mod_count[0]

            core_cols = ["ComputerName", "PlantId", "CollectedAt"]
            if sheet_name == "Summary":
                summary_cols = [
                    "HasOldDomainRefs", "PotentialServiceAccounts",
                    "SqlServerInstalled", "SqlServerVersion",
                    "IsOracleServerLikely", "OracleVersion",
                    "RdsLicensingRoleInstalled",
                    "CrowdStrike_Tenant", "Qualys_Tenant",
                    "SCCM_Tenant", "SCCM_HasDomainReference", "SCCM_AllowedMPs", "SCCM_AllowedMPDomains",
                    "Encase_Installed", "Encase_Tenant",
                ]
                core_cols = core_cols + [c for c in summary_cols if c in df.columns]
            elif sheet_name == "Diagnostics":
                core_cols = ["SourceFile", "SourceComputerKey", "ComputerName", "CollectedAt", "PlantId"]
            elif sheet_name == "Metadata":
                core_cols = [
                    "ComputerName", "PlantId", "Domain", "OldDomainFqdn",
                    "OldDomainNetBIOS", "NewDomainFqdn", "CollectedAt",
                ]
            elif sheet_name == "ServiceAccountCandidates":
                action_cols = [
                    "SourceType", "NeedsAttention", "IsOldDomainAccount", "IsDomainAccount",
                    "AccountName", "AccountDomain", "AccountValue",
                    "ServiceName", "DisplayName", "TaskPath", "AppPoolName",
                    "InstanceName", "GroupName", "Target",
                ]
                core_cols = core_cols + [c for c in action_cols if c in df.columns]

            cols = list(df.columns)
            ordered = []
            for c in core_cols:
                if c in cols:
                    ordered.append(c)
                    cols.remove(c)
            ordered.extend(cols)
            df = df[ordered]

            safe_name = sheet_name[:31]
            for ch in r'[]:*?/\\':
                safe_name = safe_name.replace(ch, "_")

            df.to_excel(writer, sheet_name=safe_name, index=False)
            written += 1
            if progress_cb:
                progress_cb(written, total_sheets)

    if all_issues and report_path and emit_sanitize_report:
        write_sanitize_report_csv(all_issues, report_path)
        _log(f"Sanitize report ({len(all_issues)} issue(s)): {report_path}")

    _log(f"Wrote Excel workbook: {output_path}")
    return all_issues, sanitization_modified_count


# Sheet order used for validation and writing
_PREFERRED_SHEET_ORDER = [
    "Summary", "Diagnostics", "Metadata", "System", "ServiceAccountCandidates",
    "Services", "ScheduledTasks", "LocalAdministrators", "Local Admin Membership",
    "LocalGroupMembers", "MappedDrives", "Printers", "OdbcDsn", "CredentialManager",
    "Certificates", "FirewallRules", "Profiles", "InstalledApps", "SharedFolders_Shares",
    "SharedFolders_Errors", "DnsSuffixSearchList", "DnsAdapters", "AutoAdminLogon",
    "EventLogDomainReferences", "ApplicationConfigFiles", "Config File Findings",
    "Config Summary", "Oracle Summary", "Oracle Details", "RDS Licensing",
    "SecurityAgents", "IIS", "SqlServer",
]


def build_workbook(
    input_folder: str,
    output_path: str,
    *,
    validate_only: bool = False,
    sanitize: bool = False,
    include_sourcefile: bool = False,
    fail_fast: bool = False,
    strict_json: bool = False,
    cancel_event: Optional[threading.Event] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    status_cb: Optional[Callable[[str], None]] = None,
) -> BuildResult:
    """
    Build migration discovery workbook from JSON snapshots (GUI-safe).
    All long-running loops check cancel_event; progress/log/status go only through callbacks.
    """
    warnings_count = [0]  # mutable so inner callbacks can increment

    def _log(msg: str) -> None:
        if msg.strip().startswith("WARNING") or "WARNING:" in msg:
            warnings_count[0] += 1
        if log_cb:
            log_cb(msg)

    def _status(msg: str) -> None:
        if status_cb:
            status_cb(msg)

    ev = cancel_event or threading.Event()
    workbook_path: Optional[str] = None
    report_path: Optional[str] = None
    errors_count = 0

    try:
        _status("Loading JSON files...")
        records_with_provenance, plant_ids_seen = load_latest_records(
            input_folder,
            explicit_plant_id=None,
            strict_json=strict_json,
            cancel_event=ev,
            log_cb=_log,
        )

        if not records_with_provenance:
            _log("No JSON records found in input folder.")
            return BuildResult(
                workbook_path=None,
                report_path=None,
                warnings=warnings_count[0],
                errors=0,
                cancelled=False,
            )

        _status("Building sheet data...")
        sheet_rows = defaultdict(list)
        total = len(records_with_provenance)
        for idx, item in enumerate(records_with_provenance):
            if ev.is_set():
                raise CancelledError()
            if progress_cb and total:
                progress_cb(idx, total)
            comp_key = item["computer_key"]
            record = item["data"]
            path = item["path"]
            flatten_record(
                comp_key,
                record,
                sheet_rows,
                source_file=path,
                source_computer_key=comp_key,
                debug_provenance=include_sourcefile,
            )

        for item in records_with_provenance:
            if ev.is_set():
                raise CancelledError()
            meta = (item["data"] or {}).get("Metadata") or {}
            sheet_rows["Diagnostics"].append({
                "SourceFile": item["path"],
                "SourceComputerKey": item["computer_key"],
                "ComputerName": meta.get("ComputerName", item["computer_key"]),
                "CollectedAt": meta.get("CollectedAt"),
                "PlantId": meta.get("PlantId"),
            })

        output_dir = os.path.dirname(output_path)
        base_name = os.path.splitext(os.path.basename(output_path))[0]
        sanitize_report_path = os.path.join(
            output_dir, base_name + "_excel_sanitize_report.csv"
        )
        validate_report_path = os.path.join(output_dir, "excel_validate_report.csv")

        if validate_only:
            _status("Validating sheets...")
            all_sheets = set(sheet_rows.keys())
            ordered_sheets = [s for s in _PREFERRED_SHEET_ORDER if s in all_sheets]
            remaining_sheets = sorted(all_sheets - set(_PREFERRED_SHEET_ORDER))
            final_sheet_order = ordered_sheets + remaining_sheets
            all_issues = []
            for sheet_name in final_sheet_order:
                if ev.is_set():
                    raise CancelledError()
                rows = sheet_rows.get(sheet_name, [])
                if not rows:
                    continue
                df = pd.DataFrame(rows)
                all_issues.extend(find_excel_issues(df, sheet_name))
            if all_issues:
                write_sanitize_report_csv(all_issues, validate_report_path)
                _log(f"Validation found {len(all_issues)} issue(s). Report: {validate_report_path}")
                return BuildResult(
                    workbook_path=None,
                    report_path=validate_report_path,
                    warnings=warnings_count[0],
                    errors=len(all_issues),
                    cancelled=False,
                )
            _log("Validation completed: no illegal Excel characters found.")
            return BuildResult(
                workbook_path=None,
                report_path=None,
                warnings=warnings_count[0],
                errors=0,
                cancelled=False,
            )

        _status("Writing workbook...")
        workbook_path = output_path
        report_path = sanitize_report_path if sanitize else None
        all_issues, sanitization_count = write_excel(
            sheet_rows,
            output_path,
            fail_fast=fail_fast,
            report_path=sanitize_report_path,
            emit_sanitize_report=sanitize,
            cancel_event=ev,
            log_cb=_log,
            progress_cb=progress_cb,
        )
        warnings_count[0] += sanitization_count
        errors_count = len(all_issues)
        return BuildResult(
            workbook_path=workbook_path,
            report_path=report_path if all_issues and sanitize else None,
            warnings=warnings_count[0],
            errors=errors_count,
            cancelled=False,
        )

    except CancelledError:
        return BuildResult(
            workbook_path=workbook_path if workbook_path else None,
            report_path=report_path,
            warnings=warnings_count[0],
            errors=errors_count,
            cancelled=True,
        )
    except RuntimeError as e:
        if "fail-fast" in str(e):
            if log_cb:
                log_cb(str(e))
            return BuildResult(
                workbook_path=None,
                report_path=None,
                warnings=warnings_count[0],
                errors=1,
                cancelled=False,
            )
        raise


def main() -> None:
    """Thin CLI wrapper: parse args, call build_workbook(), print summary."""
    args = parse_args()

    input_path = os.path.abspath(os.path.normpath(args.input))
    if not os.path.isdir(input_path):
        if args.input == DEFAULT_INPUT_FOLDER:
            print("Default input folder './results' was not found in the current directory.")
            print("Use the -i (or --input) switch to specify the folder that contains your discovery JSON files.")
            print("Example: python build_migration_workbook.py -i C:\\path\\to\\results")
            sys.exit(1)
        print("Input folder not found: {}".format(args.input))
        sys.exit(1)

    # Build output path (same logic as before)
    if args.plant_id:
        plant_for_name = args.plant_id
    else:
        # Need to load once to get plant_ids for naming; use minimal load without callbacks
        recs, plant_ids_seen = load_latest_records(
            input_path,
            explicit_plant_id=args.plant_id,
            strict_json=args.strict_json,
            cancel_event=None,
            log_cb=None,
        )
        if not recs:
            print(f"No JSON records found in {input_path}")
            sys.exit(1)
        non_empty = {p for p in plant_ids_seen if p}
        if len(non_empty) == 1:
            plant_for_name = next(iter(non_empty))
        elif len(non_empty) == 0:
            plant_for_name = "ALL"
        else:
            plant_for_name = "MULTI"

    today_str = datetime.date.today().strftime("%Y%m%d")
    filename = f"{plant_for_name}_MigrationDiscovery_{today_str}.xlsx"
    output_path = os.path.join(args.output_dir, filename)

    cancel_ev = threading.Event()

    def cli_log(msg: str) -> None:
        print(msg, file=sys.stderr)

    def cli_status(msg: str) -> None:
        print(msg, file=sys.stderr)

    include_sourcefile = args.include_sourcefile or args.debug_provenance
    result = build_workbook(
        input_path,
        output_path,
        validate_only=args.validate_only,
        sanitize=args.debug,
        include_sourcefile=include_sourcefile,
        fail_fast=args.fail_fast,
        strict_json=args.strict_json,
        cancel_event=cancel_ev,
        progress_cb=None,
        log_cb=cli_log,
        status_cb=cli_status,
    )

    if result.cancelled:
        print("Cancelled.", file=sys.stderr)
        sys.exit(130)
    if result.errors and args.validate_only:
        print(f"Validation failed: {result.errors} issue(s).", file=sys.stderr)
        sys.exit(1)
    if result.workbook_path:
        print(f"Wrote: {result.workbook_path}")
    print(f"Warnings: {result.warnings}, Errors: {result.errors}")
    if result.errors and not args.validate_only:
        sys.exit(1)
    if result.report_path:
        print(f"Report: {result.report_path}", file=sys.stderr)
    sys.exit(0)
