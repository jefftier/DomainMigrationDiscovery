import os
import json
import argparse
import datetime
from collections import defaultdict

import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build a migration discovery Excel workbook from JSON snapshots."
    )
    parser.add_argument(
        "-i",
        "--input",
        default=r"Y:\results",
        help="Folder containing discovery JSON files (default: Y:\\results)",
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


def load_latest_records(input_folder, explicit_plant_id=None):
    """
    Load all JSON files, group by ComputerName, and keep the latest snapshot
    (by Metadata.CollectedAt). Returns dict: {computerName: data}.
    Optionally filter by PlantId if explicit_plant_id is provided.
    """
    latest_by_computer = {}
    plant_ids_seen = set()

    for root, _, files in os.walk(input_folder):
        for fname in files:
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to parse {fpath}: {e}")
                continue

            meta = data.get("Metadata", {}) or {}
            comp_name = meta.get("ComputerName") or os.path.splitext(fname)[0]
            plant_id = meta.get("PlantId") or ""
            collected_raw = meta.get("CollectedAt")
            collected_dt = safe_iso_parse(collected_raw)

            if explicit_plant_id and plant_id and plant_id != explicit_plant_id:
                # Skip records from other plants if a specific plant is requested
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
                # Keep the latest CollectedAt; if parsing fails, keep the first
                prev_dt = existing.get("collected_dt")
                if prev_dt is None and collected_dt is None:
                    # Arbitrary; keep existing
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
                # else: collected_dt is None and prev_dt is not None -> keep existing

    # Strip helper keys, keep just JSON data
    pure_records = {k: v["data"] for k, v in latest_by_computer.items()}

    return pure_records, plant_ids_seen


def add_row(sheet_rows, sheet_name, row_dict):
    """
    Append a row (dict) to the given sheet name in the rows dict.
    """
    if row_dict is None:
        return
    sheet_rows[sheet_name].append(row_dict)


def flatten_record(computer_name, record, sheet_rows):
    """
    Flatten a single JSON record into multiple sheet rows.

    - Adds rows into sheet_rows[...] for sections:
      Metadata, System, Profiles, SharedFolders_Shares, SharedFolders_Errors,
      InstalledApps, Services, ScheduledTasks, LocalGroupMembers,
      LocalAdministrators, MappedDrives, Printers, OdbcDsn, AutoAdminLogon,
      CredentialManager, Certificates, FirewallRules, DnsSummary,
      DnsSuffixSearchList, DnsAdapters, IIS, SqlServer, EventLogDomainReferences,
      ApplicationConfigFiles, SecurityAgents, DetectionSummary,
      ServiceAccountCandidates.
    """
    meta = record.get("Metadata", {}) or {}
    system = record.get("System", {}) or {}

    base = {
        "ComputerName": meta.get("ComputerName", computer_name),
        "PlantId": meta.get("PlantId"),
        "Domain": meta.get("Domain"),
        "CollectedAt": meta.get("CollectedAt"),
        "OldDomainFqdn": meta.get("OldDomainFqdn"),
        "OldDomainNetBIOS": meta.get("OldDomainNetBIOS"),
        "NewDomainFqdn": meta.get("NewDomainFqdn"),
        "ScriptVersion": meta.get("Version"),
    }

    # --- Metadata (one row per computer) ---
    row_meta = base.copy()
    # Include all metadata fields explicitly
    for k, v in meta.items():
        if k not in row_meta:
            row_meta[k] = v
    add_row(sheet_rows, "Metadata", row_meta)

    # --- System (one row per computer) ---
    row_sys = base.copy()
    row_sys.update(system)
    add_row(sheet_rows, "System", row_sys)

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
            add_row(sheet_rows, section_name, row)

    # --- Simple list sections ---
    for section in [
        "Profiles",
        "InstalledApps",
        "Services",
        "ScheduledTasks",
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
        add_row(sheet_rows, "SharedFolders_Shares", row)

    for err in errors:
        row = base.copy()
        if isinstance(err, dict):
            row.update(err)
        else:
            row["Error"] = err
        add_row(sheet_rows, "SharedFolders_Errors", row)

    # --- Printers: can be dict or list ---
    printers = record.get("Printers")
    if printers:
        if isinstance(printers, list):
            for prn in printers:
                row = base.copy()
                if isinstance(prn, dict):
                    row.update(prn)
                else:
                    row["Printer"] = prn
                add_row(sheet_rows, "Printers", row)
        elif isinstance(printers, dict):
            row = base.copy()
            row.update(printers)
            add_row(sheet_rows, "Printers", row)

    # --- AutoAdminLogon: single object ---
    auto = record.get("AutoAdminLogon")
    if auto:
        row = base.copy()
        if isinstance(auto, dict):
            row.update(auto)
        else:
            row["Value"] = auto
        add_row(sheet_rows, "AutoAdminLogon", row)

    # --- DNS Configuration ---
    dns = record.get("DnsConfiguration") or {}
    if dns:
        # Summary row
        dns_summary = base.copy()
        for k, v in dns.items():
            if not isinstance(v, (list, dict)):
                dns_summary[k] = v
        add_row(sheet_rows, "DnsSummary", dns_summary)

        # Suffix search list
        for suffix in dns.get("SuffixSearchList") or []:
            row = base.copy()
            row["Suffix"] = suffix
            add_row(sheet_rows, "DnsSuffixSearchList", row)

        # Adapters
        adapters = dns.get("Adapters") or []
        for adapter in adapters:
            row = base.copy()
            if isinstance(adapter, dict):
                row.update(adapter)
            else:
                row["Adapter"] = adapter
            add_row(sheet_rows, "DnsAdapters", row)

    # --- IIS & SqlServer: store raw JSON per machine for now ---
    iis = record.get("IIS")
    if iis is not None:
        row = base.copy()
        row["RawJson"] = json.dumps(iis, ensure_ascii=False)
        add_row(sheet_rows, "IIS", row)

    sql = record.get("SqlServer")
    if sql is not None:
        row = base.copy()
        row["RawJson"] = json.dumps(sql, ensure_ascii=False)
        add_row(sheet_rows, "SqlServer", row)

    # --- ApplicationConfigFiles: also often nested; store raw + some summary if present ---
    app_cfg = record.get("ApplicationConfigFiles")
    if app_cfg is not None:
        row = base.copy()
        if isinstance(app_cfg, dict):
            # Try to surface a high-level summary if the structure provides it,
            # otherwise keep the whole object as JSON.
            for k, v in app_cfg.items():
                if not isinstance(v, (list, dict)):
                    row[k] = v
            row["RawJson"] = json.dumps(app_cfg, ensure_ascii=False)
        else:
            row["RawJson"] = json.dumps(app_cfg, ensure_ascii=False)
        add_row(sheet_rows, "ApplicationConfigFiles", row)

    # --- SecurityAgents (CrowdStrike, Qualys, etc.) ---
    sec = record.get("SecurityAgents") or {}
    if sec:
        row = base.copy()
        for agent_name, agent_obj in sec.items():
            if isinstance(agent_obj, dict):
                for k, v in agent_obj.items():
                    col = f"{agent_name}_{k}"
                    row[col] = v
            else:
                row[agent_name] = agent_obj
        add_row(sheet_rows, "SecurityAgents", row)

    # --- Service Account Candidates & Detection Summary ---
    # We compute candidate service accounts by inspecting Services list.
    potential_service_account_count = 0
    services = record.get("Services") or []
    if isinstance(services, dict):
        services = [services]

    for svc in services:
        if not isinstance(svc, dict):
            continue
        start_name = svc.get("StartName") or svc.get("StartNameRaw") or ""
        if not isinstance(start_name, str):
            continue
        s = start_name.strip()
        if not s:
            continue

        lower = s.lower()
        # Filter out the usual built-ins
        is_builtin = (
            lower in ("localsystem", "localservice", "networkservice")
            or lower.startswith("nt authority\\")
            or lower.startswith("nt service\\")
        )
        if is_builtin:
            continue

        # At this point, it's likely a domain/local service account we care about
        potential_service_account_count += 1
        row = base.copy()
        row["ServiceName"] = svc.get("Name") or svc.get("ServiceName")
        row["DisplayName"] = svc.get("DisplayName")
        row["StartName"] = s
        row["Status"] = svc.get("Status")
        row["StartMode"] = svc.get("StartMode")
        row["PathName"] = (
            svc.get("Path")
            or svc.get("BinaryPathName")
            or svc.get("ImagePath")
        )
        add_row(sheet_rows, "ServiceAccountCandidates", row)

    # Detection Summary
    detection = record.get("Detection") or {}
    summary = detection.get("Summary") or {}
    counts = summary.get("Counts") or {}

    row_det = base.copy()
    row_det["HasOldDomainRefs"] = summary.get("HasOldDomainRefs")
    row_det["PotentialServiceAccounts"] = potential_service_account_count

    for k, v in counts.items():
        # Prefix with Count_ to make it obvious in Excel
        col_name = f"Count_{k}"
        row_det[col_name] = v

    add_row(sheet_rows, "Summary", row_det)


def write_excel(sheet_rows, output_path):
    """
    Write sheet_rows (dict of sheet_name -> list[dict]) to an XLSX file.
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for sheet_name, rows in sheet_rows.items():
            if not rows:
                continue
            df = pd.DataFrame(rows)

            # Core columns first if they exist
            core_cols = ["ComputerName", "PlantId", "Domain", "CollectedAt"]
            cols = list(df.columns)
            ordered = []
            for c in core_cols:
                if c in cols:
                    ordered.append(c)
                    cols.remove(c)
            ordered.extend(cols)
            df = df[ordered]

            # Excel sheet names max 31 chars, no []:*?/\ etc.
            safe_name = sheet_name[:31]
            for ch in r'[]:*?/\\':
                safe_name = safe_name.replace(ch, "_")

            df.to_excel(writer, sheet_name=safe_name, index=False)

    print(f"Wrote Excel workbook: {output_path}")


def main():
    args = parse_args()

    records, plant_ids_seen = load_latest_records(args.input, explicit_plant_id=args.plant_id)

    if not records:
        print(f"No JSON records found in {args.input}")
        return

    # Decide PlantId to use in file name
    if args.plant_id:
        plant_for_name = args.plant_id
    else:
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

    # Collect rows for each sheet
    sheet_rows = defaultdict(list)

    for comp_name, record in records.items():
        flatten_record(comp_name, record, sheet_rows)

    write_excel(sheet_rows, output_path)


if __name__ == "__main__":
    main()
