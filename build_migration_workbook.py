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


def flatten_record(computer_name, record, sheet_rows):
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
    
    # Add security agent status flags for quick issue identification
    row_det["CrowdStrike_Tenant"] = crowdstrike.get("Tenant")
    row_det["CrowdStrike_Issue"] = "Unknown Tenant" if not crowdstrike.get("Tenant") or crowdstrike.get("Tenant") == "UNKNOWN" else None
    
    row_det["Qualys_Tenant"] = qualys.get("Tenant")
    row_det["Qualys_Issue"] = "Unknown Tenant" if not qualys.get("Tenant") or qualys.get("Tenant") == "UNKNOWN" else None
    
    row_det["SCCM_Tenant"] = sccm.get("Tenant")
    row_det["SCCM_HasDomainReference"] = sccm.get("HasDomainReference", False)
    row_det["SCCM_Issue"] = "Domain Reference Found" if sccm.get("HasDomainReference") else None
    
    row_det["Encase_Installed"] = encase.get("Installed", False)
    row_det["Encase_Tenant"] = encase.get("Tenant")
    row_det["Encase_Issue"] = "Installed but No Tenant" if encase.get("Installed") and not encase.get("Tenant") else None

    for k, v in counts.items():
        # Prefix with Count_ to make it obvious in Excel
        col_name = f"Count_{k}"
        row_det[col_name] = v

    add_row(sheet_rows, "Summary", row_det)

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
            add_row(sheet_rows, section_name, row)

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
        add_row(sheet_rows, "Services", row)
    
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
        add_row(sheet_rows, "ScheduledTasks", row)
    
    # Other simple list sections
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
                add_row(sheet_rows, "Printers", row)
        elif isinstance(printers, dict):
            row = base.copy()
            row.update(printers)
            printer_name = row.get("Name")
            row["HasOldDomainReference"] = printer_name in printers_to_old
            row["NeedsAttention"] = row["HasOldDomainReference"]
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
        # Suffix search list - simplified to only show suffix
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
        
        # Skip built-in accounts
        if account_value and is_builtin_account(account_value):
            return
        
        account_info, parsed_account = extract_account_info(
            account_value, account_identity, old_domain_fqdn or "", old_domain_netbios or ""
        )
        
        if not parsed_account and not account_info.get("AccountName"):
            return
        
        row = base.copy()
        row["SourceType"] = source_type
        row.update(context_info)
        row.update(account_info)
        row["AccountValue"] = parsed_account  # Original account value
        row["NeedsAttention"] = needs_attention_flag or account_info.get("IsOldDomainAccount", False)
        
        add_row(sheet_rows, "ServiceAccountCandidates", row)
    
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
        start_name = svc.get("StartName") or svc.get("StartNameRaw") or svc.get("Account") or ""
        account_identity = svc.get("AccountIdentity")
        
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
        user_id = task.get("UserId") or task.get("Principal")
        account_identity = task.get("AccountIdentity")
        
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


def write_excel(sheet_rows, output_path):
    """
    Write sheet_rows (dict of sheet_name -> list[dict]) to an XLSX file.
    """
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:  # Only create if there's actually a directory path
        os.makedirs(output_dir, exist_ok=True)

    # Define sheet order - Summary first for quick overview
    preferred_order = [
        "Summary",
        "Metadata",
        "System",
        "ServiceAccountCandidates",
        "Services",
        "ScheduledTasks",
        "LocalAdministrators",
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
        "SecurityAgents",
        "IIS",
        "SqlServer",
    ]

    # Get all sheet names, prioritizing preferred order
    all_sheets = set(sheet_rows.keys())
    ordered_sheets = [s for s in preferred_order if s in all_sheets]
    remaining_sheets = sorted(all_sheets - set(preferred_order))
    final_sheet_order = ordered_sheets + remaining_sheets

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for sheet_name in final_sheet_order:
            rows = sheet_rows.get(sheet_name, [])
            if not rows:
                continue
            df = pd.DataFrame(rows)

            # Core columns first if they exist (no Domain in base, only in Metadata)
            core_cols = ["ComputerName", "PlantId", "CollectedAt"]
            # For Summary sheet, put key metrics first
            if sheet_name == "Summary":
                summary_cols = ["HasOldDomainRefs", "PotentialServiceAccounts", 
                               "CrowdStrike_Tenant", "CrowdStrike_Issue",
                               "Qualys_Tenant", "Qualys_Issue",
                               "SCCM_Tenant", "SCCM_HasDomainReference", "SCCM_Issue",
                               "Encase_Installed", "Encase_Tenant", "Encase_Issue"]
                core_cols = core_cols + [c for c in summary_cols if c in df.columns]
            # For Metadata sheet, include domain info
            elif sheet_name == "Metadata":
                core_cols = ["ComputerName", "PlantId", "Domain", "OldDomainFqdn", 
                            "OldDomainNetBIOS", "NewDomainFqdn", "CollectedAt"]
            # For ServiceAccountCandidates, put actionable columns first
            elif sheet_name == "ServiceAccountCandidates":
                action_cols = [
                    "SourceType",
                    "NeedsAttention",
                    "IsOldDomainAccount",
                    "IsDomainAccount",
                    "AccountName",
                    "AccountDomain",
                    "AccountValue",
                    # Context columns vary by source type
                    "ServiceName",
                    "DisplayName",
                    "TaskPath",
                    "AppPoolName",
                    "InstanceName",
                    "GroupName",
                    "Target",
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
