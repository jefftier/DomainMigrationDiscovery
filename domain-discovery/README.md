# Domain Discovery

Scan Windows workstations for **old domain references** (services, tasks, credentials, certificates, etc.) to plan and validate domain migrations. Output is structured JSON for reporting or the [workbook builder](../workbook-builder/).

---

## Get running in 2 minutes

**Prerequisites:** PowerShell 5.1+, Windows (local admin for full discovery).

1. **Allow script execution** (if needed):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Run discovery on this machine** (replace with your domains):
   ```powershell
   .\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com" -SlimOutputOnly
   ```

3. **Find the result:**  
   Default location: `C:\temp\MigrationDiscovery\out\{COMPUTERNAME}_{MM-dd-yyyy}.json`

Use that folder as input for the workbook builder, or run remotely (see below).

---

## What gets discovered

The script scans **30+ areas** of Windows configuration for references to the old domain:

| Category | What is checked |
|----------|-----------------|
| **Services** | Run-as accounts, executable paths |
| **Scheduled tasks** | Principals, action paths |
| **Applications** | Machine and user installs (filtered in slim mode) |
| **User profiles** | Profile paths and activity (configurable lookback) |
| **Mapped drives** | UNC paths per user |
| **Printers** | Local and network (server names) |
| **ODBC** | Machine and user DSNs |
| **Local groups** | Domain accounts in local groups (e.g. Administrators) |
| **Credentials** | Windows Credential Manager (targets/usernames, not passwords) |
| **Certificates** | Machine/user stores, SANs, IIS/RDP bindings |
| **Firewall** | Rules with domain references |
| **DNS** | Suffix search list, per-adapter DNS |
| **IIS** | Sites, app pools, bindings (if installed) |
| **SQL Server** | Logins, linked servers, jobs, config files (if installed) |
| **Event logs** | Domain mentions (configurable lookback) |
| **Config files** | Domain refs and credential indicators (redacted in output); can be skipped with `-ExcludeConfigFiles` for faster runs |
| **Hard-coded refs** | Registry, files, task XML (FQDN, NetBIOS, LDAP, UNC) |
| **Scripts** | PS1, BAT, VBS referenced by services/tasks |
| **Security agents** | CrowdStrike, Qualys, SCCM, EnCase (tenant info) |
| **Other** | Auto-admin logon, GPO machine DN, Quest ODMAD, Oracle, RDS licensing, server summary |

Detection uses **FQDN**, **NetBIOS**, **UPN**, **LDAP DN/URL**, and **UNC** patterns. Account strings are normalized (DOMAIN\User, user@domain.com, SIDs) and flagged as old-domain when they match.

---

## Files in this folder

| File | Purpose |
|------|---------|
| **Get-WorkstationDiscovery.ps1** | Main discovery script (run locally or as the payload for remote runs). |
| **Invoke-MigrationDiscoveryRemotely.ps1** | Launcher: runs discovery on many servers via WinRM, optionally collects JSON. |
| **DomainMigrationDiscovery.Helpers.psm1** | Helper module (domain refs, SQL/IIS/event log, Oracle, RDS, etc.). Loaded automatically. |
| **DomainMigrationDiscovery.Helpers.psd1** | Module manifest. |
| **migration-config.example.json** | Example config for domains and tenant maps (CrowdStrike, Qualys, EnCase). |

---

## Configuration file (recommended)

Use a JSON config file to set domains and tenant maps in one place. Command-line parameters **override** config values.

1. Copy the example and edit:
   ```powershell
   Copy-Item .\migration-config.example.json .\migration-config.json
   # Edit migration-config.json with your domains and tenant IDs
   ```

2. Run with config only:
   ```powershell
   .\Get-WorkstationDiscovery.ps1 -ConfigFile ".\migration-config.json"
   ```

3. Or override specific values:
   ```powershell
   .\Get-WorkstationDiscovery.ps1 -ConfigFile ".\migration-config.json" -OldDomainFqdn "override.com"
   ```

### Config file properties

| Property | Type | Description |
|----------|------|-------------|
| **OldDomainFqdn** | string | Old domain FQDN (e.g. `oldco.com`). |
| **NewDomainFqdn** | string | New domain FQDN (e.g. `newco.com`). |
| **OldDomainNetBIOS** | string | Old domain NetBIOS (e.g. `OLDCO`). Optional but improves detection. |
| **CrowdStrikeTenantMap** | object | Map CU hex values → tenant names. Use `DEFAULT` for unmapped CU, `UNKNOWN` when CU not found. |
| **QualysTenantMap** | object | Map ActivationID GUIDs → tenant names. Use `DEFAULT` and `UNKNOWN` similarly. |
| **EncaseRegistryPaths** | array | Registry key names under `HKLM\SOFTWARE\Microsoft\` used to identify EnCase tenant (e.g. `Encase_NewDomain`, `Encase_OldDomain`). |

**Finding tenant values:**

- **CrowdStrike:** Registry `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim` → value `CU` (hex), or Falcon console.
- **Qualys:** Registry `HKLM\SOFTWARE\Qualys` → `ActivationID`, or Qualys Cloud Platform.
- **EnCase:** Configure key names under `HKLM\SOFTWARE\Microsoft\` that indicate tenant.

Example snippet:

```json
{
  "OldDomainFqdn": "oldco.com",
  "NewDomainFqdn": "newco.com",
  "OldDomainNetBIOS": "OLDCO",
  "CrowdStrikeTenantMap": {
    "CU_HEX_VALUE_1": "CS NewCo1",
    "DEFAULT": "Oldco",
    "UNKNOWN": "Unknown"
  },
  "QualysTenantMap": {
    "ACTIVATION_ID_GUID": "Qualys NewCo",
    "DEFAULT": "OldCo",
    "UNKNOWN": "Unknown"
  },
  "EncaseRegistryPaths": ["Encase_NewDomain", "Encase_OldDomain"]
}
```

---

## Get-WorkstationDiscovery.ps1 — All parameters

### Required (or from config)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **OldDomainFqdn** | string | `OldCo.com` | FQDN of the old domain to detect. |
| **NewDomainFqdn** | string | `NewCo.com` | FQDN of the new domain. |

### Optional — Paths and output

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **OutputRoot** | string | `C:\temp\MigrationDiscovery\out` | Where to write the JSON file (local or UNC). |
| **LogRoot** | string | `C:\temp\MigrationDiscovery\logs` | Where to write log files. |
| **CentralShare** | string | — | UNC path (e.g. `\\server\share`). If set, JSON is also copied to `{CentralShare}\workstations\{filename}.json`. |

### Optional — Domain and context

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **OldDomainNetBIOS** | string | — | NetBIOS name of old domain (recommended for better detection). |
| **PlantId** | string | — | Plant/facility identifier for multi-site use. |

### Optional — Time windows

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **ProfileDays** | int | 30 | Days to look back for user profile activity. |
| **EventLogDays** | int | 7 | Days to look back in event logs for domain references. |

### Optional — Slim mode (filtering)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **SlimOutputOnly** | switch | `$true` | Filter out Microsoft-built-in apps/services; same JSON structure, less noise. |
| **KeepOffice** | switch | `$false` | In slim mode, keep Microsoft Office in output. |
| **KeepEdgeOneDrive** | switch | `$false` | In slim mode, keep Edge and OneDrive. |
| **KeepMsStoreApps** | switch | `$false` | In slim mode, keep Microsoft Store apps. |
| **SlimOnlyRunningServices** | switch | `$false` | In slim mode, only include running services. |

### Optional — Other

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **ConfigFile** | string | — | Path to JSON config (domains + tenant maps). CLI params override config. |
| **ExcludeConfigFiles** | switch | `$false` | Skip scanning for application config files (faster discovery when not needed). |
| **IncludeAppx** | switch | `$false` | Include AppX (Store) packages in application discovery. |
| **EmitStdOut** | switch | `$false` | Emit a summary JSON object to stdout in addition to the file. |
| **SelfTest** | switch | `$false` | Run lightweight validation only (no full discovery). |
| **AppDiscoveryConfigPath** | string | — | Path to JSON that defines app-specific registry roots and folders to scan. |

---

## App-specific discovery (optional)

To scan custom registry keys and folders for domain references (e.g. backup or ERP configs), use **AppDiscoveryConfigPath**.

1. Create a JSON file (e.g. `app-discovery.json`):

```json
[
  {
    "Name": "BackupToolX",
    "RegistryRoots": [
      "HKLM:\\SOFTWARE\\Vendor\\BackupToolX"
    ],
    "Folders": [
      "D:\\BackupToolX\\Configs"
    ]
  }
]
```

2. Run:

```powershell
.\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com" -AppDiscoveryConfigPath ".\app-discovery.json"
```

- **RegistryRoots:** Recursively scanned (max depth 10) for domain patterns.
- **Folders:** Scanned for `.config`, `.ini`, `.xml`, `.json`, `.conf`, `.properties`, `.txt` (depth limit 3).

---

## Remote execution (many servers)

Use **Invoke-MigrationDiscoveryRemotely.ps1** to run discovery on multiple machines via WinRM and optionally collect JSON to a share or to the jump host.

### Quick start (remote)

1. Create a server list (one name per line; `#` and blank lines ignored):

   ```
   SERVER01
   SERVER02
   # SERVER03
   ```

2. From repo root (script path is relative to repo):

   ```powershell
   .\domain-discovery\Invoke-MigrationDiscoveryRemotely.ps1 `
       -ServerListPath ".\servers.txt" `
       -ScriptPath ".\domain-discovery\Get-WorkstationDiscovery.ps1" `
       -OldDomainFqdn "olddomain.com" `
       -NewDomainFqdn "newdomain.com" `
       -CollectorShare "\\fileserver\MigrationDiscovery\workstations"
   ```

3. If you `cd domain-discovery` first, you can omit `-ScriptPath` (default is `.\Get-WorkstationDiscovery.ps1`).

You will be prompted for credentials if not already running with an account that has local admin on all targets.

### Invoke-MigrationDiscoveryRemotely.ps1 — Parameters

| Parameter | Required | Default | Description |
|-----------|----------|--------|-------------|
| **ServerListPath** | Yes | — | Text file: one server name per line. |
| **ScriptPath** | No | `.\Get-WorkstationDiscovery.ps1` | Path to `Get-WorkstationDiscovery.ps1`. |
| **RemoteOutputRoot** | No | `C:\temp\MigrationDiscovery\out` | On each remote server, where JSON is written. |
| **RemoteLogRoot** | No | `C:\temp\MigrationDiscovery\logs` | On each remote server, where logs are written. |
| **CollectorShare** | No | — | UNC path. If set, JSON files are copied here from each server. If **not** set, JSON is collected from each server’s C$ to `{ScriptDir}\results\out\`. |
| **OldDomainFqdn** | Yes* | — | Old domain FQDN (*or in ConfigFile). |
| **NewDomainFqdn** | Yes* | — | New domain FQDN (*or in ConfigFile). |
| **OldDomainNetBIOS** | No | — | Old domain NetBIOS. |
| **NewDomainNetBIOS** | No | — | Not used by discovery script; optional for your notes. |
| **PlantId** | No | — | Plant/facility identifier. |
| **ConfigFile** | No | — | Path to migration config JSON. File is copied to each remote at `C:\temp\MigrationDiscovery\config.json` and passed to the discovery script. |
| **ExcludeConfigFiles** | No | `$false` | Skip config file scanning on each remote (faster discovery). |
| **EmitStdOut** | No | `$false` | Emit summary JSON to stdout per server. |
| **UseParallel** | No | `$false` | Run discovery in parallel (PowerShell 7+; throttle 10). |
| **AttemptWinRmHeal** | No | `$false` | If WinRM connect fails with a service-type error, try to start WinRM on the remote and retry once. |
| **UseSmbForResults** | No | `$false` | Retrieve JSON via `\\server\c$` or CollectorShare instead of WinRM return. |
| **Credential** | No | — | PSCredential for remote access; if omitted, you are prompted or current user is used. |

### Remote behavior summary

- Servers are read from the list; blank and `#` lines are skipped; names are de-duplicated.
- WinRM connectivity is tested before running discovery.
- Discovery runs with the given (or config-loaded) domain and options; helper module is staged under `C:\temp\MigrationDiscovery\run` on each remote.
- If **CollectorShare** is set: JSON is copied to that share.
- If **CollectorShare** is not set: JSON is collected from each server (e.g. via C$) into `domain-discovery\results\out\`.
- Errors (e.g. connection or script failure) are logged to `domain-discovery\results\error.log`; other servers still run.

---

## Output and logging

- **JSON file:** `{OutputRoot}\{COMPUTERNAME}_{MM-dd-yyyy}.json`. Same schema for slim and full; slim only filters content (e.g. Microsoft apps/services).
- **Log file:** `{LogRoot}\{COMPUTERNAME}_Discovery_{MM-dd-yyyy_HH-mm-ss}.log`.
- **Security:** Config-file matched lines and event-log snippets are redacted (e.g. passwords, tokens) in JSON. Formula-injection prevention is applied for downstream Excel (cells starting with `=`, `+`, `-`, `@` are escaped).

---

## Self-test mode

To validate the script without a full scan:

```powershell
.\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com" -SelfTest
```

Runs lightweight checks (e.g. local admin discovery, service account parsing, registry/file patterns) and exits early with pass/fail style output.

---

## Requirements and permissions

- **PowerShell:** 5.1 or higher (3.0+ for minimal use; some features need 5.1+).
- **OS:** Windows 7 / Server 2008 R2 or later.
- **Permissions:** Local Administrator for full discovery; read access to user profile dirs; write access to OutputRoot and LogRoot.
- **Remote:** WinRM enabled on targets; account with local admin on all target servers; network to WinRM (typically 5985/5986).

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| Execution policy | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| “Configuration file not found” | Use full path for `-ConfigFile` or run from the folder that contains the JSON. |
| Central share copy fails | Script continues with local output only; check UNC and write permissions. |
| Remote “script not found” | Pass correct `-ScriptPath` from repo root (e.g. `.\domain-discovery\Get-WorkstationDiscovery.ps1`) or run from `domain-discovery` and omit it. |
| Remote WinRM failures | Ensure WinRM is enabled and reachable; use `-AttemptWinRmHeal` only when the failure is due to WinRM service not running. |
| Slow run | Large profile count, many services/tasks, or slow network shares increase run time; use `-SlimOutputOnly` and consider `-SlimOnlyRunningServices`. |

For more detail on JSON schema, detection logic, and workbook integration, see the main [README](../README.md) in the repository root.
