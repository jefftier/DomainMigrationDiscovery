# Security Tools Status

Check **CrowdStrike**, **Qualys**, **SCCM**, and **EnCase** status on one or more remote Windows servers over WinRM. Use either the **CLI** script or the **GUI** for interactive runs.

---

## Get running in 2 minutes

**Prerequisites:** PowerShell 5.1+, Windows, WinRM reachable to target servers, and an account with local admin on those servers.

### Option A — GUI (easiest)

1. Run the GUI:
   ```powershell
   .\Get-SecurityToolsStatus-GUI.ps1
   ```

2. When prompted, enter credentials (or Cancel to use current user).

3. In the window:
   - **Old Domain FQDN** / **New Domain FQDN:** Your old and new domain names (e.g. `oldco.com`, `newco.com`).
   - **Config File (Optional):** Browse to a `migration-config.json` if you use one (same format as [domain-discovery](../domain-discovery/README.md#configuration-file-recommended)); otherwise leave blank.
   - **Server List:** Type or paste server names, one per line.

4. Click **Run Check**. Results appear in the table (Qualys, CrowdStrike, SCCM, Encase columns).

### Option B — CLI (one server)

```powershell
.\Get-SecurityToolsStatus.ps1 -ComputerName "SERVER01" -OldDomainFqdn "oldco.com" -NewDomainFqdn "newco.com"
```

### Option C — CLI (many servers from file)

1. Create `servers.txt` (one name per line; `#` and blank lines ignored):
   ```
   SERVER01
   SERVER02
   ```

2. Run (optionally with config for tenant maps):
   ```powershell
   .\Get-SecurityToolsStatus.ps1 -ServerListPath ".\servers.txt" -ConfigFile ".\config\migration-config.json"
   ```

Domains can come from **ConfigFile**; if you use a config file, you can omit `-OldDomainFqdn` and `-NewDomainFqdn` if they are set in the JSON.

---

## What is checked

| Tool | What the script reports |
|------|--------------------------|
| **CrowdStrike (Falcon)** | Installed or not; registry `HKLM\...\CSAgent\Sim` → `CU` (hex); **Tenant** from your CrowdStrike tenant map (e.g. config file). |
| **Qualys** | Installed or not; registry `HKLM\SOFTWARE\Qualys` → `ActivationID`; **Tenant** from your Qualys tenant map. |
| **SCCM (Config Manager)** | Whether CCM registry path exists; domain references found under that path; **Tenant** (e.g. OldDomain, NewDomain, or listed domains). |
| **EnCase** | Whether `enstart64` service exists; tenant from registry keys under `HKLM\SOFTWARE\Microsoft\` (keys configured in config as **EncaseRegistryPaths**). |

The same **migration-config.json** format used by [domain-discovery](../domain-discovery/README.md#configuration-file-recommended) is supported here for **OldDomainFqdn**, **NewDomainFqdn**, **CrowdStrikeTenantMap**, **QualysTenantMap**, and **EncaseRegistryPaths**.

---

## Files in this folder

| File | Purpose |
|------|---------|
| **Get-SecurityToolsStatus.ps1** | CLI: single server (`-ComputerName`) or list from file (`-ServerListPath`). Optional config file, parallel execution (PS7+), optional WinRM heal. |
| **Get-SecurityToolsStatus-GUI.ps1** | WPF GUI: credential prompt, domain/config inputs, server list text box, results grid. Runs checks in the background. |

---

## Get-SecurityToolsStatus.ps1 — All parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| **ComputerName** | No* | — | Single server to check. *Mutually exclusive with ServerListPath.* |
| **ServerListPath** | No* | `.\servers.txt` | Text file: one server per line. *Mutually exclusive with ComputerName.* |
| **OldDomainFqdn** | No** | — | Old domain FQDN (for SCCM and context). **Required for SCCM domain detection unless provided in ConfigFile.** |
| **NewDomainFqdn** | No** | — | New domain FQDN (for SCCM and context). **Required for SCCM domain detection unless in ConfigFile.** |
| **ConfigFile** | No | — | Path to JSON config (domains + CrowdStrike/Qualys/EnCase maps). Same format as domain-discovery. |
| **UseParallel** | No | `$false` | Run checks in parallel (PowerShell 7+). |
| **AttemptWinRmHeal** | No | `$false` | If connection fails with a WinRM service-type error, try to start WinRM on the remote and retry once. Not used for auth or network failures. |
| **Credential** | No | — | PSCredential for remote access; if omitted, you are prompted or current user is used. |

You must provide either **ComputerName** or **ServerListPath** (or rely on default `.\servers.txt` if that file exists). For SCCM tenant/domain detection, either pass **OldDomainFqdn** and **NewDomainFqdn** or provide them in **ConfigFile**.

---

## Get-SecurityToolsStatus-GUI.ps1 — Usage

- **No command-line parameters.** All input is in the window.
- **Credential:** Prompted at startup; you can Cancel to use current user.
- **Old Domain FQDN / New Domain FQDN:** Required for the Run Check; used for SCCM and for loading tenant maps if you specify a config file.
- **Config File (Optional):** Full path to a JSON config file. If set, the GUI loads **CrowdStrikeTenantMap**, **QualysTenantMap**, and **EncaseRegistryPaths** from it (same format as domain-discovery). Optional; you can leave it blank and still run checks (tenant columns may show raw values or defaults).
- **Server list:** One server name per line in the text box. Blank and comment lines are ignored when running.
- **Run Check:** Runs the same logic as the CLI against each server (sequentially in the GUI), then fills the results grid (Server, Qualys, CrowdStrike, SCCM, Encase).
- **Results:** Shown in the DataGrid; you can resize columns and scroll. Status text at the bottom shows progress/errors.

---

## Configuration file (shared with domain-discovery)

Use the same **migration-config.json** format as in [domain-discovery](../domain-discovery/README.md#configuration-file-recommended). Relevant keys:

| Property | Use in security-tools-status |
|----------|------------------------------|
| **OldDomainFqdn** | SCCM domain detection; can be omitted if you type domains in the GUI. |
| **NewDomainFqdn** | SCCM domain detection; same as above. |
| **CrowdStrikeTenantMap** | Maps CU hex → display name (DEFAULT/UNKNOWN supported). |
| **QualysTenantMap** | Maps ActivationID → display name (DEFAULT/UNKNOWN supported). |
| **EncaseRegistryPaths** | Array of registry key names under `HKLM\SOFTWARE\Microsoft\` used to identify EnCase tenant. |

Example (same as domain-discovery):

```json
{
  "OldDomainFqdn": "oldco.com",
  "NewDomainFqdn": "newco.com",
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

## WinRM and connectivity

- **WinRM** must be enabled and reachable on each target (typically ports 5985/5986). The script tests connectivity before running the security check.
- **AttemptWinRmHeal** (CLI only): When a connection fails and the error is classified as a **WinRM service** issue (not auth, not network), the script can try to start the WinRM service on the remote and retry once. Auth and network errors are never “healed.”
- **Credentials:** If you don’t pass `-Credential` (CLI) or cancel the credential prompt (GUI), the current user is used. That account must have local admin (or equivalent) on the target servers for registry/service checks.

---

## Requirements

- **PowerShell:** 5.1 or higher (GUI and CLI). For **UseParallel** in the CLI, PowerShell 7+.
- **OS:** Windows (WPF for GUI; WinRM and registry access for checks).
- **Network:** WinRM access to all target servers.
- **Permissions:** Account with local administrator rights on target servers.

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| “Either ComputerName or ServerListPath must be provided” | Pass `-ComputerName "SERVER01"` or `-ServerListPath ".\servers.txt"` (or create `servers.txt` and use default). |
| “OldDomainFqdn is required” | Provide `-OldDomainFqdn` and `-NewDomainFqdn` on the CLI, or set them in the config file and pass `-ConfigFile`. In the GUI, fill Old/New Domain FQDN. |
| WinRM connection fails | Verify WinRM is enabled and firewall allows it; use `-AttemptWinRmHeal` only when the failure is due to WinRM service not running. |
| GUI doesn’t start | Ensure PowerShell 5.1+ and that no execution policy is blocking the script; run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` if needed. |
| Tenant shows “Unknown” or raw value | Add or fix **CrowdStrikeTenantMap** / **QualysTenantMap** / **EncaseRegistryPaths** in your config and point the CLI or GUI to that config file. |

For domain discovery and full migration workflow, see the main [README](../README.md) and [domain-discovery](../domain-discovery/README.md).
