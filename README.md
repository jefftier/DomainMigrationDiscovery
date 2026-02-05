# Domain Migration Discovery

A comprehensive toolkit for discovering domain migration readiness: scan workstations for old domain references, check security tool status, and build Excel reports from JSON results.

## Repository structure (by function)

| Function | Folder | Purpose |
|----------|--------|---------|
| **Domain discovery** | `domain-discovery/` | Scan workstations for old domain references (services, tasks, credentials, etc.); run locally or remotely. |
| **Workbook builder** | `workbook-builder/` | Build Excel workbooks from discovery JSON (CLI and GUI). |
| **Security tools status** | `security-tools-status/` | Check CrowdStrike, Qualys, SCCM, and EnCase status on remote servers (CLI and GUI). |

Shared config lives in `config/` (e.g. `config/migration-config.example.json`).

## Quick Reference

### Basic Discovery (from repo root)
```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com"
```

### Using Configuration File
```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 -ConfigFile ".\config\migration-config.json"
```

### Remote Execution (Multiple Servers)
When running from the repo root, pass the discovery script path explicitly:
```powershell
.\domain-discovery\Invoke-MigrationDiscoveryRemotely.ps1 `
    -ServerListPath ".\servers.txt" `
    -ScriptPath ".\domain-discovery\Get-WorkstationDiscovery.ps1" `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -ConfigFile ".\config\migration-config.json"
```
If you `cd domain-discovery` first, you can omit `-ScriptPath` (default is `.\Get-WorkstationDiscovery.ps1`).

### Build Excel Report from JSON Results
```powershell
python workbook-builder\build_migration_workbook.py -i "Y:\results" -o "."
```

### Security Tools Status (CLI or GUI)
```powershell
.\security-tools-status\Get-SecurityToolsStatus.ps1 -ServerListPath ".\servers.txt" -ConfigFile ".\config\migration-config.json"
.\security-tools-status\Get-SecurityToolsStatus-GUI.ps1
```

### Smoke run (end-to-end, no new dependencies)
```powershell
# 1. Run discovery locally (writes JSON to C:\temp\MigrationDiscovery\out)
.\domain-discovery\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "oldco.com" -NewDomainFqdn "newco.com" -SlimOutputOnly

# 2. Build workbook from that folder (adjust -i if you use a different output path)
python workbook-builder\build_migration_workbook.py -i "C:\temp\MigrationDiscovery\out" -o "."

# 3. Open the generated *MigrationDiscovery_*.xlsx and verify Summary, Config File Findings, Config Summary, Oracle Summary, RDS Licensing, Local Admin Membership tabs
```

**Key files by function:**
- **Domain discovery:** `domain-discovery/Get-WorkstationDiscovery.ps1`, `domain-discovery/Invoke-MigrationDiscoveryRemotely.ps1`, `domain-discovery/DomainMigrationDiscovery.Helpers.psm1`
- **Workbook builder:** `workbook-builder/build_migration_workbook.py`, `workbook-builder/gui_app.py`
- **Security tools:** `security-tools-status/Get-SecurityToolsStatus.ps1`, `security-tools-status/Get-SecurityToolsStatus-GUI.ps1`
- **Config:** `config/migration-config.example.json`

## Overview

This script performs a deep discovery of Windows workstations to identify all references to an old domain that may need to be updated during a domain migration. It collects data about services, scheduled tasks, applications, printers, ODBC connections, local group memberships, credentials, certificates, firewall rules, DNS configuration, and more.

## Features

### Core Capabilities

- **Comprehensive Discovery**: Scans 30+ areas of Windows configuration for domain references
- **Slim Output Mode**: Filter out Microsoft-built-in applications and services for cleaner output
- **JSON Output**: Structured JSON output for easy parsing and integration
- **Self-Documenting Schema**: JSON output includes embedded schema documentation for Power BI and custom web applications
- **Central Share Support**: Optionally copy results to a central network share
- **Remote Execution**: Launcher script for executing discovery on multiple servers via PowerShell Remoting
- **Parallel Processing**: Support for parallel execution across multiple servers (PowerShell 7+)
- **Headless Operation**: Designed for automated execution without user interaction
- **Multi-Profile Support**: Scans all user profiles on the system
- **Error Handling**: Robust error handling with detailed logging
- **Error Logging**: Automatic error logging to `results\error.log` for remote execution
- **Automatic File Collection**: Automatically collects JSON files from remote servers when `CollectorShare` is not specified
- **Self-Test Mode**: Lightweight validation mode for testing discovery functions
- **App-Specific Discovery**: Config-driven deep scanning of application-specific registry keys and folders
- **Database Connection Parsing**: Structured parsing of database connection strings with password protection
- **Script & Automation Discovery**: Targeted discovery of script files referenced by services and tasks
- **Server Summary**: Aggregated file server and print server references for reporting
- **Configuration File Support**: Load domain settings and tenant maps from JSON configuration file

### Discovery Areas

The script scans the following areas for old domain references:

1. **Windows Services** - Service accounts and executable paths
2. **Scheduled Tasks** - Task principals and action paths
3. **Installed Applications** - Machine and user-level applications
4. **User Profiles** - Profile information and activity
5. **Mapped Network Drives** - Per-user drive mappings
6. **Printers** - Local and network printers
7. **ODBC Data Sources** - Machine and user-level ODBC connections
8. **Local Group Memberships** - Domain accounts in local groups
9. **Local Administrators** - Domain accounts with admin rights
10. **Local Accounts** - Local users and groups with usage tracking
11. **Shared Folders** - File shares with ACLs
12. **Windows Credential Manager** - Stored credentials (per-user and current user)
13. **Certificate Stores** - Machine and user certificate stores with SAN analysis
14. **Certificate Endpoints** - IIS HTTPS bindings and RDP SSL configurations
15. **Firewall Rules** - Windows Firewall rules with domain references
16. **DNS Configuration** - DNS suffix search lists and per-adapter DNS
17. **IIS Configuration** - Websites, application pools, and bindings (if IIS is installed)
18. **SQL Server** - SQL logins, linked servers, jobs, and config files (if SQL Server is installed)
19. **Event Logs** - Domain references in Windows event logs
20. **Application Configuration Files** - Config files with domain references and embedded credentials
21. **Hard-Coded References** - Aggressive scanning of registry, files, scheduled task XML for domain references
22. **Script & Automation Files** - PowerShell, batch, VBScript files referenced by services/tasks
23. **Database Connection Strings** - Parsed connection strings from ODBC, registry, and config files
24. **App-Specific Discovery** - Config-driven deep scanning of application-specific locations
25. **Server Summary** - Aggregated file server and print server references
26. **Security Agents** - CrowdStrike, Qualys, SCCM, and EnCase agent tenant information
27. **Quest ODMAD** - Quest On Demand Migration for Active Directory configuration
28. **Auto Admin Logon** - Registry-based auto-logon configuration
29. **GPO Machine DN** - Group Policy Object machine distinguished name

## Requirements

- **PowerShell Version**: 5.1 or higher (full features), 3.0+ for basic functionality
- **Windows OS**: Windows 7/Server 2008 R2 or later
- **Permissions**: 
  - Local Administrator rights (for full discovery)
  - Read access to user profile directories
  - Write access to output and log directories

## Installation

1. Clone or download this repository
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Basic Usage

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com"
```

### Common Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `OldDomainFqdn` | String | Yes | `olddomain.com` | FQDN of the old domain to detect |
| `NewDomainFqdn` | String | Yes | `newdomain.com` | FQDN of the new domain |
| `OldDomainNetBIOS` | String | No | - | NetBIOS name of the old domain |
| `OutputRoot` | String | No | `C:\temp\MigrationDiscovery\out` | Local path for JSON output |
| `LogRoot` | String | No | `C:\temp\MigrationDiscovery\logs` | Local path for log files |
| `CentralShare` | String | No | - | UNC path to central share (e.g., `\\server\share`) |
| `ProfileDays` | Int | No | 30 | Days to look back for profile activity |
| `EventLogDays` | Int | No | 7 | Days to look back in event logs |
| `PlantId` | String | No | - | Optional plant/facility identifier |
| `SlimOutputOnly` | Switch | No | `$true` | Enable slim output mode (filter Microsoft apps) |
| `KeepOffice` | Switch | No | `$false` | Keep Microsoft Office apps in slim mode |
| `KeepEdgeOneDrive` | Switch | No | `$false` | Keep Edge/OneDrive in slim mode |
| `KeepMsStoreApps` | Switch | No | `$false` | Keep Microsoft Store apps in slim mode |
| `SlimOnlyRunningServices` | Switch | No | `$false` | Only include running services in slim mode |
| `IncludeAppx` | Switch | No | `$false` | Include AppX packages in discovery |
| `EmitStdOut` | Switch | No | `$false` | Emit summary JSON to stdout |
| `ExcludeConfigFiles` | Switch | No | `$false` | Skip scanning for application config files (faster discovery) |
| `SelfTest` | Switch | No | `$false` | Run lightweight self-test validation mode |
| `AppDiscoveryConfigPath` | String | No | - | Path to JSON config file for app-specific discovery |
| `ConfigFile` | String | No | - | Path to JSON configuration file for domain settings, tenant maps (CrowdStrike, Qualys), and EnCase registry paths |

### Example: Full Discovery with Central Share

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -OldDomainNetBIOS "OLDDOMAIN" `
    -CentralShare "\\fileserver\migration" `
    -OutputRoot "C:\temp\discovery\out" `
    -LogRoot "C:\temp\discovery\logs" `
    -PlantId "PLANT001" `
    -EmitStdOut
```

### Example: Slim Output with Custom Filters

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -SlimOutputOnly `
    -KeepOffice `
    -SlimOnlyRunningServices
```

### Example: App-Specific Discovery

Create a JSON configuration file (`app-discovery.json`):

```json
[
  {
    "Name": "App1",
    "RegistryRoots": [
      "HKLM:\\SOFTWARE\\Vendor\\App1",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\App1Service"
    ],
    "Folders": [
      "C:\\ProgramData\\Vendor\\App1",
      "C:\\App1\\Config"
    ]
  },
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

Run discovery with app-specific scanning:

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -AppDiscoveryConfigPath ".\app-discovery.json"
```

### Example: Self-Test Mode

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -SelfTest
```

### Example: Skip Config File Scanning (Faster Discovery)

To reduce discovery time when scanning application config files is slow or not needed:

```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -ExcludeConfigFiles
```

For remote runs, pass the same switch to the launcher so each remote run skips config file scanning:

```powershell
.\domain-discovery\Invoke-MigrationDiscoveryRemotely.ps1 `
    -ServerListPath ".\servers.txt" `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -ExcludeConfigFiles
```

### Example: Using Configuration File

The script supports loading domain settings and tenant maps from a JSON configuration file. This is useful for:
- Centralizing configuration across multiple workstations
- Managing CrowdStrike, Qualys, and EnCase tenant mappings
- Simplifying command-line usage

**Important**: Command-line parameters take precedence over configuration file values. If a parameter is explicitly provided on the command line, the config file value for that parameter is ignored.

Create a JSON configuration file (e.g. `config/migration-config.json`; copy from `config/migration-config.example.json`):

```json
{
  "OldDomainFqdn": "oldco.com",
  "NewDomainFqdn": "newco.com",
  "OldDomainNetBIOS": "OLDCO",
  "CrowdStrikeTenantMap": {
    "CU_HEX_VALUE_1": "CS NewCo1",
    "CU_HEX_VALUE_2": "CS Newco2",
    "DEFAULT": "Oldco",
    "UNKNOWN": "Unknown"
  },
  "QualysTenantMap": {
    "ACTIVATION_ID_GUID": "Qualys NewCo",
    "DEFAULT": "OldCo",
    "UNKNOWN": "Unknown"
  },
  "EncaseRegistryPaths": [
    "Encase_NewDomain",
    "Encase_OldDomain"
  ]
}
```

**Configuration File Properties**:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `OldDomainFqdn` | String | No | Old domain FQDN (only used if not provided as parameter) |
| `NewDomainFqdn` | String | No | New domain FQDN (only used if not provided as parameter) |
| `OldDomainNetBIOS` | String | No | Old domain NetBIOS name (only used if not provided as parameter) |
| `CrowdStrikeTenantMap` | Object | No | Hashtable mapping CU hex values to tenant names |
| `QualysTenantMap` | Object | No | Hashtable mapping ActivationID GUIDs to tenant names |
| `EncaseRegistryPaths` | Array | No | Array of registry paths (relative to `HKLM\SOFTWARE\Microsoft\`) to check for EnCase tenant identification |

**Tenant Map Keys**:
- Custom keys: Your specific CU hex values or ActivationID GUIDs
- `DEFAULT`: Used when a value is found but not in the custom mappings
- `UNKNOWN`: Used when no value is found

**Usage Examples**:

Load all settings from configuration file:
```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 -ConfigFile ".\config\migration-config.json"
```

Override specific parameter (config file values used for others):
```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -ConfigFile ".\config\migration-config.json" `
    -OldDomainFqdn "override.com"
```

Use command-line parameters (config file ignored if all params provided):
```powershell
.\domain-discovery\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "oldco.com" `
    -NewDomainFqdn "newco.com"
```

**Finding Tenant Values**:

- **CrowdStrike CU Values**: Check registry `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim` value `CU`, or check CrowdStrike Falcon console
- **Qualys ActivationID**: Check registry `HKLM\SOFTWARE\Qualys` value `ActivationID`, or check Qualys Cloud Platform
- **EnCase Registry Paths**: Configure registry paths relative to `HKLM\SOFTWARE\Microsoft\` that indicate tenant configuration (e.g., `Encase_NewDomain`, `Encase_OldDomain`)

## Remote Execution

For executing discovery on multiple remote workstations, use the `domain-discovery/Invoke-MigrationDiscoveryRemotely.ps1` launcher script. This script uses PowerShell Remoting (PSRemoting) to execute the discovery script on multiple servers in parallel or sequentially.

### Remote Execution Requirements

- **PowerShell Remoting**: WinRM must be enabled and configured on target servers
- **Credentials**: An account with local administrator rights on all target servers
- **Network Access**: The jump host must be able to reach target servers via WinRM (typically port 5985/5986)
- **PowerShell Version**: 
  - PowerShell 5.1+ for sequential execution
  - PowerShell 7+ for parallel execution (`-UseParallel`)

### Server List File

Create a text file containing one server name per line. Blank lines and lines starting with `#` are ignored:

```
# Production Servers
SERVER01
SERVER02
SERVER03

# Development Servers
DEV-SERVER01
DEV-SERVER02
```

### Remote Execution Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ServerListPath` | String | Yes | - | Path to text file containing server names (one per line) |
| `ScriptPath` | String | No | `.\Get-WorkstationDiscovery.ps1` (when run from `domain-discovery/`) | Path to the discovery script |
| `RemoteOutputRoot` | String | No | `C:\temp\MigrationDiscovery\out` | Local path on remote servers for JSON output |
| `RemoteLogRoot` | String | No | `C:\temp\MigrationDiscovery\logs` | Local path on remote servers for log files |
| `CollectorShare` | String | No | - | UNC path where collected JSON files will be copied (e.g., `\\fileserver\MigrationDiscovery\workstations`) |
| `OldDomainFqdn` | String | Yes | - | FQDN of the old domain to detect |
| `NewDomainFqdn` | String | Yes | - | FQDN of the new domain |
| `OldDomainNetBIOS` | String | No | - | NetBIOS name of the old domain |
| `NewDomainNetBIOS` | String | No | - | NetBIOS name of the new domain (not used by discovery script) |
| `PlantId` | String | No | - | Optional plant/facility identifier |
| `ConfigFile` | String | No | - | Path to migration config JSON (copied to each remote) |
| `ExcludeConfigFiles` | Switch | No | `$false` | Skip config file scanning on each remote (faster discovery) |
| `EmitStdOut` | Switch | No | `$false` | Emit summary JSON to stdout for each server |
| `UseParallel` | Switch | No | `$false` | Execute discovery in parallel (requires PowerShell 7+) |
| `Credential` | PSCredential | No | - | Credentials for remote access (prompts if not provided) |

### Example: Sequential Remote Execution

```powershell
.\domain-discovery\Invoke-MigrationDiscoveryRemotely.ps1 `
    -ServerListPath ".\servers.txt" `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -PlantId "PLANT001" `
    -CollectorShare "\\fileserver\MigrationDiscovery\workstations"
```

### Example: Parallel Remote Execution (PowerShell 7+)

```powershell
.\domain-discovery\Invoke-MigrationDiscoveryRemotely.ps1 `
    -ServerListPath ".\servers.txt" `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -PlantId "PLANT001" `
    -CollectorShare "\\fileserver\MigrationDiscovery\workstations" `
    -UseParallel `
    -EmitStdOut
```

### How Remote Execution Works

1. **Server List Processing**: The launcher reads the server list file, removes blank/commented lines, and de-duplicates server names
2. **Connectivity Check**: For each server, WinRM connectivity is tested before attempting discovery
3. **Remote Execution**: The discovery script is executed on each remote server using `Invoke-Command` with the provided credentials
4. **File Collection** (optional): 
   - If `CollectorShare` is specified, JSON files are copied from each remote server's `RemoteOutputRoot` to the collector share
   - If `CollectorShare` is NOT specified, JSON files are automatically collected from each remote server's C$ admin share to `{ScriptDirectory}\results\out\`
5. **Error Handling**: Failures on individual servers are logged to `results\error.log` but don't stop execution on other servers

### Remote Execution Output

- **On Remote Servers**: JSON and log files are written to the specified `RemoteOutputRoot` and `RemoteLogRoot` directories
- **On Collector Share**: If `CollectorShare` is specified, JSON files are copied with the same naming pattern: `{COMPUTERNAME}_{MM-dd-yyyy}.json`
- **On Local Machine**: If `CollectorShare` is not specified, JSON files are collected to `{ScriptDirectory}\results\out\{COMPUTERNAME}_{MM-dd-yyyy}.json`
- **Error Log**: All errors are logged to `{ScriptDirectory}\results\error.log` with timestamps, server names, and error details
- **Console Output**: Progress messages and errors are displayed in the console, with optional summary JSON output when `-EmitStdOut` is used

### Notes on Remote Execution

- The launcher script will prompt for credentials if not already running with appropriate permissions
- Remote servers must have the discovery script accessible (either locally or via a network share)
- The `-UseParallel` switch uses PowerShell 7+ `ForEach-Object -Parallel` with a throttle limit of 10 concurrent executions
- If a server is unreachable or discovery fails, execution continues with the remaining servers
- JSON files are copied using `Copy-Item -FromSession` or via C$ admin share access
- The script automatically retrieves the actual computer name from remote systems to match JSON filenames

## Output Format

The script generates a JSON file named `{COMPUTERNAME}_{MM-dd-yyyy}.json` in the specified output directory.

### JSON Structure

**Important**: The JSON structure is **identical** regardless of the `SlimOutputOnly` setting. When `SlimOutputOnly` is enabled, the script uses filtered data (excluding Microsoft-built-in applications and services), but the structure remains the same. This ensures consistent ingestion into reporting engines.

The JSON output includes a self-documenting `Schema` section that describes all sections, property types, and data formats for easy integration with Power BI and custom web applications.

### Security and backward compatibility

- **Redaction**: Config file matched lines and event-log snippets are redacted before storage (passwords, tokens, API keys, connection-string values replaced with "REDACTED"). Same JSON structure; no secrets in JSON or Excel.
- **Excel formula injection**: String cells that start with `=`, `+`, `-`, or `@` are escaped so Excel treats them as text, not formulas.
- **New JSON sections**: `Oracle` (server/client discovery) and `RDSLicensing` (RDS/RDP licensing). The workbook builder accepts older JSON that lacks these sections; missing sections produce empty or default rows.

## Complete Data Elements Collected

### Schema
Self-documenting schema object describing all sections, property types, nested structures, and data format conventions. This enables automatic schema validation and Power BI ingestion.

### Metadata
- `GpoMachineDN` - Group Policy Object machine distinguished name
- `ComputerName` - Computer hostname
- `CollectedAt` - ISO 8601 timestamp of collection
- `UserContext` - User account that ran the script
- `Domain` - Current domain membership
- `OldDomainFqdn` - Old domain FQDN being detected
- `OldDomainNetBIOS` - Old domain NetBIOS name
- `NewDomainFqdn` - New domain FQDN
- `ProfileDays` - Days looked back for profile activity
- `PlantId` - Plant/facility identifier
- `Version` - Script version

### System Information
- `Hostname` - Computer hostname
- `Manufacturer` - System manufacturer
- `Model` - System model
- `OSVersion` - Operating system version string (Caption, Version, BuildNumber)
- `IPAddress` - Primary IP address (comma-separated if multiple)
- `MACAddress` - Primary MAC address (comma-separated if multiple)
- `LoggedInUser` - Currently logged in user

### User Profiles
Each profile object contains:
- `SID` - Security Identifier
- `LocalPath` - Profile directory path
- `LastUseTime` - Last profile access timestamp
- `Special` - Whether profile is a special system profile

### Shared Folders
- `Shares` - Array of share objects with:
  - `Name` - Share name
  - `Path` - Share path
  - `Description` - Share description
  - `ACLs` - Access Control List entries (Domain, Account, Permission)
- `Errors` - Array of errors encountered during share enumeration

### Installed Applications (filtered in SlimOutputOnly mode)
Each application object contains:
- `DisplayName` - Application display name
- `DisplayVersion` - Application version
- `Publisher` - Application publisher
- `InstallLocation` - Installation directory
- `KeyPath` - Registry key path
- `Scope` - Installation scope (Machine, User:SID, AppxAllUsers)

### Services (filtered in SlimOutputOnly mode)
Each service object contains:
- `Name` - Service name
- `DisplayName` - Service display name
- `State` - Service state (Running, Stopped, etc.)
- `StartMode` - Service start mode (Automatic, Manual, Disabled)
- `Account` - Service account (run-as account)
- `PathName` - Service executable path with arguments
- `AccountIdentity` - Normalized account identity object (Raw, Name, Domain, Type, Sid, IsOldDomain)
- `HasDomainReference` - Whether service contains old domain reference
- `MatchedField` - Which field matched (Account, PathName)

### Scheduled Tasks (filtered in SlimOutputOnly mode)
Each task object contains:
- `Path` - Task path and name
- `State` - Task state (Ready, Running, Disabled, etc.)
- `Principal` - Task principal (run-as account)
- `AccountIdentity` - Normalized account identity object
- `Actions` - Array of action objects:
  - `ActionType` - Action type (Exec, ComHandler, etc.)
  - `Execute` - Executable path
  - `Arguments` - Command-line arguments
  - `WorkingDir` - Working directory
- `HasDomainReference` - Whether task contains old domain reference
- `MatchedFields` - Array of fields that matched (Principal, Actions)

### Local Group Members
Each member object contains:
- `GroupName` - Group name
- `Members` - Array of member objects with:
  - `Name` - Member name (account name)
  - `SID` - Security Identifier
  - `ObjectClass` - Object class (User, Group, etc.)
  - `PrincipalSource` - Principal source (ActiveDirectory, Local, etc.)
  - `AccountIdentity` - Normalized account identity object
- `HasDomainReference` - Whether group contains old domain members

### Local Administrators (always included)
Each administrator object contains:
- `Name` - Administrator account name
- `Type` - Account type (Domain, Local, BuiltIn)
- `Sid` - Security Identifier
- `IsOldDomain` - Whether account is from old domain
- `Source` - Source of member information

### Local Accounts
Object containing:
- `Users` - Array of local user objects:
  - `Name` - User name
  - `SID` - Security Identifier
  - `Description` - User description
  - `Enabled` - Whether account is enabled
  - `PasswordExpires` - Password expiration date
  - `PasswordLastSet` - Password last set date
  - `PasswordNeverExpires` - Whether password never expires
  - `UserMayChangePassword` - Whether user can change password
  - `AccountExpires` - Account expiration date
  - `LastLogon` - Last logon timestamp
  - `IsBuiltIn` - Whether account is built-in (Administrator, Guest)
  - `AccountIdentity` - Normalized account identity object
  - `Usage` - Usage tracking object:
    - `Services` - Array of service names using this account
    - `ScheduledTasks` - Array of task paths using this account
    - `LocalGroups` - Array of local group names
    - `IsLocalAdministrator` - Whether user is a local administrator
- `Groups` - Array of local group objects:
  - `Name` - Group name
  - `SID` - Security Identifier
  - `Description` - Group description
  - `Members` - Array of member objects with AccountIdentity
  - `IsAdministratorsGroup` - Whether this is the Administrators group

### Mapped Drives
Each drive mapping object contains:
- `SID` - User SID who owns the mapping
- `Drive` - Drive letter
- `Remote` - Remote UNC path
- `Provider` - Network provider name
- `Persistent` - Whether mapping is persistent
- `AccountIdentity` - Normalized account identity (if applicable)
- `HasDomainReference` - Whether mapping references old domain

### Printers (filtered in SlimOutputOnly mode)
Each printer object contains:
- `Name` - Printer name
- `DriverName` - Printer driver name
- `PortName` - Printer port name
- `ShareName` - Printer share name (if shared)
- `ComputerName` - Computer name (for network printers)
- `ServerName` - Server name (for network printers)
- `HasDomainReference` - Whether printer references old domain
- `MatchedField` - Which field matched (PortName, ShareName, ServerName, ComputerName)

### ODBC Data Sources
Each ODBC DSN object contains:
- `Name` - DSN name
- `Driver` - ODBC driver name
- `Server` - Database server name
- `Database` - Database name
- `Trusted` - Whether using trusted connection
- `Scope` - DSN scope (Machine64, Machine32, User:SID)
- `HasDomainReference` - Whether DSN references old domain

### Auto Admin Logon
Object contains:
- `Enabled` - Whether auto-logon is enabled
- `ForceAutoLogon` - Whether force auto-logon is enabled
- `DefaultUserName` - Default username
- `DefaultDomainName` - Default domain name
- `HasDomainReference` - Whether auto-logon references old domain

### Credential Manager
Each credential object contains:
- `Profile` - Profile identifier (SID or "CurrentUser")
- `Target` - Credential target name
- `UserName` - Stored username
- `AccountIdentity` - Normalized account identity object
- `Source` - Source of credential (CredentialManager, Registry)
- `Type` - Credential type (Generic, DomainPassword, etc.)
- `HasDomainReference` - Whether credential contains old domain reference

### Certificates
Each certificate object contains:
- `Store` - Certificate store location (LocalMachine/CurrentUser) and store name
- `Thumbprint` - Certificate thumbprint
- `Subject` - Certificate subject
- `Issuer` - Certificate issuer
- `NotBefore` - Certificate valid from date
- `NotAfter` - Certificate valid to date
- `SANs` - Subject Alternative Names array
- `SANText` - SAN entries as comma-separated string
- `KeyUsages` - Array of key usage OIDs
- `HasDomainReference` - Whether certificate contains old domain reference
- `MatchedFields` - Array of fields that matched (Subject, Issuer, SANs)

### Certificate Endpoints
Each endpoint object contains:
- `Type` - Endpoint type (IIS, RDP)
- `Name` - Endpoint name (site name or "RDP Listener")
- `Protocol` - Protocol (https, tcp)
- `HostHeader` - Host header value (for IIS)
- `IPAddress` - IP address
- `Port` - Port number
- `CertificateThumbprint` - Certificate thumbprint
- `CertificateTiedToOldDomain` - Whether certificate contains old domain reference
- `HasDomainReference` - Whether endpoint itself references old domain
- `MatchedFields` - Array of fields that matched

### Firewall Rules
Each firewall rule object contains:
- `Name` - Rule name
- `DisplayName` - Rule display name
- `Direction` - Rule direction (Inbound, Outbound)
- `Action` - Rule action (Allow, Block)
- `ApplicationPath` - Application path filter
- `LocalUser` - Local user filter
- `RemoteUser` - Remote user filter
- `HasDomainReference` - Whether rule contains old domain reference
- `MatchedField` - Which field matched (DisplayName, Description, Group, LocalUser, RemoteUser, ApplicationPath, ServiceName)

### DNS Configuration
Object contains:
- `PrimaryDNSSuffix` - Primary DNS suffix
- `DNSSuffixSearchList` - DNS suffix search list array
- `PerAdapterDNS` - Array of per-adapter DNS configurations:
  - `InterfaceAlias` - Network adapter name
  - `ServerAddresses` - DNS server addresses array
  - `ConnectionSuffix` - Connection-specific DNS suffix
  - `HasOldDomainReference` - Whether adapter has old domain reference

### IIS Configuration (null if IIS not installed)
Object contains:
- `Sites` - Array of website objects:
  - `Name` - Site name
  - `State` - Site state (Started, Stopped)
  - `Bindings` - Array of binding objects:
    - `Protocol` - Binding protocol (http, https)
    - `BindingInformation` - Full binding information string
    - `HostHeader` - Host header value
    - `IPAddress` - IP address
    - `Port` - Port number
  - `HasDomainReference` - Whether site contains old domain reference
  - `MatchedFields` - Array of fields that matched (Name, Binding, ApplicationPath)
- `AppPools` - Array of application pool objects:
  - `Name` - Application pool name
  - `State` - Application pool state
  - `Identity` - Identity type (ApplicationPoolIdentity, NetworkService, Custom)
  - `AccountIdentity` - Normalized account identity (if custom identity)
  - `HasDomainReference` - Whether app pool contains old domain reference
  - `MatchedField` - Which field matched (Name, IdentityUser)

### SQL Server Configuration (null if SQL Server not installed)
Array of SQL instance objects, each containing:
- `InstanceName` - SQL Server instance name
- `ServiceName` - Windows service name
- `DetectionMethod` - How instance was detected (Service, Registry, WMI)
- `DomainLogins` - Array of domain login objects:
  - `LoginName` - SQL login name
  - `LoginType` - Login type (WindowsUser, WindowsGroup, etc.)
  - `AccountIdentity` - Normalized account identity object
- `LinkedServersWithDomainReferences` - Array of linked server objects:
  - `LinkedServerName` - Linked server name
  - `Provider` - Linked server provider
  - `DataSource` - Data source
  - `RemoteLogin` - Remote login name
  - `AccountIdentity` - Normalized account identity for remote login
  - `MatchedFields` - Array of fields that matched
- `ConfigFilesWithDomainReferences` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `FileName` - File name
  - `MatchedLines` - Array of matched line snippets
  - `TotalMatches` - Total number of matches

### Event Log Domain References
Array of event log entry objects, each containing:
- `LogName` - Event log name (Application, System, Security, etc.)
- `EventId` - Event ID
- `TimeGenerated` - Event timestamp
- `Level` - Event level (Information, Warning, Error, etc.)
- `Message` - Event message (truncated if very long)
- `MatchedField` - Which field matched (Message, UserName, etc.)

### Application Configuration Files
Object contains:
- `FilesWithDomainReferences` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `FileExtension` - File extension
  - `MatchedField` - Which field matched
  - `Snippet` - Snippet of matched content
- `FilesWithCredentials` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `HasCredentials` - Whether file contains embedded credentials
  - `CredentialPatterns` - Array of credential patterns found

### Hard-Coded Domain References
Object containing:
- `OldDomain` - Array of reference objects:
  - `LocationType` - Location type (Registry, File, ScheduledTask, Printer, ServiceConfig, Other)
  - `Location` - Full location path (registry path, file path, etc.)
  - `EvidenceType` - Evidence type (FQDN, NetBIOS, LDAP, UNC)
  - `Value` - Snippet of value where match was found
- `ScriptAutomation` - Array of script file objects:
  - `Path` - Script file path
  - `Type` - Reference type (ScriptFile)
  - `ScriptType` - Script type (PowerShell, Batch, VBScript, etc.)
  - `EvidenceType` - Evidence type (FQDN, NetBIOS, UNC, LDAP)
  - `Snippet` - Snippet of matched content
  - `LineNumber` - Line number where match was found (if available)
  - Limited to 50 files in Slim mode

### App-Specific Discovery (null if AppDiscoveryConfigPath not provided)
Array of app objects, each containing:
- `Name` - Application name from config
- `Hits` - Array of domain reference objects:
  - `LocationType` - Location type (Registry, File)
  - `Location` - Full location path
  - `EvidenceType` - Evidence type (FQDN, NetBIOS, UNC, LDAP)
  - `ValueOrSnippet` - Value or snippet of matched content
  - Limited to 50 hits per app in Slim mode, 1000 in Full mode

### Database Connections
Array of connection objects, each containing:
- `LocationType` - Location type (ODBC, Registry, File)
- `Location` - Descriptive location (e.g., "ODBC DSN: MyDSN (Machine64)" or registry/file path)
- `Parsed` - Parsed connection string object:
  - `Raw` - Full connection string (omitted in Slim mode)
  - `DataSource` - Database server name
  - `InitialCatalog` - Database name
  - `IntegratedSecurity` - Whether using Windows authentication (true/false/null)
  - `UserId` - Username if present
  - `HasPassword` - Boolean flag (password never stored)
  - `IsOldDomainServer` - Whether DataSource matches old domain

### Server Summary
Object containing:
- `FileServers` - Array of file server objects:
  - `Name` - Server name (normalized)
  - `IsOldDomain` - Whether server is from old domain
  - `SourceTypes` - Array of source types (Share, UNCReference, MappedDrive)
  - `Paths` - Array of UNC paths (limited to first 10 in Slim mode)
- `PrintServers` - Array of print server objects:
  - `Name` - Server name (normalized)
  - `IsOldDomain` - Whether server is from old domain
  - `Printers` - Array of printer names

### Security Agents
Object containing security agent information for CrowdStrike, Qualys, SCCM, and EnCase:

- **CrowdStrike**: 
  - `RegPath` - Registry path
  - `ValueName` - Registry value name
  - `Kind` - Registry value type
  - `Raw` - Raw registry value
  - `String` - CU hex value
  - `Tenant` - Tenant name (from tenant map)
  
- **Qualys**:
  - `RegPath` - Registry path
  - `ValueName` - Registry value name
  - `Kind` - Registry value type
  - `Raw` - Raw registry value
  - `String` - ActivationID GUID
  - `Tenant` - Tenant name (from tenant map)
  
- **SCCM**:
  - `RegPath` - Registry path searched
  - `Found` - Whether SCCM registry path exists
  - `DomainReferences` - Array of domain references found
  - `FoundDomains` - Array of domains found
  - `Tenant` - Tenant identifier (OldDomain, NewDomain, Unknown, or found domain)
  - `HasDomainReference` - Whether any domain references were found
  
- **EnCase**:
  - `Installed` - Whether EnCase is installed (based on service detection)
  - `ServiceName` - EnCase service name if found
  - `RegPath` - Registry path to tenant key (if found)
  - `TenantKey` - Registry key name indicating tenant
  - `Tenant` - Tenant identifier (from registry key)

### Quest ODMAD Configuration
Array of Quest configuration objects, each containing:
- `ConfigPath` - Registry path
- `Settings` - Configuration settings object
- `HasDomainReference` - Whether configuration references old domain

### Detection Results
Object contains:
- `OldDomain` - Object with arrays of items containing old domain references:
  - `ServicesRunAsOldDomain` - Array of service names
  - `ServicesOldPathRefs` - Array of service names with old domain in paths
  - `ScheduledTasksWithOldAccounts` - Array of task paths
  - `ScheduledTasksWithOldActionRefs` - Array of task paths
  - `DriveMapsToOldDomain` - Array of drive mappings (format: "Drive->UNC")
  - `LocalGroupsOldDomainMembers` - Array of group memberships (format: "Group: Account")
  - `PrintersToOldDomain` - Array of printer names
  - `OdbcOldDomain` - Array of ODBC DSN names
  - `LocalAdministratorsOldDomain` - Array of administrator account names
  - `CredentialManagerOldDomain` - Array of credentials (format: "Profile: Target (Username)")
  - `CertificatesOldDomain` - Array of certificates (format: "Store: Thumbprint (MatchedField)")
  - `FirewallRulesOldDomain` - Array of firewall rules (format: "Name: DisplayName (MatchedField)")
  - `IISSitesOldDomain` - Array of IIS sites (format: "SiteName (MatchedFields)")
  - `IISAppPoolsOldDomain` - Array of app pools (format: "PoolName (MatchedFields)")
  - `SqlServerOldDomain` - Array of SQL Server references (format: "Instance: Details")
  - `EventLogDomainReferences` - Array of event log entries (format: "LogName: Event ID at Timestamp")
  - `ApplicationConfigFilesOldDomain` - Array of config file paths
  - `HardCodedReferencesOldDomain` - Array of hard-coded references (format: "LocationType: Location")
  - `ScriptAutomationOldDomain` - Array of script files (format: "Path (EvidenceType)")
  - `DatabaseConnectionsOldDomain` - Array of database connections (format: "Location: DataSource")
  - `AppSpecificOldDomain` - Array of app-specific references (format: "App: Location")
  - `FileServersOldDomain` - Array of file server names
  - `PrintServersOldDomain` - Array of print server names
- `Summary` - Summary object:
  - `HasOldDomainRefs` - Boolean indicating if any old domain references were found
  - `Counts` - Object with counts for each category:
    - `Services` - Count of services with old domain accounts
    - `ServicesPath` - Count of services with old domain in paths
    - `TaskPrincipals` - Count of tasks with old domain accounts
    - `TaskActions` - Count of tasks with old domain in actions
    - `Tasks` - Total unique tasks with old domain references
    - `DriveMaps` - Count of drive mappings to old domain
    - `LocalGroups` - Count of local group members from old domain
    - `Printers` - Count of printers referencing old domain
    - `ODBC` - Count of ODBC DSNs referencing old domain
    - `LocalAdmins` - Count of local administrators from old domain
    - `CredentialManager` - Count of credentials referencing old domain
    - `Certificates` - Count of certificates referencing old domain
    - `FirewallRules` - Count of firewall rules referencing old domain
    - `IISSites` - Count of IIS sites referencing old domain
    - `IISAppPools` - Count of IIS app pools referencing old domain
    - `SqlServer` - Count of SQL Server references to old domain
    - `EventLogs` - Count of event log entries referencing old domain
    - `ApplicationConfigFiles` - Count of application config files with old domain references
    - `HardCodedReferences` - Count of hard-coded references
    - `ScriptAutomation` - Count of script files with old domain references
    - `DatabaseConnections` - Count of database connections to old domain servers
    - `AppSpecific` - Count of app-specific references
    - `FileServers` - Count of file servers from old domain
    - `PrintServers` - Count of print servers from old domain

### Slim Mode Behavior

When `SlimOutputOnly` is enabled:
- **InstalledApps**, **Services**, **ScheduledTasks**, and **Printers** contain filtered data (Microsoft-built-in items excluded unless explicitly kept)
- **DatabaseConnections** omits `Raw` connection string (keeps parsed fields only)
- **AppSpecific** limits to 50 hits per app (vs 1000 in Full mode) and truncates snippets to 100 chars (vs 200)
- **ScriptAutomation** limits to 50 script files (stops scanning after 50 matches) and truncates snippets to 100 chars
- **ServerSummary** limits file server paths to first 10 per server (vs all in Full mode)
- **DatabaseConnections** scanning limits to 50 config files per location (vs 200 in Full mode)
- **All other sections** remain fully populated (Profiles, LocalGroupMembers, LocalAccounts, MappedDrives, OdbcDsn, AutoAdminLogon are now included in Slim mode)
- The JSON structure is identical to full mode

## Detection Logic

The script detects old domain references using regex pattern matching in the following formats:
- **NetBIOS Name**: Word boundaries around NetBIOS name (e.g., `\bOLDDOMAIN\b`)
- **FQDN**: Direct FQDN match (e.g., `olddomain.com`)
- **UPN Format**: Email-style format (e.g., `@olddomain.com$`)
- **LDAP DN Format**: Distinguished name format (e.g., `DC=olddomain,DC=com`)
- **LDAP URL Format**: LDAP URLs (e.g., `LDAP://server.olddomain.com`)
- **UNC Path Format**: UNC paths (e.g., `\\server.olddomain.com\share` or `\\olddomain\share`)

The script scans for old domain references in:

- **Service Accounts**: Service start names containing old domain (normalized via `Resolve-AccountIdentity`)
- **Service Paths**: Executable paths referencing old domain
- **Task Principals**: Scheduled task run-as accounts (normalized via `Resolve-AccountIdentity`)
- **Task Actions**: Executable paths in task actions
- **Drive Maps**: Mapped drive UNC paths
- **Printers**: Printer UNC paths and server names
- **ODBC**: Connection strings and server names
- **Local Groups**: Domain accounts in local groups (normalized via `Resolve-AccountIdentity`)
- **Local Accounts**: Local users and groups with usage tracking
- **Credentials**: Windows Credential Manager entries (normalized via `Resolve-AccountIdentity`)
- **Certificates**: Certificate subjects, issuers, and SANs
- **Certificate Endpoints**: IIS HTTPS bindings and RDP SSL configurations
- **Firewall Rules**: Domain account references in firewall rules
- **DNS**: DNS suffix search lists and per-adapter DNS suffixes
- **IIS**: Application pool identities, site bindings, and application paths (normalized via `Resolve-AccountIdentity`)
- **SQL Server**: SQL logins, linked servers, and configuration files (normalized via `Resolve-AccountIdentity`)
- **Application Config Files**: Configuration files containing domain references or embedded credentials (connection strings, etc.)
- **Event Logs**: Event log messages containing domain references
- **Hard-Coded References**: Registry values, config files, scheduled task XML
- **Script Files**: PowerShell, batch, VBScript files referenced by services/tasks
- **Database Connection Strings**: Parsed connection strings from ODBC, registry, and config files
- **App-Specific Locations**: Config-driven scanning of application-specific registry keys and folders

### Account Identity Normalization

The script uses a centralized `Resolve-AccountIdentity` function that normalizes account formats:
- **DOMAIN\User** (NetBIOS format)
- **User@domain.com** (UPN format)
- **Bare User** (local or domain depending on context)
- **SIDs** (resolved to account names)

All normalized accounts include:
- `Raw` - Original account string
- `Name` - Account name only
- `Domain` - Domain or computer name
- `Type` - Account type (Domain, Local, BuiltIn, Unknown)
- `Sid` - Security Identifier (if resolved)
- `IsOldDomain` - Whether account is from old domain

## Logging

The script creates detailed logs in the specified `LogRoot` directory. Log files are named:
- `{COMPUTERNAME}_Discovery_{MM-dd-yyyy_HH-mm-ss}.log`

Logs include:
- Discovery progress
- Errors and warnings
- Validation results
- Performance metrics
- Profile processing status
- Registry access attempts
- Network share access attempts
- App-specific discovery progress
- Database connection discovery progress
- Script automation discovery progress

## Central Share

If `CentralShare` is provided, the script will:
1. Validate the UNC path format
2. Test write access by creating and deleting a test file
3. Copy the JSON output to `{CentralShare}\workstations\{filename}.json`

If validation fails, the script will log a warning but continue with local output only.

## Self-Test Mode

When `-SelfTest` is specified, the script runs lightweight validation tests instead of full discovery:
- Tests local administrator discovery
- Tests service account parsing
- Tests registry scanning patterns
- Tests file scanning patterns
- Outputs concise JSON/table showing pass/fail per area
- Exits early after validation

This mode is useful for quickly validating script behavior across multiple machines before running full discovery.

## App-Specific Discovery

When `-AppDiscoveryConfigPath` is provided, the script performs deep scanning of application-specific locations:

1. **Registry Scanning**: Recursively scans specified registry keys (max depth 10) for domain references
2. **Folder Scanning**: Scans specified folders for config files (`.config`, `.ini`, `.xml`, `.json`, `.conf`, `.properties`, `.txt`) with depth limit of 3
3. **Results**: Returns structured results per app with location, evidence type, and snippets

The config file format is a JSON array:
```json
[
  {
    "Name": "App1",
    "RegistryRoots": ["HKLM:\\SOFTWARE\\Vendor\\App1"],
    "Folders": ["C:\\ProgramData\\Vendor\\App1"]
  }
]
```

Apps with no hits are still included with empty `Hits` arrays so Power BI can show "scanned but clean".

## Performance Considerations

- **Profile Processing**: User profiles are processed efficiently with batched hive operations
- **Large Systems**: On systems with many profiles or services, execution may take several minutes
- **Network Shares**: Accessing network shares may add latency if shares are slow or unavailable
- **Parallel Execution**: Remote execution supports parallel processing (PowerShell 7+) with throttle limit of 10 concurrent executions
- **App-Specific Discovery**: Deep registry and folder scanning may add time; use targeted configs
- **Script Discovery**: Limited to files referenced by services/tasks and well-known directories to avoid full disk scans
- **File Size Limits**: Config files larger than 5MB are skipped to avoid memory issues

## Error Handling

The script includes comprehensive error handling:
- Registry access errors are caught and logged
- Network share access failures are handled gracefully
- Profile loading errors are logged but don't stop execution
- All errors are written to the log file
- Remote execution errors are logged to `results\error.log` with timestamps and server names
- Execution continues even if individual servers fail
- App-specific discovery failures are logged but don't stop overall execution
- Database connection parsing errors are logged but don't stop discovery

## Security Notes

- The script requires local administrator rights for full functionality
- Output JSON files may contain sensitive information (paths, account names, connection strings)
- Ensure output directories have appropriate access controls
- Credential passwords are not extracted (they are encrypted in Windows Vault)
- Database connection passwords are never stored; only `HasPassword` boolean flag is recorded
- The script does not modify any system configuration, only reads and reports
- Script files are read for content scanning but not executed

## Excel Report Builder

The `workbook-builder/build_migration_workbook.py` script generates a comprehensive Excel workbook from JSON discovery results.

### Report Builder Usage

From the repo root:
```powershell
python workbook-builder\build_migration_workbook.py -i "Y:\results" -o "."
```
Or from the `workbook-builder/` folder: `python build_migration_workbook.py -i "Y:\results" -o "."`

**Parameters:**
- `-i, --input`: Folder containing discovery JSON files (default: `Y:\results`)
- `-o, --output-dir`: Folder to write the Excel workbook (default: current directory)
- `-p, --plant-id`: Optional PlantId to use for naming/filtering

### Report Structure

The Excel workbook includes the following sheets:

1. **Summary** - Quick overview with:
   - `HasOldDomainRefs` - Boolean flag for any old domain references
   - `PotentialServiceAccounts` - Count of potential service accounts
   - Security agent status flags:
     - `CrowdStrike_Tenant` and `CrowdStrike_Issue`
     - `Qualys_Tenant` and `Qualys_Issue`
     - `SCCM_Tenant`, `SCCM_HasDomainReference`, and `SCCM_Issue`
     - `Encase_Installed`, `Encase_Tenant`, and `Encase_Issue`
   - Count columns for each discovery category

2. **Metadata** - Complete metadata including domain information (OldDomainFqdn, OldDomainNetBIOS, NewDomainFqdn)

3. **System** - System information

4. **ServiceAccountCandidates** - Comprehensive list of all service accounts from all sources (Services, Scheduled Tasks, IIS App Pools, SQL Logins, Local Admins, Local Groups, Credential Manager, AutoAdminLogon)

5. **Services** - Windows services with old domain detection flags

6. **ScheduledTasks** - Scheduled tasks with old domain detection flags

7. **LocalAdministrators** - Local administrators with domain account identification

8. **LocalGroupMembers** - Local group members with domain account identification

9. **MappedDrives** - Mapped network drives

10. **Printers** - Printers with old domain reference detection

11. **OdbcDsn** - ODBC data sources

12. **CredentialManager** - Windows Credential Manager entries

13. **Certificates** - Certificate stores with domain reference detection

14. **FirewallRules** - Windows Firewall rules

15. **Profiles** - User profiles

16. **InstalledApps** - Installed applications

17. **SharedFolders_Shares** - File shares with:
    - Domain reference detection in Identity field
    - `HasDomainReference`, `IsOldDomainAccount`, `IsDomainAccount` flags
    - `NeedsAttention` flag for accounts requiring migration attention

18. **SharedFolders_Errors** - Errors encountered during share enumeration

19. **DnsSuffixSearchList** - DNS suffix search list (simplified to show only suffixes)

20. **DnsAdapters** - Per-adapter DNS configuration

21. **AutoAdminLogon** - Auto-admin logon configuration

22. **EventLogDomainReferences** - Event log entries with domain references

23. **ApplicationConfigFiles** - Application configuration files (raw JSON)

24. **Config File Findings** - One row per machine per config file finding (FilePath, Extension, MatchCount, HasCredentialIndicators, OldDomainIndicator, MatchedLinesRedacted capped)

25. **Config Summary** - One row per computer: total files with hits, total match count, files credential-flagged, top 5 file paths

26. **Oracle Summary** - Oracle server/client discovery: IsOracleServerLikely, OracleClientInstalled, OracleHomes, OracleODBCDrivers, TnsnamesFiles counts

27. **Oracle Details** - One row per Oracle service (Name, DisplayName, Status, StartType)

28. **RDS Licensing** - RDS/RDP licensing: IsRDSSessionHost, LicensingMode, LicenseServerConfigured, IsRDSLicensingLikelyInUse, RDSLicensingEvidence

29. **Local Admin Membership** - One row per local Administrators group member (GroupName=Administrators, MemberName, MemberType, DomainOrScope, SID, Source). Every computer appears; errors captured.

30. **SecurityAgents** - Security agent information (CrowdStrike, Qualys, SCCM, EnCase)

31. **IIS** - IIS configuration (raw JSON)

32. **SqlServer** - SQL Server configuration (raw JSON)

### Report Builder Features

- **Domain Column Management**: Domain information (OldDomainFqdn, OldDomainNetBIOS, NewDomainFqdn, Domain) is only shown in the Metadata tab to reduce redundancy. Other tabs only display domain information when it's specific to that line (e.g., `AccountDomain` in ServiceAccountCandidates).

- **Security Agent Quick Reference**: The Summary tab includes quick-reference columns for all security agents (CrowdStrike, Qualys, SCCM, EnCase) with issue flags to quickly identify problems:
  - CrowdStrike: Flags "Unknown Tenant" issues
  - Qualys: Flags "Unknown Tenant" issues
  - SCCM: Flags "Domain Reference Found" issues
  - EnCase: Flags "Installed but No Tenant" issues

- **Shared Folders Domain Detection**: The SharedFolders_Shares tab automatically detects domain references in the Identity field and flags accounts of interest for migration attention.

- **Simplified DNS Tabs**: 
  - DnsSummary tab removed (did not contain DNS information)
  - DnsSuffixSearchList simplified to show only suffix information

## Version

Current version: **2.0.0**

### Recent Changes (Latest Update)

- **Report Builder Enhancements**:
  - Added security agent outputs (CrowdStrike, Qualys, SCCM, EnCase) to Summary tab with issue flags
  - Removed redundant domain columns from all tabs except Metadata
  - Enhanced SharedFolders_Shares with domain reference detection in Identity field
  - Removed DnsSummary tab (did not contain DNS information)
  - Simplified DnsSuffixSearchList to show only suffix information
  
- **EnCase Support**:
  - Added EnCase registry path configuration support in config file
  - EnCase tenant detection based on registry keys and service presence
  - EnCase status reporting in Summary tab

- **SCCM Support**:
  - Enhanced SCCM domain reference detection
  - SCCM status reporting in Summary tab with domain reference flags

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Copyright (c) 2025 jefftier

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
