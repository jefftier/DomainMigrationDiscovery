# Domain Migration Discovery Script

A comprehensive PowerShell script for discovering domain migration readiness by scanning workstations for references to old domain configurations, credentials, certificates, and dependencies.

## Overview

This script performs a deep discovery of Windows workstations to identify all references to an old domain that may need to be updated during a domain migration. It collects data about services, scheduled tasks, applications, printers, ODBC connections, local group memberships, credentials, certificates, firewall rules, DNS configuration, and more.

## Features

- **Comprehensive Discovery**: Scans multiple areas including:
  - Windows Services (service accounts, executable paths)
  - Scheduled Tasks (principals, actions)
  - Installed Applications
  - Mapped Network Drives
  - Printers
  - ODBC Data Sources
  - Local Group Memberships
  - Shared Folders with ACLs
  - Windows Credential Manager entries
  - Certificate Stores (machine and user)
  - Firewall Rules
  - DNS Configuration
  - IIS Configuration (if applicable)
  - SQL Server instances (if applicable)
  - Event Log domain references
  - Application Configuration Files (scans all servers for embedded domain references and credentials)

- **Slim Output Mode**: Filter out Microsoft-built-in applications and services for cleaner output
- **JSON Output**: Structured JSON output for easy parsing and integration
- **Central Share Support**: Optionally copy results to a central network share
- **Remote Execution**: Launcher script for executing discovery on multiple servers via PowerShell Remoting
- **Parallel Processing**: Support for parallel execution across multiple servers (PowerShell 7+)
- **Headless Operation**: Designed for automated execution without user interaction
- **Multi-Profile Support**: Scans all user profiles on the system
- **Error Handling**: Robust error handling with detailed logging

## Requirements

- **PowerShell Version**: 5.1 or higher
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
.\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com"
```

### Common Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `OldDomainFqdn` | String | Yes | `OldCo.com` | FQDN of the old domain to detect |
| `NewDomainFqdn` | String | Yes | `NewCo.com` | FQDN of the new domain |
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

### Example: Full Discovery with Central Share

```powershell
.\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "OldCo.com" `
    -NewDomainFqdn "NewCo.com" `
    -OldDomainNetBIOS "" `
    -CentralShare "\\fileserver\migration" `
    -OutputRoot "C:\temp\discovery\out" `
    -LogRoot "C:\temp\discovery\logs" `
    -PlantId "PLANT001" `
    -EmitStdOut
```

### Example: Slim Output with Custom Filters

```powershell
.\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -SlimOutputOnly `
    -KeepOffice `
    -SlimOnlyRunningServices
```

## Remote Execution

For executing discovery on multiple remote workstations, use the `Invoke-MigrationDiscoveryRemotely.ps1` launcher script. This script uses PowerShell Remoting (PSRemoting) to execute the discovery script on multiple servers in parallel or sequentially.

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
| `ScriptPath` | String | No | `.\Get-WorkstationDiscovery.ps1` | Path to the discovery script |
| `RemoteOutputRoot` | String | No | `C:\temp\MigrationDiscovery\out` | Local path on remote servers for JSON output |
| `RemoteLogRoot` | String | No | `C:\temp\MigrationDiscovery\logs` | Local path on remote servers for log files |
| `CollectorShare` | String | No | - | UNC path where collected JSON files will be copied (e.g., `\\fileserver\MigrationDiscovery\workstations`) |
| `OldDomainFqdn` | String | Yes | - | FQDN of the old domain to detect |
| `NewDomainFqdn` | String | Yes | - | FQDN of the new domain |
| `OldDomainNetBIOS` | String | No | - | NetBIOS name of the old domain |
| `NewDomainNetBIOS` | String | No | - | NetBIOS name of the new domain |
| `PlantId` | String | No | - | Optional plant/facility identifier |
| `EmitStdOut` | Switch | No | `$false` | Emit summary JSON to stdout for each server |
| `UseParallel` | Switch | No | `$false` | Execute discovery in parallel (requires PowerShell 7+) |

### Example: Sequential Remote Execution

```powershell
.\Invoke-MigrationDiscoveryRemotely.ps1 `
    -ServerListPath ".\servers.txt" `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
    -PlantId "PLANT001" `
    -CollectorShare "\\fileserver\MigrationDiscovery\workstations"
```

### Example: Parallel Remote Execution (PowerShell 7+)

```powershell
.\Invoke-MigrationDiscoveryRemotely.ps1 `
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
4. **File Collection** (optional): If `CollectorShare` is specified, JSON output files are copied from each remote server's `RemoteOutputRoot` to the collector share
5. **Error Handling**: Failures on individual servers are logged but don't stop execution on other servers

### Remote Execution Output

- **On Remote Servers**: JSON and log files are written to the specified `RemoteOutputRoot` and `RemoteLogRoot` directories
- **On Collector Share**: If `CollectorShare` is specified, JSON files are copied with the same naming pattern: `{COMPUTERNAME}_{MM-dd-yyyy}.json`
- **Console Output**: Progress messages and errors are displayed in the console, with optional summary JSON output when `-EmitStdOut` is used

### Notes on Remote Execution

- The launcher script will prompt for credentials if not already running with appropriate permissions
- Remote servers must have the discovery script accessible (either locally or via a network share)
- The `-UseParallel` switch uses PowerShell 7+ `ForEach-Object -Parallel` with a throttle limit of 10 concurrent executions
- If a server is unreachable or discovery fails, execution continues with the remaining servers
- JSON files are copied using `Copy-Item -FromSession`, which requires an active PSSession

## Output Format

The script generates a JSON file named `{COMPUTERNAME}_{MM-dd-yyyy}.json` in the specified output directory.

### JSON Structure

**Important**: The JSON structure is **identical** regardless of the `SlimOutputOnly` setting. When `SlimOutputOnly` is enabled, the script uses filtered data (excluding Microsoft-built-in applications and services), but the structure remains the same. This ensures consistent ingestion into reporting engines.

```json
{
  "Metadata": {
    "Version": "1.7.0",
    "CollectedAt": "2025-01-15T10:30:00Z",
    "PlantId": "PLANT001",
    "OldDomainFqdn": "olddomain.com",
    "NewDomainFqdn": "newdomain.com"
  },
  "System": {
    "Hostname": "COMPUTER01",
    "Manufacturer": "...",
    "Model": "...",
    "OSVersion": "...",
    "IPAddress": "...",
    "MACAddress": "...",
    "LoggedInUser": "..."
  },
  "Profiles": [...],  // null when SlimOutputOnly is true
  "SharedFolders": {
    "Shares": [...],
    "Errors": [...]
  },
  "InstalledApps": [...],  // Filtered when SlimOutputOnly is true
  "Services": [...],  // Filtered when SlimOutputOnly is true
  "ScheduledTasks": [...],  // Filtered when SlimOutputOnly is true
  "LocalGroupMembers": [...],  // null when SlimOutputOnly is true
  "LocalAdministrators": [...],  // null when SlimOutputOnly is true
  "MappedDrives": [...],  // null when SlimOutputOnly is true
  "Printers": [...],  // Filtered when SlimOutputOnly is true
  "OdbcDsn": [...],  // null when SlimOutputOnly is true
  "AutoAdminLogon": {...},  // null when SlimOutputOnly is true
  "CredentialManager": [...],
  "Certificates": [...],
  "FirewallRules": [...],
  "DnsConfiguration": {...},
  "IIS": {...},
  "SqlServer": {...},
  "EventLogDomainReferences": [...],
  "ApplicationConfigFiles": {...},
  "SecurityAgents": {
    "CrowdStrike": {...},
    "Qualys": {...}
  },
  "QuestConfig": {
    "RegPath": "HKLM:\\SOFTWARE\\WOW6432NODE\\Quest\\On Demand Migration For Active Directory\\ODMAD_AD",
    "AgentKey": "...",
    "DeviceName": "...",
    "DomainName": "...",
    "TenantId": "...",
    "Hostname": "..."
  },
  "Detection": {
    "OldDomain": {
      "Services": true,
      "Tasks": false,
      ...
    },
    "Summary": {
      "HasOldDomainRefs": true,
      "Counts": {...}
    }
  }
}
```

### Slim Mode Behavior

When `SlimOutputOnly` is enabled:
- **InstalledApps**, **Services**, **ScheduledTasks**, and **Printers** contain filtered data (Microsoft-built-in items excluded)
- **Profiles**, **LocalGroupMembers**, **LocalAdministrators**, **MappedDrives**, **OdbcDsn**, and **AutoAdminLogon** are set to `null`
- All other properties remain populated
- The JSON structure is identical to full mode

## Detection Logic

The script detects old domain references in:

- **Service Accounts**: Service start names containing old domain
- **Service Paths**: Executable paths referencing old domain
- **Task Principals**: Scheduled task run-as accounts
- **Task Actions**: Executable paths in task actions
- **Drive Maps**: Mapped drive UNC paths
- **Printers**: Printer UNC paths and server names
- **ODBC**: Connection strings and server names
- **Local Groups**: Domain accounts in local groups
- **Credentials**: Windows Credential Manager entries
- **Certificates**: Certificate subjects, issuers, and SANs
- **Firewall Rules**: Domain account references in firewall rules
- **DNS**: DNS suffix search lists
- **IIS**: Application pool identities and authentication
- **SQL Server**: SQL logins and linked servers
- **Application Config Files**: Configuration files containing domain references or embedded credentials (connection strings, etc.)

## Logging

The script creates detailed logs in the specified `LogRoot` directory. Log files are named:
- `{COMPUTERNAME}_Discovery_{MM-dd-yyyy_HH-mm-ss}.log`

Logs include:
- Discovery progress
- Errors and warnings
- Validation results
- Performance metrics

## Central Share

If `CentralShare` is provided, the script will:
1. Validate the UNC path format
2. Test write access
3. Copy the JSON output to `{CentralShare}\workstations\{filename}.json`

If validation fails, the script will log a warning but continue with local output only.

## Performance Considerations

- **Profile Processing**: User profiles are processed efficiently with batched hive operations
- **Large Systems**: On systems with many profiles or services, execution may take several minutes
- **Network Shares**: Accessing network shares may add latency if shares are slow or unavailable

## Error Handling

The script includes comprehensive error handling:
- Registry access errors are caught and logged
- Network share access failures are handled gracefully
- Profile loading errors are logged but don't stop execution
- All errors are written to the log file

## Security Notes

- The script requires local administrator rights for full functionality
- Output JSON files may contain sensitive information (paths, account names)
- Ensure output directories have appropriate access controls
- Credential passwords are not extracted (they are encrypted in Windows Vault)

## Version

Current version: **1.7.0**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Copyright (c) 2025 jefftier

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

