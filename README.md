# Domain Migration Discovery Script

A comprehensive PowerShell script for discovering domain migration readiness by scanning workstations for references to old domain configurations, credentials, certificates, and dependencies.

## Overview

This script performs a deep discovery of Windows workstations to identify all references to an old domain that may need to be updated during a domain migration. It collects data about services, scheduled tasks, applications, printers, ODBC connections, local group memberships, credentials, certificates, firewall rules, DNS configuration, and more.

## Features

### Core Capabilities

- **Comprehensive Discovery**: Scans 20+ areas of Windows configuration for domain references
- **Slim Output Mode**: Filter out Microsoft-built-in applications and services for cleaner output
- **JSON Output**: Structured JSON output for easy parsing and integration
- **Central Share Support**: Optionally copy results to a central network share
- **Remote Execution**: Launcher script for executing discovery on multiple servers via PowerShell Remoting
- **Parallel Processing**: Support for parallel execution across multiple servers (PowerShell 7+)
- **Headless Operation**: Designed for automated execution without user interaction
- **Multi-Profile Support**: Scans all user profiles on the system
- **Error Handling**: Robust error handling with detailed logging
- **Error Logging**: Automatic error logging to `results\error.log` for remote execution
- **Automatic File Collection**: Automatically collects JSON files from remote servers when `CollectorShare` is not specified

### Discovery Areas

The script scans the following areas for old domain references:

1. **Windows Services** - Service accounts and executable paths
2. **Scheduled Tasks** - Task principals and action paths
3. **Installed Applications** - Machine and user-level applications
4. **Mapped Network Drives** - Per-user drive mappings
5. **Printers** - Local and network printers
6. **ODBC Data Sources** - Machine and user-level ODBC connections
7. **Local Group Memberships** - Domain accounts in local groups
8. **Local Administrators** - Domain accounts with admin rights
9. **Shared Folders** - File shares with ACLs
10. **Windows Credential Manager** - Stored credentials (per-user and current user)
11. **Certificate Stores** - Machine and user certificate stores
12. **Firewall Rules** - Windows Firewall rules with domain references
13. **DNS Configuration** - DNS suffix search lists and per-adapter DNS
14. **IIS Configuration** - Websites, application pools, and bindings (if IIS is installed)
15. **SQL Server** - SQL logins, linked servers, and config files (if SQL Server is installed)
16. **Event Logs** - Domain references in Windows event logs
17. **Application Configuration Files** - Config files with domain references and embedded credentials
18. **Security Agents** - CrowdStrike and Qualys agent tenant information
19. **Quest ODMAD** - Quest On Demand Migration for Active Directory configuration
20. **Auto Admin Logon** - Registry-based auto-logon configuration
21. **User Profiles** - Profile information and activity (full mode only)
22. **GPO Machine DN** - Group Policy Object machine distinguished name

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

### Example: Full Discovery with Central Share

```powershell
.\Get-WorkstationDiscovery.ps1 `
    -OldDomainFqdn "olddomain.com" `
    -NewDomainFqdn "newdomain.com" `
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
| `NewDomainNetBIOS` | String | No | - | NetBIOS name of the new domain (not used by discovery script) |
| `PlantId` | String | No | - | Optional plant/facility identifier |
| `EmitStdOut` | Switch | No | `$false` | Emit summary JSON to stdout for each server |
| `UseParallel` | Switch | No | `$false` | Execute discovery in parallel (requires PowerShell 7+) |
| `Credential` | PSCredential | No | - | Credentials for remote access (prompts if not provided) |

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

## Complete Data Elements Collected

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

### User Profiles (null in SlimOutputOnly mode)
Each profile object contains:
- `SID` - Security Identifier
- `LocalPath` - Profile directory path
- `LastUseTime` - Last profile access timestamp
- `ProfileSize` - Profile directory size in bytes
- `Status` - Profile status (Loaded/Unloaded)

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
- `InstallDate` - Installation date
- `InstallLocation` - Installation directory
- `UninstallString` - Uninstall command
- `KeyPath` - Registry key path
- `Scope` - Installation scope (Machine, User:SID, AppxAllUsers)

### Services (filtered in SlimOutputOnly mode)
Each service object contains:
- `Name` - Service name
- `DisplayName` - Service display name
- `State` - Service state (Running, Stopped, etc.)
- `StartMode` - Service start mode (Automatic, Manual, Disabled)
- `StartName` - Service account (run-as account)
- `PathName` - Service executable path with arguments

### Scheduled Tasks (filtered in SlimOutputOnly mode)
Each task object contains:
- `Path` - Task path and name
- `UserId` - Task principal (run-as account)
- `LogonType` - Logon type (Interactive, Password, S4U, etc.)
- `RunLevel` - Run level (Limited, Highest)
- `Enabled` - Whether task is enabled
- `Actions` - Array of action objects:
  - `ActionType` - Action type (Exec, ComHandler, etc.)
  - `Execute` - Executable path
  - `Arguments` - Command-line arguments
  - `WorkingDir` - Working directory
  - `ClassId` - COM class ID (for ComHandler actions)
  - `Data` - Action data
  - `Summary` - Action summary string

### Local Group Members (null in SlimOutputOnly mode)
Each member object contains:
- `Group` - Group name
- `Name` - Member name (account name)
- `ObjectClass` - Object class (User, Group, etc.)
- `PrincipalSource` - Principal source (ActiveDirectory, Local, etc.)
- `SID` - Security Identifier
- `IsGroup` - Whether member is a group
- `IsDomain` - Whether member is a domain account
- `IsBuiltIn` - Whether member is a built-in account
- `Domain` - Domain name (if domain account)
- `Account` - Account name without domain
- `IsDomainGroupLikely` - Whether likely a domain group
- `Source` - Source of member information

### Local Administrators (null in SlimOutputOnly mode)
Each administrator object contains:
- `Group` - Group name (typically "Administrators")
- `Name` - Administrator account name
- `ObjectClass` - Object class
- `PrincipalSource` - Principal source
- `SID` - Security Identifier
- `IsGroup` - Whether member is a group
- `IsDomain` - Whether member is a domain account
- `IsBuiltIn` - Whether member is a built-in account
- `Domain` - Domain name (if domain account)
- `Account` - Account name without domain
- `IsDomainGroupLikely` - Whether likely a domain group
- `Source` - Source of member information

### Mapped Drives (null in SlimOutputOnly mode)
Each drive mapping object contains:
- `SID` - User SID who owns the mapping
- `Drive` - Drive letter
- `Remote` - Remote UNC path
- `Provider` - Network provider name
- `Persistent` - Whether mapping is persistent

### Printers (filtered in SlimOutputOnly mode)
Each printer object contains:
- `Name` - Printer name
- `DriverName` - Printer driver name
- `PortName` - Printer port name
- `ShareName` - Printer share name (if shared)
- `ComputerName` - Computer name (for network printers)
- `SystemName` - System name (alternative field)
- `ServerName` - Server name (for network printers)
- `Type` - Printer type
- `Location` - Printer location
- `Comment` - Printer comment
- `Network` - Whether printer is network printer

### ODBC Data Sources (null in SlimOutputOnly mode)
Each ODBC DSN object contains:
- `Name` - DSN name
- `Driver` - ODBC driver name
- `Server` - Database server name
- `Database` - Database name
- `Trusted` - Whether using trusted connection
- `Scope` - DSN scope (Machine64, Machine32, User:SID)

### Auto Admin Logon (null in SlimOutputOnly mode)
Object contains:
- `Enabled` - Whether auto-logon is enabled
- `DefaultUserName` - Default username
- `DefaultDomainName` - Default domain name
- `DefaultPassword` - Whether password is set (not the actual password)
- `AutoAdminLogon` - Auto-logon flag value

### Credential Manager
Each credential object contains:
- `Profile` - Profile identifier (SID or "CurrentUser")
- `Target` - Credential target name
- `UserName` - Stored username
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
- `HasDomainReference` - Whether certificate contains old domain reference
- `MatchedField` - Which field matched (Subject, Issuer, SANs)

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
  - `IdentityType` - Identity type (ApplicationPoolIdentity, NetworkService, Custom)
  - `IdentityUser` - Identity user (if custom identity)
  - `HasDomainReference` - Whether app pool contains old domain reference
  - `MatchedFields` - Array of fields that matched (Name, IdentityUser)

### SQL Server Configuration (null if SQL Server not installed)
Array of SQL instance objects, each containing:
- `InstanceName` - SQL Server instance name
- `InstancePath` - SQL Server installation path
- `DomainLogins` - Array of domain login objects:
  - `LoginName` - SQL login name
  - `LoginType` - Login type (WindowsUser, WindowsGroup, etc.)
- `LinkedServersWithDomainReferences` - Array of linked server objects:
  - `LinkedServerName` - Linked server name
  - `Provider` - Linked server provider
  - `DataSource` - Data source
  - `Catalog` - Catalog/database
  - `HasDomainReference` - Whether linked server contains old domain reference
  - `MatchedFields` - Array of fields that matched
- `ConfigFilesWithDomainReferences` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `HasDomainReference` - Whether file contains old domain reference

### Event Log Domain References
Array of event log entry objects, each containing:
- `LogName` - Event log name (Application, System, Security, etc.)
- `Id` - Event ID
- `TimeCreated` - Event timestamp
- `Level` - Event level (Information, Warning, Error, etc.)
- `Message` - Event message (truncated if very long)
- `HasDomainReference` - Whether event contains old domain reference

### Application Configuration Files
Object contains:
- `FilesWithDomainReferences` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `HasDomainReference` - Whether file contains old domain reference
- `FilesWithCredentials` - Array of config file objects:
  - `FilePath` - Configuration file path
  - `HasCredentials` - Whether file contains embedded credentials (connection strings, etc.)

### Security Agents
Object contains:
- `CrowdStrike` - CrowdStrike agent information:
  - `RegPath` - Registry path
  - `ValueName` - Registry value name
  - `Kind` - Registry value kind (Binary, String, etc.)
  - `Raw` - Raw registry value (hex string for binary)
  - `String` - String representation of value
  - `Tenant` - Mapped tenant name
- `Qualys` - Qualys agent information:
  - `RegPath` - Registry path
  - `ValueName` - Registry value name
  - `Kind` - Registry value kind
  - `Raw` - Raw registry value
  - `String` - String representation of value
  - `Tenant` - Mapped tenant name

### Quest ODMAD Configuration
Object contains:
- `RegPath` - Registry path
- `AgentKey` - Agent key value
- `DeviceName` - Device name
- `DomainName` - Domain name
- `TenantId` - Tenant ID
- `Hostname` - Hostname

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

### Slim Mode Behavior

When `SlimOutputOnly` is enabled:
- **InstalledApps**, **Services**, **ScheduledTasks**, and **Printers** contain filtered data (Microsoft-built-in items excluded)
- **Profiles**, **LocalGroupMembers**, **LocalAdministrators**, **MappedDrives**, **OdbcDsn**, and **AutoAdminLogon** are set to `null`
- All other properties remain populated
- The JSON structure is identical to full mode

## Detection Logic

The script detects old domain references using regex pattern matching in the following formats:
- **NetBIOS Name**: Word boundaries around NetBIOS name (e.g., `\bOLDDOMAIN\b`)
- **FQDN**: Direct FQDN match (e.g., `olddomain.com`)
- **UPN Format**: Email-style format (e.g., `@olddomain.com$`)
- **LDAP DN Format**: Distinguished name format (e.g., `DC=olddomain,DC=com`)

The script scans for old domain references in:

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
- **DNS**: DNS suffix search lists and per-adapter DNS suffixes
- **IIS**: Application pool identities, site bindings, and application paths
- **SQL Server**: SQL logins, linked servers, and configuration files
- **Application Config Files**: Configuration files containing domain references or embedded credentials (connection strings, etc.)
- **Event Logs**: Event log messages containing domain references

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

## Central Share

If `CentralShare` is provided, the script will:
1. Validate the UNC path format
2. Test write access by creating and deleting a test file
3. Copy the JSON output to `{CentralShare}\workstations\{filename}.json`

If validation fails, the script will log a warning but continue with local output only.

## Performance Considerations

- **Profile Processing**: User profiles are processed efficiently with batched hive operations
- **Large Systems**: On systems with many profiles or services, execution may take several minutes
- **Network Shares**: Accessing network shares may add latency if shares are slow or unavailable
- **Parallel Execution**: Remote execution supports parallel processing (PowerShell 7+) with throttle limit of 10 concurrent executions

## Error Handling

The script includes comprehensive error handling:
- Registry access errors are caught and logged
- Network share access failures are handled gracefully
- Profile loading errors are logged but don't stop execution
- All errors are written to the log file
- Remote execution errors are logged to `results\error.log` with timestamps and server names
- Execution continues even if individual servers fail

## Security Notes

- The script requires local administrator rights for full functionality
- Output JSON files may contain sensitive information (paths, account names)
- Ensure output directories have appropriate access controls
- Credential passwords are not extracted (they are encrypted in Windows Vault)
- The script does not modify any system configuration, only reads and reports

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
