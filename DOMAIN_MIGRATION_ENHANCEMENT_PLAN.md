# Domain Migration Discovery Script - Deep Analysis & Enhancement Plan

## Executive Summary

This document provides a comprehensive analysis of the `Get-WorkstationDiscovery.ps1` script for pre-migration discovery before an Active Directory/domain migration. It identifies current capabilities, gaps, and proposes a structured enhancement plan aligned with domain migration best practices.

---

## Part 1: Current Discovery Coverage Analysis

### ✅ What the Script Does Well

The script provides **comprehensive coverage** across 22+ discovery areas:

#### 1. **Service Account Discovery**
- ✅ Service run-as accounts (StartName) - detects `DOMAIN\User` format
- ✅ Service executable paths containing domain references
- ✅ Service state and configuration

#### 2. **Scheduled Task Discovery**
- ✅ Task principals (run-as accounts) - detects `DOMAIN\User` format
- ✅ Task action paths and arguments
- ✅ Task configuration and state

#### 3. **Application Discovery**
- ✅ Machine-level installed applications (HKLM)
- ✅ User-level installed applications (per-profile registry hives)
- ✅ AppX packages (optional)
- ✅ Application installation paths

#### 4. **Network Resource Discovery**
- ✅ Mapped network drives (per-user, from registry)
- ✅ Network printers (UNC paths, server names)
- ✅ ODBC data sources (machine and user-level)
- ✅ Shared folders with ACLs

#### 5. **Account & Group Discovery**
- ✅ Local group memberships (Administrators, Remote Desktop Users, Power Users)
- ✅ Local administrators (detailed enumeration)
- ✅ Domain account detection in groups (DOMAIN\User format)
- ✅ Built-in vs domain account differentiation

#### 6. **Credential Discovery**
- ✅ Windows Credential Manager (per-user and current user)
- ✅ Registry-based credential vault entries
- ✅ CmdKey.exe enumeration for current user
- ✅ Domain reference detection in credential targets and usernames

#### 7. **Certificate Discovery**
- ✅ Machine certificate stores (LocalMachine)
- ✅ User certificate stores (CurrentUser)
- ✅ Certificate subject, issuer, and SAN detection
- ✅ Domain reference matching across all certificate fields

#### 8. **Security & Network Configuration**
- ✅ Windows Firewall rules (domain account references)
- ✅ DNS configuration (suffix search lists, per-adapter DNS)
- ✅ Auto-admin logon registry settings

#### 9. **Web Server Discovery**
- ✅ IIS sites (bindings, application paths)
- ✅ IIS application pools (identities, names)
- ✅ Domain reference detection in IIS configuration

#### 10. **Database Server Discovery**
- ✅ SQL Server instances (detection)
- ✅ SQL Server domain logins
- ✅ SQL Server linked servers
- ✅ SQL Server configuration files

#### 11. **System Configuration**
- ✅ GPO Machine Distinguished Name (OU location)
- ✅ Event log domain references (configurable time window)
- ✅ Application configuration files (common patterns: .config, .ini, .json, .xml, etc.)
- ✅ Embedded credential detection in config files

#### 12. **Security Agent Discovery**
- ✅ CrowdStrike agent tenant information
- ✅ Qualys agent tenant information
- ✅ Quest ODMAD configuration

#### 13. **User Profile Discovery**
- ✅ User profile enumeration (with activity filtering)
- ✅ Profile SID, path, and last use time
- ✅ Profile size calculation

#### 14. **Output & Integration**
- ✅ Structured JSON output (consistent schema)
- ✅ Slim mode for filtered output (Microsoft noise reduction)
- ✅ Central share support for centralized collection
- ✅ Comprehensive logging
- ✅ Remote execution support via PowerShell Remoting

---

## Part 2: Domain Migration "Gotchas" - Gap Analysis

### 🔴 Critical Gaps Identified

#### 1. **Account Format Detection Limitations**

**Current State:**
- Detects `DOMAIN\User` format (NetBIOS\Username)
- Detects `User@domain.com` format (UPN) in some contexts
- Detects LDAP DN format (`DC=olddomain,DC=com`)

**Gaps:**
- ❌ **Bare username detection**: Does not identify bare usernames (e.g., `MyServiceAccount`) that may be domain accounts when used in certain contexts (service accounts, scheduled tasks, etc.)
- ❌ **Account format normalization**: Does not normalize and cross-reference account formats (e.g., `DOMAIN\user` vs `user@domain.com` vs bare `user`)
- ❌ **Service account resolution**: Does not resolve SIDs to account names to identify domain accounts that may appear as SIDs in some configurations

**Impact:** High - May miss domain accounts that appear in non-standard formats

---

#### 2. **Local Account Discovery & Usage Tracking**

**Current State:**
- Enumerates local group members
- Identifies domain vs local accounts in groups
- Lists local administrators

**Gaps:**
- ❌ **Local account creation tracking**: Does not identify locally created accounts (vs built-in accounts like Administrator, Guest)
- ❌ **Local account usage**: Does not track where local accounts are used (services, tasks, etc.) beyond group membership
- ❌ **Local account purpose**: Does not document why local accounts exist (e.g., "Created for service X")

**Impact:** High - Local accounts may need to be recreated or migrated; usage tracking is critical

---

#### 3. **Hard-Coded FQDN & NetBIOS References**

**Current State:**
- Detects FQDN in various contexts (certificates, DNS, config files)
- Detects NetBIOS names in account formats
- Scans application config files

**Gaps:**
- ❌ **Registry deep scan**: Does not comprehensively scan all registry hives for hard-coded FQDNs/NetBIOS names beyond known locations
- ❌ **Environment variables**: Does not check system/user environment variables for domain references
- ❌ **WMI filters**: Does not scan WMI filters (used by GPOs) for domain references
- ❌ **COM+ applications**: Does not check COM+ application identities for domain accounts
- ❌ **Windows Search index locations**: Does not check search index UNC paths
- ❌ **Backup/restore configurations**: Does not check backup software configurations for domain references

**Impact:** High - Hard-coded domain names in registry/WMI can break after migration

---

#### 4. **DFS (Distributed File System) Path Discovery**

**Current State:**
- Detects mapped drives (which may point to DFS)
- Detects UNC paths in various contexts

**Gaps:**
- ❌ **DFS namespace enumeration**: Does not specifically identify DFS namespaces and targets
- ❌ **DFS referral cache**: Does not check DFS referral cache for old domain paths
- ❌ **DFS path normalization**: Does not distinguish between DFS paths and direct UNC paths
- ❌ **DFS target server references**: Does not identify which file servers are referenced via DFS

**Impact:** High - DFS paths often contain domain references and need special handling

---

#### 5. **GPO-Driven Artifacts**

**Current State:**
- Reads GPO Machine DN (OU location)
- Detects mapped drives (but doesn't distinguish GPO-driven vs manual)

**Gaps:**
- ❌ **GPO logon scripts**: Does not identify or scan logon scripts deployed via GPO
- ❌ **GPO drive mappings**: Does not distinguish GPO-deployed drive mappings from user-created ones
- ❌ **GPO registry preferences**: Does not scan GPO registry preferences for domain references
- ❌ **GPO scheduled tasks**: Does not identify GPO-deployed scheduled tasks
- ❌ **GPO file/registry item-level targeting**: Does not check targeting filters for domain references
- ❌ **GPO WMI filters**: Does not scan WMI filter queries for domain references

**Impact:** High - GPO artifacts are re-applied after migration and may reintroduce old domain references

---

#### 6. **File Server & Print Server References**

**Current State:**
- Detects printers with server names
- Detects mapped drives (which may point to file servers)
- Detects shared folders

**Gaps:**
- ❌ **File server enumeration**: Does not comprehensively enumerate all file server references (beyond mapped drives)
- ❌ **Print server enumeration**: Does not specifically identify print servers (beyond printer objects)
- ❌ **Legacy UNC path discovery**: Does not scan for legacy UNC paths in:
  - Shortcuts (.lnk files)
  - Recent files/jump lists
  - Browser favorites/bookmarks
  - Application-specific registry keys
  - Windows Search index
- ❌ **File server FQDN vs NetBIOS**: Does not normalize file server references (may appear as FQDN or NetBIOS)

**Impact:** Medium-High - File/print server references are common and need comprehensive discovery

---

#### 7. **Application-Specific Domain References**

**Current State:**
- Scans common config file patterns (.config, .ini, .json, .xml)
- Scans common application directories

**Gaps:**
- ❌ **Application registry keys**: Does not comprehensively scan application-specific registry locations (beyond standard Uninstall keys)
- ❌ **Application data directories**: Limited depth scanning (only 2 levels) may miss nested config files
- ❌ **PowerShell profiles**: Does not scan PowerShell profile scripts for domain references
- ❌ **Batch files and scripts**: Does not scan common script locations (e.g., `C:\Scripts`, user profile scripts) for domain references
- ❌ **Application log files**: Does not scan application logs for domain references (may contain connection strings, etc.)

**Impact:** Medium - Application-specific references are often missed and cause post-migration issues

---

#### 8. **Remote Desktop & Connection Files**

**Current State:**
- No specific RDP file discovery

**Gaps:**
- ❌ **RDP connection files**: Does not scan for `.rdp` files containing domain references
- ❌ **RDP saved credentials**: Does not check RDP saved credentials in Credential Manager (may be separate from generic credentials)
- ❌ **Remote Desktop Gateway settings**: Does not check RD Gateway configurations

**Impact:** Medium - RDP files often contain hard-coded domain names

---

#### 9. **Windows Subsystem & Container Configurations**

**Current State:**
- No WSL/container discovery

**Gaps:**
- ❌ **WSL configurations**: Does not check WSL distributions for domain references in configs
- ❌ **Hyper-V configurations**: Does not check Hyper-V VM configurations, checkpoints, or virtual switch settings
- ❌ **Windows Containers/Docker**: Does not check container configurations, image registries, or Docker daemon settings
- ❌ **WSL network mounts**: Does not check WSL network drive mappings

**Impact:** Low-Medium - Growing relevance as containerization becomes more common

---

#### 10. **Certificate Binding & SSL/TLS Configuration**

**Current State:**
- Discovers certificates in stores
- Detects domain references in certificate fields

**Gaps:**
- ❌ **Certificate bindings**: Does not identify where certificates are bound (IIS bindings are covered, but not other applications)
- ❌ **Certificate store locations**: Does not enumerate all certificate store locations (only standard stores)
- ❌ **Application certificate stores**: Does not check application-specific certificate stores (e.g., Java keystores, application-specific stores)

**Impact:** Medium - Certificate bindings may reference old domain names

---

#### 11. **Shortcuts & User Interface References**

**Current State:**
- No shortcut discovery

**Gaps:**
- ❌ **Shortcut files (.lnk)**: Does not scan `.lnk` files for UNC paths or domain references
- ❌ **Recent files/jump lists**: Does not check Windows jump lists for domain references
- ❌ **Desktop/Start Menu shortcuts**: Does not scan user desktop and Start Menu for shortcuts with domain references
- ❌ **Browser favorites**: Does not check browser favorites/bookmarks for domain URLs

**Impact:** Low-Medium - User-facing references that may cause confusion

---

#### 12. **Script & Automation Discovery**

**Current State:**
- No script discovery

**Gaps:**
- ❌ **PowerShell profiles**: Does not scan PowerShell profile scripts (`$PROFILE`)
- ❌ **PowerShell scripts**: Does not scan common script directories for `.ps1` files with domain references
- ❌ **Batch files**: Does not scan for `.bat`, `.cmd` files with domain references
- ❌ **VBScript/WSH scripts**: Does not scan for `.vbs`, `.js` (WSH) files
- ❌ **Task Scheduler XML**: Does not scan Task Scheduler XML files (beyond Get-ScheduledTask enumeration)

**Impact:** Medium - Scripts often contain hard-coded domain references

---

#### 13. **Database & Application Server References**

**Current State:**
- SQL Server discovery (logins, linked servers, configs)
- ODBC DSN discovery

**Gaps:**
- ❌ **Connection string parsing**: Does not deeply parse connection strings to extract all server references (beyond basic detection)
- ❌ **Application server references**: Does not specifically identify application server references (beyond SQL)
- ❌ **Database server FQDN normalization**: Does not normalize database server names (FQDN vs NetBIOS)

**Impact:** Medium - Database connections are critical and often contain domain references

---

#### 14. **Windows Update & Maintenance Configurations**

**Current State:**
- No Windows Update discovery

**Gaps:**
- ❌ **WSUS server settings**: Does not check Windows Update Server (WSUS) configurations for domain references
- ❌ **Windows Update group policy**: Does not check GPO-driven Windows Update settings

**Impact:** Low - May affect update delivery post-migration

---

## Part 3: Structured Enhancement Plan

### Enhancement Plan Overview

This plan proposes **25 concrete enhancements** organized into **5 priority tiers**. Each enhancement includes:
- **Feature number and name**
- **Short description**
- **JSON schema additions** (to maintain consistency for Power BI/web app consumption)
- **Priority rationale**

---

### Priority Tier 1: Critical Domain Migration Blockers

#### Enhancement 1: Enhanced Account Format Detection & Normalization
**Description:** Expand account detection to handle all formats (`DOMAIN\User`, `User@domain.com`, bare `User`, SID resolution) and normalize accounts across all discovery areas to identify the same account in different formats.

**JSON Schema Addition:**
```json
{
  "AccountReferences": {
    "NormalizedAccounts": [
      {
        "AccountName": "MyServiceAccount",
        "Formats": ["OLDDOMAIN\\MyServiceAccount", "MyServiceAccount@olddomain.com", "MyServiceAccount"],
        "Locations": ["Services", "ScheduledTasks", "LocalGroups"],
        "IsDomainAccount": true,
        "SID": "S-1-5-21-..."
      }
    ],
    "UnresolvedSIDs": [
      {
        "SID": "S-1-5-21-...",
        "Locations": ["Services", "Registry"]
      }
    ]
  }
}
```

**Rationale:** Critical for identifying all domain account references regardless of format.

---

#### Enhancement 2: Local Account Discovery & Usage Tracking
**Description:** Identify locally created accounts (excluding built-ins), track where they are used (services, tasks, groups), and document their purpose/creation context.

**JSON Schema Addition:**
```json
{
  "LocalAccounts": [
    {
      "Name": "LocalServiceAccount",
      "SID": "S-1-5-21-...",
      "IsBuiltIn": false,
      "CreatedDate": "2020-01-15T10:30:00Z",
      "LastLogon": "2024-01-10T08:00:00Z",
      "Usage": {
        "Services": ["ServiceName1", "ServiceName2"],
        "ScheduledTasks": ["TaskPath1"],
        "LocalGroups": ["Administrators"],
        "CredentialManager": ["Target1"]
      },
      "Purpose": "Used by ServiceName1"
    }
  ]
}
```

**Rationale:** Local accounts may need recreation or migration; usage tracking is essential for migration planning.

---

#### Enhancement 3: Comprehensive Registry Deep Scan for Domain References
**Description:** Perform deep registry scan across all hives (HKLM, HKCU, HKU) for hard-coded FQDNs, NetBIOS names, and domain references beyond known locations. Include environment variables and WMI filter queries.

**JSON Schema Addition:**
```json
{
  "RegistryDomainReferences": [
    {
      "Hive": "HKLM",
      "Path": "SOFTWARE\\MyApp\\Config",
      "ValueName": "ServerName",
      "Value": "server.olddomain.com",
      "ValueType": "String",
      "MatchedPattern": "FQDN",
      "Context": "Application configuration"
    }
  ],
  "EnvironmentVariables": [
    {
      "Scope": "Machine",
      "Name": "APPSERVER",
      "Value": "app.olddomain.com",
      "MatchedPattern": "FQDN"
    }
  ],
  "WMIFilters": [
    {
      "Name": "Domain Computers Filter",
      "Query": "SELECT * FROM Win32_ComputerSystem WHERE Domain = 'OLDDOMAIN'",
      "HasDomainReference": true
    }
  ]
}
```

**Rationale:** Registry and WMI often contain hard-coded domain references that break after migration.

---

#### Enhancement 4: DFS Namespace & Path Discovery
**Description:** Enumerate DFS namespaces, identify DFS paths vs direct UNC paths, check DFS referral cache, and identify target file servers.

**JSON Schema Addition:**
```json
{
  "DFSNamespaces": [
    {
      "NamespacePath": "\\\\olddomain.com\\DFSShare",
      "TargetServers": ["server1.olddomain.com", "server2.olddomain.com"],
      "ReferralCache": true,
      "IsDomainBased": true,
      "Locations": ["MappedDrives", "Shortcuts", "Registry"]
    }
  ],
  "DFSPathReferences": [
    {
      "Path": "\\\\olddomain.com\\DFSShare\\Folder",
      "Location": "MappedDrive",
      "Drive": "Z:",
      "UserSID": "S-1-5-21-..."
    }
  ]
}
```

**Rationale:** DFS paths are common and require special handling during domain migration.

---

#### Enhancement 5: GPO Artifact Discovery
**Description:** Identify GPO-deployed logon scripts, drive mappings, scheduled tasks, registry preferences, and WMI filters. Distinguish GPO-deployed items from manually created ones.

**JSON Schema Addition:**
```json
{
  "GPOArtifacts": {
    "LogonScripts": [
      {
        "ScriptPath": "\\\\olddomain.com\\SYSVOL\\...\\logon.vbs",
        "GPO": "Default Domain Policy",
        "HasDomainReference": true,
        "ScriptContent": "// First 500 chars for reference"
      }
    ],
    "DriveMappings": [
      {
        "Drive": "H:",
        "UNC": "\\\\olddomain.com\\share",
        "GPO": "File Server Mapping Policy",
        "IsGPODeployed": true
      }
    ],
    "ScheduledTasks": [
      {
        "TaskPath": "\\GPO Tasks\\MyTask",
        "GPO": "Application Deployment Policy",
        "HasDomainReference": true
      }
    ],
    "RegistryPreferences": [
      {
        "Path": "HKLM\\SOFTWARE\\MyApp",
        "GPO": "Application Settings Policy",
        "HasDomainReference": true
      }
    ]
  }
}
```

**Rationale:** GPO artifacts are reapplied after migration and may reintroduce old domain references.

---

### Priority Tier 2: High-Impact Domain References

#### Enhancement 6: File Server & Print Server Comprehensive Enumeration
**Description:** Enumerate all file server and print server references beyond mapped drives and printers. Include server FQDN normalization and legacy UNC path discovery.

**JSON Schema Addition:**
```json
{
  "FileServers": [
    {
      "ServerName": "fileserver",
      "FQDN": "fileserver.olddomain.com",
      "NetBIOS": "OLDDOMAIN\\fileserver",
      "References": [
        {
          "Type": "MappedDrive",
          "Path": "Z:",
          "UNC": "\\\\fileserver.olddomain.com\\share"
        },
        {
          "Type": "Shortcut",
          "Path": "C:\\Users\\User\\Desktop\\link.lnk",
          "Target": "\\\\fileserver.olddomain.com\\share\\file.txt"
        }
      ]
    }
  ],
  "PrintServers": [
    {
      "ServerName": "printserver",
      "FQDN": "printserver.olddomain.com",
      "Printers": ["Printer1", "Printer2"],
      "References": ["Printers", "Registry"]
    }
  ]
}
```

**Rationale:** File and print servers are frequently referenced and need comprehensive discovery.

---

#### Enhancement 7: Shortcut & User Interface Reference Discovery
**Description:** Scan `.lnk` files, jump lists, desktop/Start Menu shortcuts, and browser favorites for domain references and UNC paths.

**JSON Schema Addition:**
```json
{
  "Shortcuts": [
    {
      "Path": "C:\\Users\\User\\Desktop\\ServerLink.lnk",
      "Target": "\\\\server.olddomain.com\\share",
      "WorkingDirectory": "\\\\server.olddomain.com\\share\\folder",
      "HasDomainReference": true,
      "Location": "Desktop"
    }
  ],
  "JumpLists": [
    {
      "UserSID": "S-1-5-21-...",
        "Items": [
          {
            "Path": "\\\\server.olddomain.com\\share\\file.txt",
            "HasDomainReference": true
          }
        ]
    }
  ],
  "BrowserFavorites": [
    {
      "Browser": "Chrome",
      "URL": "https://app.olddomain.com",
      "Title": "Internal App",
      "HasDomainReference": true
    }
  ]
}
```

**Rationale:** User-facing references cause confusion and need updating.

---

#### Enhancement 8: Script & Automation Discovery
**Description:** Scan PowerShell profiles, common script directories, batch files, VBScript files, and Task Scheduler XML files for domain references.

**JSON Schema Addition:**
```json
{
  "Scripts": [
    {
      "Path": "C:\\Scripts\\deploy.ps1",
      "Type": "PowerShell",
      "HasDomainReference": true,
      "MatchedLines": [
        {
          "LineNumber": 15,
          "Content": "$server = 'server.olddomain.com'"
        }
      ],
      "First500Chars": "// Script content preview"
    }
  ],
  "PowerShellProfiles": [
    {
      "ProfilePath": "$PROFILE",
      "ResolvedPath": "C:\\Users\\User\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
      "HasDomainReference": true
    }
  ],
  "TaskSchedulerXML": [
    {
      "TaskPath": "\\MyTasks\\Task1",
      "XMLPath": "C:\\Windows\\System32\\Tasks\\MyTasks\\Task1",
      "HasDomainReference": true
    }
  ]
}
```

**Rationale:** Scripts often contain hard-coded domain references that break automation.

---

#### Enhancement 9: Application-Specific Registry & Config Deep Scan
**Description:** Expand application config file scanning depth, scan application-specific registry keys beyond Uninstall keys, and check application log files.

**JSON Schema Addition:**
```json
{
  "ApplicationRegistryKeys": [
    {
      "Application": "MyApp",
      "RegistryPath": "HKLM\\SOFTWARE\\MyApp\\Settings",
      "Values": [
        {
          "Name": "ServerURL",
          "Value": "https://app.olddomain.com",
          "HasDomainReference": true
        }
      ]
    }
  ],
  "ApplicationLogFiles": [
    {
      "Path": "C:\\ProgramData\\MyApp\\logs\\app.log",
      "HasDomainReference": true,
      "MatchedLines": 5,
      "SampleLines": ["Connection to server.olddomain.com failed"]
    }
  ]
}
```

**Rationale:** Application-specific configurations are often missed and cause post-migration issues.

---

#### Enhancement 10: Remote Desktop Connection File Discovery
**Description:** Scan for `.rdp` files, check RDP saved credentials, and examine Remote Desktop Gateway settings.

**JSON Schema Addition:**
```json
{
  "RDPConnections": [
    {
      "FilePath": "C:\\Users\\User\\Documents\\Server.rdp",
      "Server": "server.olddomain.com",
      "Domain": "OLDDOMAIN",
      "Username": "user@olddomain.com",
      "HasDomainReference": true,
      "GatewaySettings": {
        "GatewayHostname": "rdgateway.olddomain.com",
        "HasDomainReference": true
      }
    }
  ]
}
```

**Rationale:** RDP files often contain hard-coded domain names and credentials.

---

### Priority Tier 3: Medium-Impact Enhancements

#### Enhancement 11: COM+ Application Identity Discovery
**Description:** Enumerate COM+ applications and check their configured identities for domain account references.

**JSON Schema Addition:**
```json
{
  "COMPlusApplications": [
    {
      "Name": "MyCOMApp",
      "Identity": "OLDDOMAIN\\ServiceAccount",
      "HasDomainReference": true,
      "IsActivated": true
    }
  ]
}
```

**Rationale:** COM+ applications may use domain accounts that need updating.

---

#### Enhancement 12: Certificate Binding & Store Discovery
**Description:** Identify certificate bindings beyond IIS, enumerate all certificate store locations, and check application-specific certificate stores.

**JSON Schema Addition:**
```json
{
  "CertificateBindings": [
    {
      "CertificateThumbprint": "ABC123...",
      "Application": "MyApp",
      "BindingType": "HTTPS",
      "Port": 443,
      "Hostname": "app.olddomain.com",
      "HasDomainReference": true
    }
  ],
  "ApplicationCertificateStores": [
    {
      "Application": "Java",
      "StorePath": "C:\\Program Files\\Java\\keystore.jks",
      "HasDomainReference": true
    }
  ]
}
```

**Rationale:** Certificate bindings may reference old domain names.

---

#### Enhancement 13: Database Connection String Deep Parsing
**Description:** Deeply parse connection strings to extract all server references, normalize database server names, and identify application server references beyond SQL.

**JSON Schema Addition:**
```json
{
  "DatabaseConnections": [
    {
      "Type": "SQL Server",
      "ConnectionString": "Server=db.olddomain.com;Database=MyDB;...",
      "ParsedComponents": {
        "Server": "db.olddomain.com",
        "Database": "MyDB",
        "IntegratedSecurity": true,
        "Domain": "OLDDOMAIN"
      },
      "HasDomainReference": true,
      "Location": "ODBC DSN: MyDSN"
    }
  ],
  "ApplicationServers": [
    {
      "Type": "Web Service",
      "Endpoint": "https://api.olddomain.com",
      "HasDomainReference": true,
      "Location": "Config File: app.config"
    }
  ]
}
```

**Rationale:** Database and application server connections are critical and often contain domain references.

---

#### Enhancement 14: Windows Search Index Location Discovery
**Description:** Check Windows Search index locations for UNC paths and domain references.

**JSON Schema Addition:**
```json
{
  "WindowsSearch": {
    "IndexLocations": [
      {
        "Path": "\\\\server.olddomain.com\\share",
        "HasDomainReference": true,
        "IsIndexed": true
      }
    ]
  }
}
```

**Rationale:** Search index may contain references to old domain resources.

---

#### Enhancement 15: Backup & Restore Configuration Discovery
**Description:** Check backup software configurations, restore points, and backup target locations for domain references.

**JSON Schema Addition:**
```json
{
  "BackupConfigurations": [
    {
      "Software": "Windows Backup",
      "BackupTarget": "\\\\backup.olddomain.com\\backups",
      "HasDomainReference": true,
      "IsConfigured": true
    }
  ]
}
```

**Rationale:** Backup configurations may reference old domain resources.

---

### Priority Tier 4: Lower-Priority but Valuable

#### Enhancement 16: Windows Update Server (WSUS) Configuration
**Description:** Check WSUS server settings and GPO-driven Windows Update configurations for domain references.

**JSON Schema Addition:**
```json
{
  "WindowsUpdate": {
    "WUServer": "wsus.olddomain.com",
    "WUStatusServer": "wsus.olddomain.com",
    "HasDomainReference": true,
    "IsGPOConfigured": true
    }
}
```

**Rationale:** May affect update delivery post-migration.

---

#### Enhancement 17: Hyper-V & Virtualization Configuration
**Description:** Check Hyper-V VM configurations, checkpoints, virtual switch settings, and VM file locations for domain references.

**JSON Schema Addition:**
```json
{
  "HyperV": {
    "VMs": [
      {
        "Name": "MyVM",
        "ConfigPath": "C:\\VMs\\MyVM",
        "HasDomainReference": false
      }
    ],
    "VirtualSwitches": [
      {
        "Name": "External Switch",
        "HasDomainReference": false
      }
    ]
  }
}
```

**Rationale:** Virtualization configurations may contain domain references.

---

#### Enhancement 18: WSL Configuration Discovery
**Description:** Check WSL distributions, network mounts, and configuration files for domain references.

**JSON Schema Addition:**
```json
{
  "WSL": {
    "Distributions": [
      {
        "Name": "Ubuntu",
        "ConfigPath": "C:\\Users\\User\\AppData\\Local\\Packages\\...",
        "HasDomainReference": false,
        "NetworkMounts": [
          {
            "Path": "\\\\server.olddomain.com\\share",
            "HasDomainReference": true
          }
        ]
      }
    ]
  }
}
```

**Rationale:** WSL configurations may contain domain references.

---

#### Enhancement 19: Windows Container & Docker Configuration
**Description:** Check container configurations, image registries, and Docker daemon settings for domain references.

**JSON Schema Addition:**
```json
{
  "Containers": {
    "Docker": {
      "Registry": "registry.olddomain.com",
      "HasDomainReference": true,
      "ConfigPath": "C:\\ProgramData\\Docker\\config.json"
    },
    "WindowsContainers": [
      {
        "Name": "MyContainer",
        "HasDomainReference": false
      }
    ]
  }
}
```

**Rationale:** Container configurations may reference domain resources.

---

#### Enhancement 20: Event Log Pattern Analysis
**Description:** Enhance event log scanning to identify patterns (e.g., repeated authentication failures to old domain, service start failures) that indicate domain dependencies.

**JSON Schema Addition:**
```json
{
  "EventLogPatterns": [
    {
      "Pattern": "AuthenticationFailure",
      "Domain": "OLDDOMAIN",
      "Count": 150,
      "TimeRange": "2024-01-01 to 2024-01-31",
      "IndicatesDependency": true
    }
  ]
}
```

**Rationale:** Event log patterns can reveal hidden domain dependencies.

---

### Priority Tier 5: Reporting & Analysis Enhancements

#### Enhancement 21: Domain Reference Cross-Reference Matrix
**Description:** Create a cross-reference matrix showing which accounts, servers, and paths are referenced across multiple discovery areas (e.g., same account used in services, tasks, and groups).

**JSON Schema Addition:**
```json
{
  "CrossReferences": {
    "Accounts": [
      {
        "Account": "OLDDOMAIN\\ServiceAccount",
        "References": {
          "Services": ["Service1", "Service2"],
          "ScheduledTasks": ["Task1"],
          "LocalGroups": ["Administrators"],
          "TotalReferences": 4
        }
      }
    ],
    "Servers": [
      {
        "Server": "server.olddomain.com",
        "References": {
          "MappedDrives": 2,
          "Shortcuts": 5,
          "Registry": 1,
          "TotalReferences": 8
        }
      }
    ]
  }
}
```

**Rationale:** Helps prioritize migration efforts by identifying high-impact references.

---

#### Enhancement 22: Risk Assessment & Migration Priority Scoring
**Description:** Assign risk scores and migration priority to each discovered domain reference based on impact (critical service, user-facing, etc.) and complexity.

**JSON Schema Addition:**
```json
{
  "RiskAssessment": [
    {
      "Reference": "Service: CriticalService",
      "Type": "ServiceAccount",
      "RiskScore": 9,
      "MigrationPriority": "Critical",
      "Impact": "Service will fail to start",
      "Complexity": "Medium",
      "EstimatedEffort": "2 hours"
    }
  ]
}
```

**Rationale:** Helps migration teams prioritize work and allocate resources.

---

#### Enhancement 23: Historical Change Detection
**Description:** Compare current discovery results with previous runs to identify new domain references (indicating drift or incomplete previous migration).

**JSON Schema Addition:**
```json
{
  "ChangeDetection": {
    "NewReferences": [
      {
        "Reference": "Service: NewService",
        "Type": "ServiceAccount",
        "FirstSeen": "2024-01-15T10:00:00Z"
      }
    ],
    "RemovedReferences": [
      {
        "Reference": "Service: OldService",
        "Type": "ServiceAccount",
        "LastSeen": "2023-12-01T08:00:00Z"
      }
    ]
  }
}
```

**Rationale:** Helps track migration progress and identify regressions.

---

#### Enhancement 24: Migration Readiness Report Generation
**Description:** Generate human-readable migration readiness reports with summaries, recommendations, and action items.

**JSON Schema Addition:**
```json
{
  "MigrationReadiness": {
    "OverallScore": 75,
    "CriticalIssues": 3,
    "HighPriorityIssues": 12,
    "MediumPriorityIssues": 45,
    "Recommendations": [
      "Update 3 service accounts before migration",
      "Migrate 5 local accounts to domain accounts",
      "Update 12 GPO logon scripts"
    ],
    "EstimatedMigrationTime": "8 hours"
  }
}
```

**Rationale:** Provides actionable insights for migration planning.

---

#### Enhancement 25: Enhanced JSON Schema Versioning & Metadata
**Description:** Add schema versioning, collection metadata, and data quality indicators to JSON output for better integration with Power BI and web apps.

**JSON Schema Addition:**
```json
{
  "SchemaVersion": "2.0",
  "CollectionMetadata": {
    "CollectionId": "uuid-here",
    "PreviousCollectionId": "uuid-previous",
    "CollectionDuration": "00:15:30",
    "DataQuality": {
      "CompletenessScore": 95,
      "ErrorsEncountered": 2,
      "Warnings": 5
    }
  },
  "EnhancementsEnabled": [
    "AccountNormalization",
    "DFSDiscovery",
    "GPOArtifacts"
  ]
}
```

**Rationale:** Ensures consistent data consumption and enables schema evolution.

---

## Part 4: Implementation Recommendations

### Phase 1: Critical Enhancements (Priority Tier 1)
**Timeline:** 4-6 weeks
**Enhancements:** 1-5
**Impact:** Addresses critical domain migration blockers

### Phase 2: High-Impact Enhancements (Priority Tier 2)
**Timeline:** 3-4 weeks
**Enhancements:** 6-10
**Impact:** Covers most common domain reference scenarios

### Phase 3: Medium-Impact Enhancements (Priority Tier 3)
**Timeline:** 2-3 weeks
**Enhancements:** 11-15
**Impact:** Addresses edge cases and specialized scenarios

### Phase 4: Lower-Priority Enhancements (Priority Tier 4)
**Timeline:** 2-3 weeks
**Enhancements:** 16-20
**Impact:** Completes comprehensive coverage

### Phase 5: Reporting & Analysis (Priority Tier 5)
**Timeline:** 2-3 weeks
**Enhancements:** 21-25
**Impact:** Enhances usability and migration planning

---

## Part 5: JSON Schema Consistency Guidelines

### Core Principles
1. **Consistent Structure**: All enhancements maintain the existing JSON structure pattern
2. **Null Handling**: Use `null` for empty collections (not empty arrays) when appropriate
3. **ISO 8601 Dates**: All timestamps use ISO 8601 format
4. **SID Format**: Security Identifiers use standard SID string format
5. **Enumeration Values**: Use consistent enumeration values (e.g., "Critical", "High", "Medium", "Low" for priorities)

### Schema Evolution
- **Versioning**: Include `SchemaVersion` field to track schema changes
- **Backward Compatibility**: Maintain backward compatibility where possible
- **Deprecation**: Mark deprecated fields but don't remove them immediately

---

## Conclusion

This enhancement plan addresses **25 concrete gaps** identified in the current domain migration discovery script. The phased approach allows for incremental implementation while maintaining the script's existing strengths. All enhancements are designed to maintain JSON schema consistency for easy consumption in Power BI or custom web applications.

**Total Estimated Implementation Time:** 13-19 weeks (with appropriate testing and validation)

**Expected Impact:** Significantly improved domain migration readiness discovery, reducing post-migration issues and downtime.

