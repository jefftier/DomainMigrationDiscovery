#Requires -Version 5.1
<#
.SYNOPSIS
    Discovers domain migration readiness by scanning workstations for old domain references.

.DESCRIPTION
    This script performs comprehensive discovery of Windows workstations to identify all references 
    to an old domain that may need to be updated during a domain migration. It collects data about 
    services, scheduled tasks, applications, printers, ODBC connections, local group memberships, 
    credentials, certificates, firewall rules, DNS configuration, IIS, SQL Server, and more.
    
    The script outputs structured JSON data that can be easily ingested into reporting engines or 
    migration planning tools. It supports both full discovery mode and slim mode (filtered output 
    excluding Microsoft-built-in applications and services).
    
    Designed for headless, automated execution with comprehensive error handling and logging.

.PARAMETER OldDomainFqdn
    Fully Qualified Domain Name (FQDN) of the old domain to detect references for.
    Must be a valid FQDN format (e.g., 'example.com' or 'subdomain.example.com').
    Default: 'oldco.com'

.PARAMETER NewDomainFqdn
    Fully Qualified Domain Name (FQDN) of the new domain.
    Must be a valid FQDN format (e.g., 'example.com' or 'subdomain.example.com').

.PARAMETER OldDomainNetBIOS
    NetBIOS name of the old domain (optional, but recommended for better detection).
    Must be 15 characters or less, alphanumeric with hyphens allowed.
    Example: 'OldCo'

.PARAMETER OutputRoot
    Local or UNC path where JSON output files will be written.
    Default: 'C:\temp\MigrationDiscovery\out'

.PARAMETER LogRoot
    Local or UNC path where log files will be written.
    Default: 'C:\temp\MigrationDiscovery\logs'

.PARAMETER CentralShare
    Optional UNC path to a central network share for copying output files.
    Format: '\\server\share'
    If provided, output will be copied to '{CentralShare}\workstations\{filename}.json'

.PARAMETER ProfileDays
    Number of days to look back for user profile activity when determining which profiles to scan.
    Default: 30

.PARAMETER EventLogDays
    Number of days to look back in event logs for domain references.
    Default: 7

.PARAMETER PlantId
    Optional identifier for the plant/facility where the workstation is located.
    Useful for multi-site deployments.

.PARAMETER SlimOutputOnly
    When enabled, filters out Microsoft-built-in applications and services for cleaner output.
    The JSON structure remains identical; only the data content is filtered.
    Default: $true

.PARAMETER KeepOffice
    When SlimOutputOnly is enabled, keep Microsoft Office applications in the output.
    Default: $false

.PARAMETER KeepEdgeOneDrive
    When SlimOutputOnly is enabled, keep Microsoft Edge and OneDrive in the output.
    Default: $false

.PARAMETER KeepMsStoreApps
    When SlimOutputOnly is enabled, keep Microsoft Store apps in the output.
    Default: $false

.PARAMETER SlimOnlyRunningServices
    When SlimOutputOnly is enabled, only include running services in the output.
    Default: $false

.PARAMETER IncludeAppx
    Include AppX packages (Windows Store apps) in application discovery.
    Default: $false

.PARAMETER EmitStdOut
    Emit a summary JSON object to stdout in addition to writing the full JSON file.
    Useful for quick status checks or integration with other tools.
    Default: $false

.EXAMPLE
    .\Get-WorkstationDiscovery.ps1 -OldDomainFqdn "olddomain.com" -NewDomainFqdn "newdomain.com"
    
    Basic discovery with default settings.

.EXAMPLE
    .\Get-WorkstationDiscovery.ps1 `
        -OldDomainFqdn "OldCo.com" `
        -NewDomainFqdn "Newco.com" `
        -OldDomainNetBIOS "OldCo" `
        -CentralShare "\\fileserver\migration" `
        -OutputRoot "C:\temp\discovery\out" `
        -LogRoot "C:\temp\discovery\logs" `
        -PlantId "PLANT001" `
        -EmitStdOut
    
    Full discovery with central share and custom paths.

.EXAMPLE
    .\Get-WorkstationDiscovery.ps1 `
        -OldDomainFqdn "olddomain.com" `
        -NewDomainFqdn "newdomain.com" `
        -SlimOutputOnly `
        -KeepOffice `
        -SlimOnlyRunningServices
    
    Slim output mode with Office apps kept and only running services included.

.EXAMPLE
    .\Get-WorkstationDiscovery.ps1 -ConfigFile ".\migration-config.json"
    
    Load all settings from configuration file.

.EXAMPLE
    .\Get-WorkstationDiscovery.ps1 `
        -ConfigFile ".\migration-config.json" `
        -OldDomainFqdn "override.com"
    
    Load settings from config file, but override OldDomainFqdn with command-line value.

.NOTES
    - Requires PowerShell 5.1 or higher
    - Requires local Administrator rights for full functionality
    - Output JSON files may contain sensitive information (paths, account names)
    - Credential passwords are not extracted (they are encrypted in Windows Vault)
    - Execution time varies based on system size (profiles, services, etc.)
    - The JSON structure is consistent regardless of SlimOutputOnly setting

.LINK
    https://github.com/jefftier/DomainMigrationDiscovery

.VERSION
    1.7.0
#>
[CmdletBinding()]
param(
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) { return $true }
    if ($_ -notmatch '^\\\\[^\\]+\\[^\\]+') {
      throw "CentralShare must be a valid UNC path starting with '\\' (e.g., '\\server\share'). Provided value: '$_'"
    }
    return $true
  })]
  [string]$CentralShare,
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) {
      throw "OutputRoot cannot be empty. Please provide a valid local or UNC path."
    }
    # Allow both local paths (C:\...) and UNC paths (\\...)
    if ($_ -notmatch '^(?:[a-zA-Z]:\\|\\\\).*') {
      throw "OutputRoot must be a valid local path (e.g., 'C:\temp\path') or UNC path (e.g., '\\server\share'). Provided value: '$_'"
    }
    return $true
  })]
  [string]$OutputRoot = "C:\\temp\\MigrationDiscovery\\out",
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) {
      throw "LogRoot cannot be empty. Please provide a valid local or UNC path."
    }
    # Allow both local paths (C:\...) and UNC paths (\\...)
    if ($_ -notmatch '^(?:[a-zA-Z]:\\|\\\\).*') {
      throw "LogRoot must be a valid local path (e.g., 'C:\temp\path') or UNC path (e.g., '\\server\share'). Provided value: '$_'"
    }
    return $true
  })]
  [string]$LogRoot    = "C:\\temp\\MigrationDiscovery\\logs",
  
  [int]$ProfileDays   = 30,
  [int]$EventLogDays  = 7,
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) {
      throw "OldDomainFqdn cannot be empty. Please provide a valid FQDN (e.g., 'example.com' or 'subdomain.example.com')."
    }
    if ($_ -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$') {
      throw "OldDomainFqdn must be a valid FQDN (e.g., 'example.com' or 'subdomain.example.com'). It must contain at least one dot and only alphanumeric characters, hyphens, and dots. Provided value: '$_'"
    }
    return $true
  })]
  [string]$OldDomainFqdn = "OldCo.com",
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) {
      throw "NewDomainFqdn cannot be empty. Please provide a valid FQDN (e.g., 'example.com' or 'subdomain.example.com')."
    }
    if ($_ -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$') {
      throw "NewDomainFqdn must be a valid FQDN (e.g., 'example.com' or 'subdomain.example.com'). It must contain at least one dot and only alphanumeric characters, hyphens, and dots. Provided value: '$_'"
    }
    return $true
  })]
  [string]$NewDomainFqdn = "NewCo.com",
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) { return $true }
    if ($_.Length -gt 15) {
      throw "OldDomainNetBIOS must be 15 characters or less. Provided value has $($_.Length) characters: '$_'"
    }
    if ($_ -notmatch '^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$') {
      throw "OldDomainNetBIOS must contain only alphanumeric characters and hyphens, and cannot start or end with a hyphen. Provided value: '$_'"
    }
    return $true
  })]
  [string]$OldDomainNetBIOS,
  
  [switch]$IncludeAppx = $false,
  [switch]$EmitStdOut  = $false,
  [string]$PlantId,
  # Slim view controls
  [switch]$SlimOutputOnly = $true,
  [switch]$KeepOffice = $false,
  [switch]$KeepEdgeOneDrive = $false,
  [switch]$KeepMsStoreApps = $false,
  [switch]$SlimOnlyRunningServices = $false,
  
  [Parameter(HelpMessage="Path to JSON configuration file containing domain settings and tenant maps. Command-line parameters take precedence over config file values.")]
  [string]$ConfigFile = $null
)

# Load helper module (Domain References functions) early so they are available to discovery logic
$helperModulePath = Join-Path $PSScriptRoot 'DomainMigrationDiscovery.Helpers.psm1'
Import-Module $helperModulePath -Force -ErrorAction Stop

#region ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================
# PowerShell version compatibility check
if (-not $PSVersionTable -or -not $PSVersionTable.PSVersion) {
    $techError = "Unable to determine PowerShell version. This script requires at least PowerShell 5.1."
    Write-Error (Get-HumanReadableError -ErrorMessage $techError -Context "checking PowerShell version")
    exit 1
}

$script:PSMajorVersion = $PSVersionTable.PSVersion.Major

if ($script:PSMajorVersion -lt 5) {
    $techError = "This script requires PowerShell 5.1 or higher. Current version: $($PSVersionTable.PSVersion)"
    Write-Error (Get-HumanReadableError -ErrorMessage $techError -Context "checking PowerShell version")
    exit 1
}

# Set compatibility mode (for error handling and encoding)
if ($script:PSMajorVersion -lt 5) {
    $script:CompatibilityMode = 'Legacy3to4'
} else {
    $script:CompatibilityMode = 'Full'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#endregion

#region ============================================================================
# CONFIGURATION FILE LOADING
# ============================================================================
<#
.SYNOPSIS
    Loads configuration from a JSON file.

.DESCRIPTION
    Loads domain settings and tenant maps from a JSON configuration file.
    Only applies values that were not provided as command-line parameters.
    
.PARAMETER ConfigFilePath
    Path to the JSON configuration file.
    
.PARAMETER OldDomainFqdn
    Current OldDomainFqdn parameter value (reference).
    
.PARAMETER NewDomainFqdn
    Current NewDomainFqdn parameter value (reference).
    
.PARAMETER OldDomainNetBIOS
    Current OldDomainNetBIOS parameter value (reference).
    
.OUTPUTS
    Hashtable with loaded configuration values and updated tenant maps.
#>
function Import-ConfigurationFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigFilePath,
        
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn,
        [string]$OldDomainNetBIOS
    )
    
    if (-not (Test-Path -LiteralPath $ConfigFilePath)) {
        $techError = "Configuration file not found: $ConfigFilePath"
        Write-Warning (Get-HumanReadableError -ErrorMessage $techError -Context "loading configuration")
        return @{
            OldDomainFqdn = $OldDomainFqdn
            NewDomainFqdn = $NewDomainFqdn
            OldDomainNetBIOS = $OldDomainNetBIOS
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
    }
    
    try {
        $configContent = Get-Content -Path $ConfigFilePath -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop
        
        # Extract values from config file
        # The caller will decide whether to use these based on $PSBoundParameters
        $result = @{
            OldDomainFqdn = $OldDomainFqdn
            NewDomainFqdn = $NewDomainFqdn
            OldDomainNetBIOS = $OldDomainNetBIOS
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
        
        # Get domain settings from config file
        if ($config.PSObject.Properties['OldDomainFqdn']) {
            $result.OldDomainFqdn = $config.OldDomainFqdn
        }
        
        if ($config.PSObject.Properties['NewDomainFqdn']) {
            $result.NewDomainFqdn = $config.NewDomainFqdn
        }
        
        if ($config.PSObject.Properties['OldDomainNetBIOS']) {
            $result.OldDomainNetBIOS = $config.OldDomainNetBIOS
        }
        
        # Load CrowdStrike tenant map from config
        if ($config.PSObject.Properties['CrowdStrikeTenantMap']) {
            $csMap = @{}
            $config.CrowdStrikeTenantMap.PSObject.Properties | ForEach-Object {
                $csMap[$_.Name] = $_.Value
            }
            $result.CrowdStrikeTenantMap = $csMap
        }
        
        # Load Qualys tenant map from config
        if ($config.PSObject.Properties['QualysTenantMap']) {
            $qMap = @{}
            $config.QualysTenantMap.PSObject.Properties | ForEach-Object {
                $qMap[$_.Name] = $_.Value
            }
            $result.QualysTenantMap = $qMap
        }
        
        # Load Encase registry paths from config
        if ($config.PSObject.Properties['EncaseRegistryPaths']) {
            if ($config.EncaseRegistryPaths -is [System.Array]) {
                $result.EncaseRegistryPaths = $config.EncaseRegistryPaths
            } elseif ($config.EncaseRegistryPaths -is [string]) {
                $result.EncaseRegistryPaths = @($config.EncaseRegistryPaths)
            }
        }
        
        return $result
    }
    catch {
        $techError = "Failed to load configuration file '$ConfigFilePath': $($_.Exception.Message)"
        Write-Warning (Get-HumanReadableError -ErrorMessage $techError -Context "loading configuration file")
        return @{
            OldDomainFqdn = $OldDomainFqdn
            NewDomainFqdn = $NewDomainFqdn
            OldDomainNetBIOS = $OldDomainNetBIOS
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
    }
}
#endregion

#region ============================================================================
# ═══════════════════════════════════════════════════════════════════════════
# USER CONFIGURATION SECTION
# ═══════════════════════════════════════════════════════════════════════════
# ============================================================================
# 
# IMPORTANT: These are the PRIMARY user-configurable settings.
# Modify the variables below to customize the script for your environment.
#
# Most other settings are controlled via script parameters (see param block above).
#
# ============================================================================

# Script Version (for tracking and reporting)
$ScriptVersion = '1.7.0'

# ----------------------------------------------------------------------------
# Security Agent Tenant Mapping
# ----------------------------------------------------------------------------
# These mappings are used to identify which tenant/company a security agent
# is configured for. This is useful in multi-tenant environments or during
# domain migrations where agents may be configured for different tenants.
#
# ----------------------------------------------------------------------------

# CrowdStrike Configuration
# Map CU (Customer UUID) hex values to friendly tenant names
# 
# How to find CU values:
#   - Check CrowdStrike agent configuration
#   - Look in registry: HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Config
#   - Check CrowdStrike Falcon console
#
# Format: @{ 'CU_HEX_VALUE' = 'Friendly Name' }
# These defaults can be overridden by -ConfigFile parameter
$CrowdStrikeTenantMap = @{
    '<CU_HEX_VALUE_1>' = 'CS NewCo1'
    '<CU_HEX_VALUE_2>' = 'CS Newco2'
    'DEFAULT' = 'Oldco'  # Used when CU is found but not in the map above
    'UNKNOWN' = 'Unknown'  # Used when CU is not found
}

# Qualys Configuration
# Map ActivationID GUID values to friendly tenant names
#
# How to find ActivationID:
#   - Check Qualys agent configuration
#   - Look in registry: HKLM\SOFTWARE\Qualys\QualysAgent\Config
#   - Check Qualys Cloud Platform
#
# Format: @{ 'ACTIVATION_ID_GUID' = 'Friendly Name' }
# These defaults can be overridden by -ConfigFile parameter
$QualysTenantMap = @{
    '<QUALYS_ACTIVATION_ID>' = 'Qualys NewCo'
    'DEFAULT' = 'OldCo'  # Used when ActivationID is found but not in the map above
    'UNKNOWN' = 'Unknown'  # Used when ActivationID is not found
}

# SCCM Configuration
# SCCM tenant detection searches for OldDomainFqdn and NewDomainFqdn in the registry
# and reports which domain is found. No tenant map is needed as it uses the domain parameters.

# Encase Configuration
# Registry paths to check for Encase tenant identification
# These can be overridden by -ConfigFile parameter (EncaseRegistryPaths)
# Format: Array of registry paths relative to HKLM\SOFTWARE\Microsoft\
# Example: @('Encase_NewDomain', 'Encase_OldDomain')
$EncaseRegistryPaths = @()

# Load configuration from file if provided
# Command-line parameters take precedence over config file values
if ($ConfigFile) {
    $loadedConfig = Import-ConfigurationFile -ConfigFilePath $ConfigFile -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn -OldDomainNetBIOS $OldDomainNetBIOS
    
    # Apply domain settings from config file (only if not explicitly provided as parameters)
    # Use $PSBoundParameters to check if parameter was explicitly provided on command line
    if ($loadedConfig.OldDomainFqdn -and -not $PSBoundParameters.ContainsKey('OldDomainFqdn')) {
        $OldDomainFqdn = $loadedConfig.OldDomainFqdn
    }
    if ($loadedConfig.NewDomainFqdn -and -not $PSBoundParameters.ContainsKey('NewDomainFqdn')) {
        $NewDomainFqdn = $loadedConfig.NewDomainFqdn
    }
    if ($loadedConfig.OldDomainNetBIOS -and -not $PSBoundParameters.ContainsKey('OldDomainNetBIOS')) {
        $OldDomainNetBIOS = $loadedConfig.OldDomainNetBIOS
    }
    
    # Apply tenant maps from config file if provided (these can't be passed as parameters)
    if ($loadedConfig.CrowdStrikeTenantMap) {
        $CrowdStrikeTenantMap = $loadedConfig.CrowdStrikeTenantMap
    }
    if ($loadedConfig.QualysTenantMap) {
        $QualysTenantMap = $loadedConfig.QualysTenantMap
    }
    if ($loadedConfig.EncaseRegistryPaths) {
        $EncaseRegistryPaths = $loadedConfig.EncaseRegistryPaths
    }
}

# ============================================================================
# END USER CONFIGURATION SECTION
# ============================================================================
# 
# Everything below this point is script logic. Do not modify unless you
# understand the implications of your changes.
#
# ============================================================================
#endregion

#region ============================================================================
# SCRIPT STRUCTURE
# ============================================================================
# 
# This script is organized into the following sections:
#
# 1. USER CONFIGURATION (above)
#    - Security agent tenant mappings
#    - Modify these variables to customize for your environment
#
# 2. HELPER FUNCTIONS (below)
#    - Core utilities: Directory, logging, error handling
#    - Registry operations: Hive loading, registry value reading
#    - Domain detection: Pattern matching, filtering logic
#    - Data collection: Security agents, groups, ODBC, credentials, etc.
#
# 3. MAIN EXECUTION
#    - Initialization: Logger, domain matchers, system info, central share validation
#    - Data Collection: Profiles, apps, services, tasks, printers, etc.
#    - Domain Detection: Scan collected data for old domain references
#    - Data Filtering: Apply slim mode filters if enabled
#    - Output Generation: Build JSON and write files
#
# ============================================================================
#endregion

#region ============================================================================
# HELPER FUNCTIONS - Core Utilities
# ============================================================================

<#
.SYNOPSIS
    Ensures a directory exists, creating it if necessary.

.DESCRIPTION
    Creates the specified directory path if it does not already exist.
    Silently handles null or empty paths.

.PARAMETER path
    The directory path to ensure exists.

.EXAMPLE
    Ensure-Directory "C:\temp\logs"
#>
<#
.SYNOPSIS
    Ensures a directory exists, creating it if necessary.

.DESCRIPTION
    Creates the specified directory path if it does not already exist.
    Silently handles null or empty paths.

.PARAMETER path
    The directory path to ensure exists.

.EXAMPLE
    Ensure-Directory "C:\temp\logs"
#>
function Ensure-Directory([string]$path) {
  if (-not [string]::IsNullOrWhiteSpace($path)) {
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
  }
}

<#
.SYNOPSIS
    Creates a logger object for writing timestamped log messages.

.DESCRIPTION
    Creates a custom logger object that writes timestamped log messages to a file.
    Log files are named with the format: {Prefix}_{COMPUTERNAME}_{timestamp}.log

.PARAMETER LogDirectory
    The directory where log files will be created.

.PARAMETER Prefix
    Prefix for the log file name. Default: 'discovery'

.OUTPUTS
    PSCustomObject with a Write method for logging messages.

.EXAMPLE
    $log = New-Logger -LogDirectory "C:\logs" -Prefix "discovery"
    $log.Write("Starting discovery", "INFO")
#>
function New-Logger {
  param([Parameter(Mandatory)][string]$LogDirectory, [string]$Prefix = 'discovery')
  Ensure-Directory $LogDirectory
  $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $logFileName = ('{0}_{1}_{2}.log' -f $Prefix, $env:COMPUTERNAME, $stamp)
  $logPath = Join-Path $LogDirectory $logFileName
  $logger = [pscustomobject]@{ Path = $logPath }
  $null = $logger | Add-Member -MemberType ScriptMethod -Name Write -Value {
    param([string]$msg, [string]$level = 'INFO')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$ts][$level] $msg"
    Add-Content -Path $this.Path -Value $line
    Write-Verbose $line
  }
  return $logger
}

<#
.SYNOPSIS
    Converts technical error messages to human-readable format for console output.

.DESCRIPTION
    Takes a technical error message or exception and converts it to a simple,
    layman-friendly message that explains what went wrong in plain language.
    The full technical error should still be logged separately.

.PARAMETER ErrorMessage
    The technical error message or exception object to convert.

.PARAMETER Context
    Optional context about what operation was being performed when the error occurred.

.OUTPUTS
    A human-readable error message string.
#>
function Get-HumanReadableError {
  param(
    [Parameter(Mandatory=$false)]
    [object]$ErrorMessage,
    [Parameter(Mandatory=$false)]
    [string]$Context = ""
  )
  
  try {
    $msg = if ($ErrorMessage -is [System.Exception]) {
      if ($null -ne $ErrorMessage -and $null -ne $ErrorMessage.Message) {
        $ErrorMessage.Message
      } else {
        "Unknown exception"
      }
    } else {
      [string]$ErrorMessage
    }
    
    if ([string]::IsNullOrWhiteSpace($msg)) {
      return "Unexpected error"
    }
    
    $msgLower = $msg.ToLower()
  
  # Common error pattern matching for human-readable conversion - SHORT messages
  if ($msgLower -match "powershell version|requires.*powershell") {
    return "PowerShell 5.1+ required"
  }
  elseif ($msgLower -match "configuration file|config file") {
    return "Config file error - check file exists and format"
  }
  elseif ($msgLower -match "json|convertto-json|serialization") {
    return "Data format error - check output file"
  }
  elseif ($msgLower -match "cannot bind|parameter.*cannot be found") {
    return "Missing required parameter - check configuration"
  }
  elseif ($msgLower -match "disk space|no space left|disk full") {
    return "Insufficient disk space"
  }
  elseif ($msgLower -match "insufficient memory|out of memory") {
    return "Insufficient memory"
  }
  elseif ($msgLower -match "timeout|timed out|operation timed out") {
    return "Operation timed out"
  }
  elseif ($msgLower -match "cannot connect|connection refused|network path not found|remote procedure call failed") {
    return "Connection failed"
  }
  elseif ($msgLower -match "cannot find path|path not found|does not exist|file not found") {
    return "Path not found"
  }
  else {
    # Generic fallback - very short
    if ($Context) {
      return "Error: $Context"
    } else {
      return "Unexpected error"
    }
  }
  } catch {
    # If Get-HumanReadableError itself fails, return a safe fallback message
    return "Error occurred"
  }
}

<#
.SYNOPSIS
    Determines if an error is actionable (user can fix) vs expected (routine permission/access issues).

.DESCRIPTION
    Returns true if the error is something the user can act on (config issues, fatal errors),
    false if it's an expected routine error (permission denied on individual files, etc.).

.PARAMETER ErrorMessage
    The error message or exception to check.

.PARAMETER Context
    The context/operation that failed.

.OUTPUTS
    Boolean - true if error is actionable, false if expected/routine.
#>
function Test-IsActionableError {
  param(
    [Parameter(Mandatory=$false)]
    [object]$ErrorMessage,
    [Parameter(Mandatory=$false)]
    [string]$Context = ""
  )
  
  try {
    $msg = if ($ErrorMessage -is [System.Exception]) {
      if ($null -ne $ErrorMessage -and $null -ne $ErrorMessage.Message) {
        $ErrorMessage.Message
      } else {
        ""
      }
    } else {
      [string]$ErrorMessage
    }
    
    if ([string]::IsNullOrWhiteSpace($msg)) {
      return $false
    }
    
    $msgLower = $msg.ToLower()
    $contextLower = $Context.ToLower()
    
    # Actionable errors - user can fix these
    if ($msgLower -match "powershell version|requires.*powershell") { return $true }
    if ($msgLower -match "configuration file|config file") { return $true }
    if ($msgLower -match "json|convertto-json|serialization") { return $true }
    if ($msgLower -match "cannot bind|parameter.*cannot be found") { return $true }
    if ($msgLower -match "disk space|no space left|disk full") { return $true }
    if ($msgLower -match "insufficient memory|out of memory") { return $true }
    
    # Expected/non-actionable errors - these are routine and expected
    # Permission denied on individual files/directories is expected
    if ($msgLower -match "access is denied|unauthorizedaccessexception|permission denied") {
      # But if it's a critical operation, it's actionable
      if ($contextLower -match "config|json|output|write") { return $true }
      return $false  # Expected for individual file/registry access
    }
    
    # Event log, registry, file access errors are usually expected
    if ($msgLower -match "event log|eventlog|registry|registry key") { return $false }
    if ($contextLower -match "credentialmanager|eventlog|applicationconfig|scanning|reading") { return $false }
    
    # File not found for individual items is expected
    if ($msgLower -match "cannot find path|path not found|does not exist|file not found") {
      if ($contextLower -match "config|output") { return $true }
      return $false  # Expected for scanning operations
    }
    
    # Default: show critical errors, hide routine ones
    return $false
  } catch {
    return $false
  }
}
#endregion

#region ============================================================================
# HELPER FUNCTIONS - Registry Operations
# ============================================================================
<#
.SYNOPSIS
    Executes a scriptblock with error handling, returning null on failure.

.DESCRIPTION
    Wraps scriptblock execution in try-catch to prevent script termination on errors.
    Logs warnings for failures and returns null instead of throwing exceptions.

.PARAMETER sb
    The scriptblock to execute.

.PARAMETER topic
    Description of the operation for logging purposes.

.OUTPUTS
    The result of the scriptblock execution, or $null if an error occurred.

.EXAMPLE
    $result = Safe-Try { Get-Service "SomeService" } "Get service"
#>
function Safe-Try([scriptblock]$sb, [string]$topic){
  try { & $sb }
  catch {
    $techMsg = "$topic failed: $($_.Exception.Message)"
    # Always log full technical details to log file
    if ($script:log) { $script:log.Write($techMsg,'WARN') }
    
    # Only show actionable errors on console (not routine permission/access issues)
    $isActionable = Test-IsActionableError -ErrorMessage $_.Exception -Context $topic
    if ($isActionable) {
      try {
        $humanMsg = Get-HumanReadableError -ErrorMessage $_.Exception -Context $topic
        Write-Warning $humanMsg
      } catch {
        # If Get-HumanReadableError fails, use a simple fallback
        Write-Warning "Error: $topic"
      }
    }
    # For non-actionable errors, silently continue (they're logged to file)
    $null
  }
}

function Convert-LastUseTime($val){
  if ($null -eq $val) { return $null }
  if ($val -is [datetime]) { return $val.ToUniversalTime() }
  if ($val -is [int64] -or ($val -is [string] -and $val -match '^\d+$')) {
    try { return [DateTime]::FromFileTimeUtc([int64]$val) } catch { return $null }
  }
  if ($val -is [string] -and $val.Length -ge 25 -and $val -match '^\d{14}\.\d{6}[\+\-]\d{3}$') {
    try { return [System.Management.ManagementDateTimeConverter]::ToDateTime($val).ToUniversalTime() } catch { return $null }
  }
  try { return [datetime]::Parse($val,[System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() } catch { return $null }
}

<#
.SYNOPSIS
    Retrieves uninstall items from a registry hive.

.DESCRIPTION
    Scans the Windows Uninstall registry keys in the specified hive for installed applications.

.PARAMETER root
    The registry root key to scan.

.OUTPUTS
    Array of PSCustomObject with application information.
#>
function Get-UninstallItemsFromHive([Microsoft.Win32.RegistryKey]$root){
  $items = @()
  foreach ($path in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
    try {
      $key = $root.OpenSubKey($path)
      if ($null -eq $key) { continue }
      foreach ($subName in $key.GetSubKeyNames()){
        try {
          $sub = $key.OpenSubKey($subName)
          if ($null -eq $sub) { continue }
          $disp = $sub.GetValue('DisplayName')
          if ([string]::IsNullOrWhiteSpace($disp)) { continue }
          $items += [pscustomobject]@{
            DisplayName     = [string]$disp
            DisplayVersion  = [string]$sub.GetValue('DisplayVersion')
            Publisher       = [string]$sub.GetValue('Publisher')
            InstallDate     = [string]$sub.GetValue('InstallDate')
            InstallLocation = [string]$sub.GetValue('InstallLocation')
            UninstallString = [string]$sub.GetValue('UninstallString')
            KeyPath         = "HK:\$path\$subName"
            Scope           = 'Machine'
          }
        } catch {}
      }
    } catch {}
  }
  $items
}

<#
.SYNOPSIS
    Loads a user registry hive for offline access.

.DESCRIPTION
    Loads a user's NTUSER.DAT file into the registry so it can be accessed via HKEY_USERS.

.PARAMETER sid
    The Security Identifier (SID) of the user.

.PARAMETER ntuserPath
    The path to the NTUSER.DAT file.

.OUTPUTS
    Boolean indicating if the hive was loaded (true) or already existed (false).
#>
function Load-UserHive([string]$sid,[string]$ntuserPath){
  if (-not (Test-Path "Registry::HKEY_USERS\$sid") -and (Test-Path $ntuserPath)){
    for($i=0; $i -lt 3; $i++){
      $p = Start-Process reg.exe -ArgumentList @('load',"HKU\$sid","$ntuserPath") -Wait -PassThru -WindowStyle Hidden
      if ($p.ExitCode -eq 0) { return $true }
      Start-Sleep -Seconds (2 * ($i+1))
    }
    throw "Unable to load hive for $sid"
  }
  return $false
}

<#
.SYNOPSIS
    Unloads a previously loaded user registry hive.

.DESCRIPTION
    Unloads a user registry hive that was loaded via Load-UserHive.

.PARAMETER sid
    The Security Identifier (SID) of the user.

.PARAMETER didLoad
    Boolean indicating if this function loaded the hive (true) or it already existed (false).
#>
function Unload-UserHive([string]$sid,[bool]$didLoad){
  if ($didLoad) {
    [gc]::Collect(); [gc]::WaitForPendingFinalizers();
    & reg.exe unload "HKU\$sid" | Out-Null
  }
}

function Get-RegistryValueMultiView {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('LocalMachine','CurrentUser','Users','CurrentConfig')]
        [string]$Hive,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    $hiveEnum = switch ($Hive) {
        'LocalMachine'  { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'CurrentUser'   { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'Users'         { [Microsoft.Win32.RegistryHive]::Users }
        'CurrentConfig' { [Microsoft.Win32.RegistryHive]::CurrentConfig }
    }
    $views = if ([Environment]::Is64BitOperatingSystem) {
        @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    } else {
        @([Microsoft.Win32.RegistryView]::Registry32)
    }
    foreach ($v in $views) {
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveEnum, $v)
            $k = $base.OpenSubKey($Path)
            if ($null -ne $k) {
                $raw = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
                if ($null -ne $raw) {
                    # Return both raw object and a normalized string representation
                    $type = $k.GetValueKind($Name)
                    $asString = $null
                    switch ($type) {
                        'Binary' {
                            # Convert byte[] to uppercase hex string without separators
                            $bytes = [byte[]]$raw
                            $asString = ([System.BitConverter]::ToString($bytes)).Replace('-', '')
                        }
                        'DWord' { $asString = ([uint32]$raw).ToString() }
                        'QWord' { $asString = ([uint64]$raw).ToString() }
                        default { $asString = [string]$raw }
                    }
                    return [pscustomobject]@{ Raw=$raw; Kind=$type; String=$asString }
                }
            }
        } catch {}
    }
    return $null
}
#endregion

#region ============================================================================
# HELPER FUNCTIONS - Domain Detection and Filtering
# ============================================================================
<#
.SYNOPSIS
    Creates domain matcher objects for detecting old domain references.

.DESCRIPTION
    Creates regex patterns for matching old domain references in various formats:
    - NetBIOS name (e.g., "OLDDOMAIN")
    - FQDN (e.g., "olddomain.com")
    - UPN format (e.g., "@olddomain.com")
    - LDAP DN format (e.g., "DC=olddomain,DC=com")

.PARAMETER netbios
    The NetBIOS name of the old domain.

.PARAMETER fqdn
    The FQDN of the old domain.

.OUTPUTS
    PSCustomObject with regex patterns and a Match method.
#>
function New-OldDomainMatchers([string]$netbios,[string]$fqdn){
  $dn = ($fqdn -split '\.' | ForEach-Object { "DC=$_" }) -join ','
  $obj = [pscustomobject]@{
    Netbios = if ($netbios) { [regex]::new("(?i)\b$([regex]::Escape($netbios))\b") } else { $null }
    Fqdn    = if ($fqdn)   { [regex]::new("(?i)$([regex]::Escape($fqdn))") } else { $null }
    Upn     = if ($fqdn)   { [regex]::new("(?i)@$([regex]::Escape($fqdn))$") } else { $null }
    LdapDn  = if ($fqdn)   { [regex]::new("(?i)$([regex]::Escape($dn))") } else { $null }
  }
  $null = $obj | Add-Member -MemberType ScriptMethod -Name Match -Value {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    foreach($r in @($this.Netbios,$this.Fqdn,$this.Upn,$this.LdapDn)){ if ($r -and $r.IsMatch($s)) { return $true } }
    return $false
  }
  return $obj
}

<#
.SYNOPSIS
    Tests if a binary is signed by Microsoft.

.DESCRIPTION
    Checks if an executable file is signed by Microsoft by examining its Authenticode signature.
    Results are cached for performance.

.PARAMETER path
    The path to the executable file (may include command-line arguments).

.OUTPUTS
    Boolean indicating if the file is a Microsoft-signed binary.
#>
$SignatureCache = @{}
function Test-IsMicrosoftBinary{ param([string]$path)
  if ([string]::IsNullOrWhiteSpace($path)) { return $false }
  $exe = Get-ExecutableFromCommand $path
  if ([string]::IsNullOrWhiteSpace($exe)) { return $false }
  if ($SignatureCache.ContainsKey($exe)) { return [bool]$SignatureCache[$exe] }
  $win = $env:windir; if (-not $win) { $win = 'C:\\Windows' }
  if ($exe -like "$win\\*") { $SignatureCache[$exe] = $true; return $true }
  if (-not (Test-Path -LiteralPath $exe)) { $SignatureCache[$exe] = $false; return $false }
  $result = $false
  try { $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop; $result = ($sig.SignerCertificate.Subject -match '(?i)Microsoft' -and $sig.Status -eq 'Valid') } catch { $result = $false }
  $SignatureCache[$exe] = $result; return $result
}

<#
.SYNOPSIS
    Tests if a service account is a built-in Windows account.

.DESCRIPTION
    Checks if the service start name is a built-in Windows account like LocalSystem,
    LocalService, or NetworkService.

.PARAMETER startName
    The service start name to check.

.OUTPUTS
    Boolean indicating if the account is a built-in service account.
#>
function Test-IsBuiltinServiceAccount([string]$startName){ $startName = ([string]$startName).ToUpperInvariant(); return $startName -in @('LOCALSYSTEM','NT AUTHORITY\\LOCALSERVICE','NT AUTHORITY\\NETWORKSERVICE') }

<#
.SYNOPSIS
    Tests if a scheduled task path is a Microsoft system task.

.DESCRIPTION
    Checks if the task path indicates it's a Microsoft system task (e.g., "\Microsoft\...").

.PARAMETER taskPath
    The scheduled task path to check.

.OUTPUTS
    Boolean indicating if the task is a Microsoft system task.
#>
function Test-IsMicrosoftTaskPath([string]$taskPath){ return $taskPath -match '(?i)^\\+Microsoft\\' }
#endregion

#region ============================================================================
# HELPER FUNCTIONS - Data Collection
# ============================================================================
<#
.SYNOPSIS
    Searches SCCM registry for domain references.

.DESCRIPTION
    Recursively searches the SCCM registry path (HKLM\SOFTWARE\Microsoft\CCM) for
    any values containing OldDomainFqdn or NewDomainFqdn references.
    Returns information about found domain references and determines tenant.

.PARAMETER Log
    Logger object for writing log messages.

.PARAMETER OldDomainFqdn
    The old domain FQDN to search for.

.PARAMETER NewDomainFqdn
    The new domain FQDN to search for.

.OUTPUTS
    PSCustomObject with SCCM tenant information including found domain references.
#>
function Get-SCCMTenantInfo {
    [CmdletBinding()]
    param(
        $Log,
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn
    )
    
    if ($Log) { $Log.Write('Detect: starting SCCM tenant check') }
    
    $sccmRegPath = 'SOFTWARE\Microsoft\CCM'
    $domainReferences = @()
    $foundDomains = @()
    
    # Domains to search for (OldDomain and NewDomain)
    $searchDomains = @()
    if (-not [string]::IsNullOrWhiteSpace($OldDomainFqdn)) {
        $searchDomains += $OldDomainFqdn
    }
    if (-not [string]::IsNullOrWhiteSpace($NewDomainFqdn)) {
        $searchDomains += $NewDomainFqdn
    }
    
    if ($searchDomains.Count -eq 0) {
        if ($Log) { $Log.Write('No domains provided for SCCM search', 'WARN') }
        return [pscustomobject]@{
            RegPath = "HKLM:\$sccmRegPath"
            Found = $false
            DomainReferences = @()
            FoundDomains = @()
            Tenant = 'Unknown'
            HasDomainReference = $false
        }
    }
    
    try {
        # Check if SCCM registry path exists
        $baseKey = [Microsoft.Win32.Registry]::LocalMachine
        $ccmKey = $baseKey.OpenSubKey($sccmRegPath)
        
        if ($null -eq $ccmKey) {
            if ($Log) { $Log.Write("SCCM registry path not found: HKLM\$sccmRegPath", 'INFO') }
            return [pscustomobject]@{
                RegPath = "HKLM:\$sccmRegPath"
                Found = $false
                DomainReferences = @()
                FoundDomains = @()
                Tenant = 'Unknown'
                HasDomainReference = $false
            }
        }
        
        # Recursively search registry values
        function Search-RegistryRecursive {
            param(
                [Microsoft.Win32.RegistryKey]$key,
                [string]$basePath,
                [string[]]$domains,
                [System.Collections.ArrayList]$results
            )
            
            try {
                # Search all value names in current key
                $valueNames = $key.GetValueNames()
                foreach ($valueName in $valueNames) {
                    try {
                        $value = $key.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
                        if ($null -ne $value) {
                            # Handle REG_MULTI_SZ (array) and single string values
                            $valuesToCheck = @()
                            if ($value -is [array]) {
                                # REG_MULTI_SZ - check each element in the array
                                $valuesToCheck = $value
                            } else {
                                # Single value - convert to string
                                $valuesToCheck = @([string]$value)
                            }
                            
                            # Check each value (or array element) for domain matches
                            foreach ($valueToCheck in $valuesToCheck) {
                                if ($null -ne $valueToCheck) {
                                    $valueStr = [string]$valueToCheck
                                    
                                    # Check each domain (case-insensitive)
                                    foreach ($domain in $domains) {
                                        $pattern = [regex]::new("(?i)" + [regex]::Escape($domain))
                                        if ($pattern.IsMatch($valueStr)) {
                                            # For arrays, show the full array in Value; for single values, show the string
                                            $displayValue = if ($value -is [array]) { ($value -join ' | ') } else { $valueStr }
                                            $null = $results.Add([pscustomobject]@{
                                                Path = $basePath
                                                ValueName = $valueName
                                                Value = $displayValue
                                                Domain = $domain
                                            })
                                            break  # Found a match, no need to check other domains for this value
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        # Skip values that can't be read
                    }
                }
                
                # Recursively search subkeys
                $subKeyNames = $key.GetSubKeyNames()
                foreach ($subKeyName in $subKeyNames) {
                    try {
                        $subKey = $key.OpenSubKey($subKeyName)
                        if ($null -ne $subKey) {
                            $newPath = if ($basePath) { "$basePath\$subKeyName" } else { $subKeyName }
                            Search-RegistryRecursive -key $subKey -basePath $newPath -domains $domains -results $results
                            $subKey.Close()
                        }
                    } catch {
                        # Skip subkeys that can't be accessed
                    }
                }
            } catch {
                # Skip keys that can't be accessed
            }
        }
        
        $resultsList = [System.Collections.ArrayList]::new()
        Search-RegistryRecursive -key $ccmKey -basePath $sccmRegPath -domains $searchDomains -results $resultsList
        $domainReferences = $resultsList.ToArray()
        $ccmKey.Close()
        
        # Extract unique found domains (ensure array for .Count)
        $foundDomains = @($domainReferences | Select-Object -ExpandProperty Domain -Unique)
        
        # Determine tenant based on found domains
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
        if ($foundDomains.Count -gt 0) {
            $hasDomainReference = $true
            # Determine tenant: if OldDomain found, report as "OldDomain", if NewDomain found, report as "NewDomain"
            # If both found, prioritize NewDomain
            if ($foundDomains -contains $NewDomainFqdn) {
                $sccmTenant = 'NewDomain'
            } elseif ($foundDomains -contains $OldDomainFqdn) {
                $sccmTenant = 'OldDomain'
            } else {
                # Found a domain but it's not one we're tracking - report the first found
                $sccmTenant = $foundDomains[0]
            }
        }
        
        return [pscustomobject]@{
            RegPath = "HKLM:\$sccmRegPath"
            Found = $true
            DomainReferences = $domainReferences
            FoundDomains = $foundDomains
            Tenant = $sccmTenant
            HasDomainReference = $hasDomainReference
        }
        
    } catch {
        if ($Log) { $Log.Write("Error searching SCCM registry: $($_.Exception.Message)", 'WARN') }
        return [pscustomobject]@{
            RegPath = "HKLM:\$sccmRegPath"
            Found = $false
            DomainReferences = @()
            FoundDomains = @()
            Tenant = 'Unknown'
            HasDomainReference = $false
        }
    }
}

<#
.SYNOPSIS
    Checks for Encase installation and tenant information.

.DESCRIPTION
    Checks if Encase is installed by looking for the enstart64 service.
    Also checks for tenant registry keys specified in EncaseRegistryPaths
    to determine which tenant Encase is configured for.

.PARAMETER Log
    Logger object for writing log messages.

.PARAMETER EncaseRegistryPaths
    Array of registry paths (relative to HKLM\SOFTWARE\Microsoft\) to check for tenant identification.

.OUTPUTS
    PSCustomObject with Encase installation and tenant information.
#>
function Get-EncaseTenantInfo {
    [CmdletBinding()]
    param(
        $Log,
        [string[]]$EncaseRegistryPaths = @()
    )
    
    if ($Log) { $Log.Write('Detect: starting Encase tenant check') }
    
    $serviceName = 'enstart64'
    $installed = $false
    $tenantKey = $null
    $tenant = 'Unknown'
    
    try {
        # Check if enstart64 service exists
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $installed = $true
            if ($Log) { $Log.Write("Encase service '$serviceName' found", 'INFO') }
        } else {
            if ($Log) { $Log.Write("Encase service '$serviceName' not found", 'INFO') }
        }
    } catch {
        if ($Log) { $Log.Write("Error checking for Encase service: $($_.Exception.Message)", 'WARN') }
    }
    
    # Check for tenant registry keys
    if ($EncaseRegistryPaths.Count -gt 0) {
        try {
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine
            $tenantKeys = @()
            
            # Check all configured registry paths
            foreach ($keyName in $EncaseRegistryPaths) {
                if (-not [string]::IsNullOrWhiteSpace($keyName)) {
                    $testPath = "SOFTWARE\Microsoft\$keyName"
                    try {
                        $testKey = $baseKey.OpenSubKey($testPath)
                        if ($null -ne $testKey) {
                            $tenantKeys += $keyName
                            $testKey.Close()
                            if ($Log) { $Log.Write("Encase tenant registry key found: HKLM\$testPath", 'INFO') }
                        }
                    } catch {
                        # Key doesn't exist or can't be accessed
                    }
                }
            }
            
            # Determine tenant based on found registry keys
            if ($tenantKeys.Count -gt 0) {
                # Use the first found tenant key as the tenant identifier
                $tenantKey = $tenantKeys[0]
                $tenant = $tenantKey  # Use the registry key name as the tenant identifier
            }
        } catch {
            if ($Log) { $Log.Write("Error checking Encase registry: $($_.Exception.Message)", 'WARN') }
        }
    }
    
    return [pscustomobject]@{
        Installed = $installed
        ServiceName = $serviceName
        RegPath = if ($tenantKey) { "HKLM:\SOFTWARE\Microsoft\$tenantKey" } else { $null }
        TenantKey = $tenantKey
        Tenant = $tenant
    }
}

<#
.SYNOPSIS
    Retrieves security agent tenant information.

.DESCRIPTION
    Collects information about CrowdStrike, Qualys, SCCM, and Encase security agents, including
    their tenant configuration. Uses the user-configurable tenant maps to identify
    which tenant each agent is configured for.

.PARAMETER Log
    Logger object for writing log messages.

.PARAMETER OldDomainFqdn
    The old domain FQDN for SCCM search.

.PARAMETER NewDomainFqdn
    The new domain FQDN for SCCM search.

.PARAMETER EncaseRegistryPaths
    Array of registry paths to check for Encase tenant identification.

.OUTPUTS
    PSCustomObject with CrowdStrike, Qualys, SCCM, and Encase tenant information.
#>
function Get-SecurityAgentsTenantInfo {
    [CmdletBinding()]
    param(
        $Log,
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn,
        [string[]]$EncaseRegistryPaths = @()
    )
    if ($Log) { $Log.Write('Detect: starting security agent tenant checks') }

    # CrowdStrike (Falcon Sensor)
    $csRegPath = 'System\\CurrentControlSet\\Services\\CSAgent\\Sim'
    $csValName = 'CU'
    $cs = Get-RegistryValueMultiView -Hive LocalMachine -Path $csRegPath -Name $csValName
    $csHex = if ($cs) { $cs.String } else { $null }
    
    # Determine tenant name using user-configurable mapping
    if ($null -eq $csHex) {
        $csTenant = $CrowdStrikeTenantMap['UNKNOWN']
    } elseif ($CrowdStrikeTenantMap.ContainsKey($csHex)) {
        $csTenant = $CrowdStrikeTenantMap[$csHex]
    } else {
        $csTenant = $CrowdStrikeTenantMap['DEFAULT']
    }

    # Qualys
    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
    # Determine tenant name using user-configurable mapping
    if ($null -eq $qStr) {
        $qTenant = $QualysTenantMap['UNKNOWN']
    } elseif ($QualysTenantMap.ContainsKey($qStr)) {
        $qTenant = $QualysTenantMap[$qStr]
    } else {
        $qTenant = $QualysTenantMap['DEFAULT']
    }

    # SCCM (Configuration Manager)
    $sccmInfo = Get-SCCMTenantInfo -Log $Log -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn

    # Encase
    $encaseInfo = Get-EncaseTenantInfo -Log $Log -EncaseRegistryPaths $EncaseRegistryPaths

    [pscustomobject]@{
        CrowdStrike = [pscustomobject]@{
            RegPath   = 'HKLM:\System\CurrentControlSet\Services\CSAgent\Sim'
            ValueName = $csValName
            Kind      = if ($cs) { $cs.Kind } else { $null }
            Raw       = if ($cs -and $cs.PSObject.Properties['Raw']) { if ($cs.Kind -eq 'Binary') { [System.BitConverter]::ToString([byte[]]$cs.Raw) } else { $cs.Raw } } else { $null }
            String    = $csHex
            Tenant    = $csTenant
        }
        Qualys = [pscustomobject]@{
            RegPath   = 'HKLM:\Software\Qualys'
            ValueName = $qValName
            Kind      = if ($q) { $q.Kind } else { $null }
            Raw       = if ($q -and $q.PSObject.Properties['Raw']) { $q.Raw } else { $null }
            String    = $qStr
            Tenant    = $qTenant
        }
        SCCM = [pscustomobject]@{
            RegPath           = $sccmInfo.RegPath
            Found             = $sccmInfo.Found
            DomainReferences  = $sccmInfo.DomainReferences
            FoundDomains      = $sccmInfo.FoundDomains
            Tenant            = $sccmInfo.Tenant
            HasDomainReference = $sccmInfo.HasDomainReference
        }
        Encase = [pscustomobject]@{
            Installed  = $encaseInfo.Installed
            ServiceName = $encaseInfo.ServiceName
            RegPath    = $encaseInfo.RegPath
            TenantKey  = $encaseInfo.TenantKey
            Tenant     = $encaseInfo.Tenant
        }
    }
}

function Get-LocalGroupMembersSafe([string]$group){
  $members = @()
  try {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){
      return Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
          Group = $group
          Name  = $_.Name
          ObjectClass = $_.ObjectClass
          PrincipalSource = $_.PrincipalSource
          SID = $_.SID.Value
        }
      }
    }
  } catch {}
  try {
    $grp = [ADSI]"WinNT://./$group,group"
    $grp.psbase.Invoke('Members') | ForEach-Object {
      $p = $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)
      $class = $null
      try { $class = $_.GetType().InvokeMember('Class','GetProperty',$null,$_,$null) } catch {}
      [pscustomobject]@{
        Group = $group
        Name  = [string]$p
        ObjectClass = $class
        PrincipalSource = 'WinNT'
        SID = $null
      }
    }
  } catch {}
  $members
}

function Get-LocalAdministratorsDetailed{
  $items = @()
  try {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){
      $items = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
        $nm = $_.Name
        $sid = $_.SID.Value
        $isDomain = ($nm -like '*\\*') -and ($nm -notlike "$env:COMPUTERNAME\\*") -and ($nm -notlike 'BUILTIN\\*')
        $isGroup  = ($_.ObjectClass -eq 'Group')
        $domain,$account = $null,$null
        if ($nm -like '*\\*'){ $parts = $nm -split '\\',2; $domain=$parts[0]; $account=$parts[1] }
        [pscustomobject]@{
          Name=$nm; SID=$sid; ObjectClass=$_.ObjectClass; PrincipalSource=$_.PrincipalSource;
          IsGroup=$isGroup; IsDomain=$isDomain; IsBuiltIn=($nm -like 'BUILTIN\\*');
          Domain=$domain; Account=$account; IsDomainGroupLikely=($isDomain -and $isGroup); Source='Get-LocalGroupMember'
        }
      }
      return $items
    }
  } catch {}
  try {
    $grp = [ADSI]"WinNT://./Administrators,group"
    $grp.psbase.Invoke('Members') | ForEach-Object {
      $name   = $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)
      $adspath= $_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null)
      $class  = $null
      try { $class = $_.GetType().InvokeMember('Class','GetProperty',$null,$_,$null) } catch {}
      $resolved = $name
      try {
        if ($adspath -and $adspath -like 'WinNT://*/**'){
          $trim = $adspath.Substring(8)
          $resolved = $trim -replace '/','\'
        }
      } catch {}
      $sidVal = $null
      try {
        $nt = New-Object System.Security.Principal.NTAccount($resolved)
        $sidVal = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
      } catch {}
      $domain,$account = $null,$null
      if ($resolved -like '*\\*'){ $parts = $resolved -split '\\',2; $domain=$parts[0]; $account=$parts[1] }
      [pscustomobject]@{
        Name=$resolved; SID=$sidVal; ObjectClass=$class; PrincipalSource='WinNT';
        IsGroup=($class -like '*Group*'); IsDomain=($resolved -like '*\\*') -and ($resolved -notlike "$env:COMPUTERNAME\\*") -and ($resolved -notlike 'BUILTIN\\*');
        IsBuiltIn=($resolved -like 'BUILTIN\\*'); Domain=$domain; Account=$account; IsDomainGroupLikely=(($resolved -like '*\\*') -and ($class -like '*Group*')); Source='ADSI'
      }

    }
  } catch {}
  return $items
}

<#
.SYNOPSIS
    Retrieves ODBC DSN entries from a registry path.

.DESCRIPTION
    Scans the specified registry path for ODBC Data Source Names (DSN) entries.

.PARAMETER regPath
    The registry path to scan (e.g., "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBC.INI").

.PARAMETER scope
    A description of the scope (e.g., "Machine64", "User:SID").

.OUTPUTS
    Array of PSCustomObject with ODBC DSN information.
#>
function Get-OdbcFromRegPath([string]$regPath,[string]$scope){
  $out = @()
  if (Test-Path $regPath){
    $rootKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'ODBC Data Sources' }
    foreach($k in $rootKeys){
      try {
        $p = Get-ItemProperty $k.PSPath -ErrorAction Stop
        $out += [pscustomobject]@{
          Name=$k.PSChildName; Driver=[string]$p.Driver; Server=[string]$p.Server; Database=[string]$p.Database; Trusted=[string]$p.Trusted_Connection; Scope=$scope
        }
      } catch {}
    }
  }
  $out
}

<#
.SYNOPSIS
    Extracts the executable path from a command string.

.DESCRIPTION
    Parses a command string (which may include arguments) and extracts just the
    executable path, handling quoted paths.

.PARAMETER cmd
    The command string to parse.

.OUTPUTS
    The executable path, or $null if not found.
#>
function Get-ExecutableFromCommand([string]$cmd){
  if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
  $s = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($s -match '^\s*"([^"]+)"'){ return $Matches[1] } else { return ($s -split '\s+',2)[0] }
}
#endregion

#region ============================================================================
# MAIN EXECUTION - Initialization
# ============================================================================

# --------------------------------------------------------------------------------
# Logger Setup
# --------------------------------------------------------------------------------
$script:log = New-Logger -LogDirectory $LogRoot
$log = $script:log
$script:log.Write("Starting discovery on $env:COMPUTERNAME (ProfileDays=$ProfileDays, PlantId=$PlantId)")

# --------------------------------------------------------------------------------
# Domain Matcher Setup
# --------------------------------------------------------------------------------
# Create regex patterns for detecting old domain references
if ([string]::IsNullOrWhiteSpace($OldDomainNetBIOS)) { try { $OldDomainNetBIOS = ($OldDomainFqdn -split '.')[0].ToUpperInvariant() } catch { $OldDomainNetBIOS = '' } }
$matchers = New-OldDomainMatchers -netbios $OldDomainNetBIOS -fqdn $OldDomainFqdn
$script:log.Write("Domain tokens -> OldFQDN=$OldDomainFqdn, OldNetBIOS=$OldDomainNetBIOS, NewFQDN=$NewDomainFqdn")

# --------------------------------------------------------------------------------
# Central Share Validation
# --------------------------------------------------------------------------------
<#
.SYNOPSIS
    Validates and tests a central share path for writability.

.DESCRIPTION
    Validates that a UNC path exists and is writable by attempting to create
    and delete a test file. This ensures the script can copy output files to
    the central share.

.PARAMETER Path
    The UNC path to validate.

.PARAMETER Log
    Logger object for writing log messages.

.OUTPUTS
    PSCustomObject with validation results.
#>
function Test-CentralSharePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $result = [pscustomobject]@{
    IsValid = $false
    IsWritable = $false
    ValidatedPath = $null
    ErrorMessage = $null
    ErrorType = $null
  }
  
  # Check if path is provided
  if ([string]::IsNullOrWhiteSpace($Path)) {
    $result.ErrorMessage = "Central share path is empty or null"
    $result.ErrorType = "EmptyPath"
    return $result
  }
  
  $trimmedPath = $Path.Trim()
  
  # Validate UNC path format
  if (-not $trimmedPath.StartsWith('\\')) {
    $result.ErrorMessage = "Central share path must be a valid UNC path (must start with '\\'): $trimmedPath"
    $result.ErrorType = "InvalidFormat"
    if ($Log) { $Log.Write($result.ErrorMessage, 'WARN') }
    return $result
  }
  
  # Check if path exists and is accessible
  try {
    if (-not (Test-Path -LiteralPath $trimmedPath -ErrorAction Stop)) {
      $result.ErrorMessage = "Central share path does not exist or is not accessible: $trimmedPath"
      $result.ErrorType = "PathNotFound"
      if ($Log) { $Log.Write($result.ErrorMessage, 'WARN') }
      return $result
    }
  } catch {
    $result.ErrorMessage = "Error checking central share path '$trimmedPath': $($_.Exception.Message)"
    $result.ErrorType = "PathCheckFailed"
    if ($Log) { $Log.Write($result.ErrorMessage, 'WARN') }
    return $result
  }
  
  # Test writability by creating and deleting a test file
  $testFileName = ".discovery_test_$(Get-Date -Format 'yyyyMMddHHmmss')_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).tmp"
  $testFilePath = Join-Path $trimmedPath $testFileName
  
  try {
    # Attempt to create test file
    $null = New-Item -Path $testFilePath -ItemType File -Force -ErrorAction Stop
    $result.IsWritable = $true
    
    # Attempt to delete test file
    try {
      Remove-Item -Path $testFilePath -Force -ErrorAction Stop
    } catch {
      # Log warning but don't fail validation if we can't delete (file was created successfully)
      if ($Log) { $Log.Write("Warning: Created test file but could not delete it: $testFilePath", 'WARN') }
    }
    
    $result.IsValid = $true
    $result.ValidatedPath = $trimmedPath
    if ($Log) { $Log.Write("Central share path validated successfully: $trimmedPath") }
  } catch {
    $result.ErrorMessage = "Central share path is not writable: $trimmedPath. Error: $($_.Exception.Message)"
    $result.ErrorType = "NotWritable"
    if ($Log) { $Log.Write($result.ErrorMessage, 'WARN') }
  }
  
  return $result
}

# Validate CentralShare if provided
$script:centralShareValidated = $null
if ($CentralShare -and $CentralShare.Trim().Length -gt 0) {
  $script:centralShareValidated = Test-CentralSharePath -Path $CentralShare -Log $script:log
  if (-not $script:centralShareValidated.IsValid) {
    $script:log.Write("Central share validation failed. Script will continue with local discovery only. Error: $($script:centralShareValidated.ErrorMessage)", 'WARN')
    # Clear CentralShare so it won't be used later
    $CentralShare = $null
  }
}
#endregion

#region ============================================================================
# MAIN EXECUTION - Data Collection
# ============================================================================

try {
  # --------------------------------------------------------------------------------
  # System Information
  # --------------------------------------------------------------------------------
  # Collect basic system information: computer system, OS, network adapters
  $system = Safe-Try { Get-CimInstance Win32_ComputerSystem } 'Win32_ComputerSystem'
  $securityAgents = Get-SecurityAgentsTenantInfo -Log $script:log -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn -EncaseRegistryPaths $EncaseRegistryPaths
  $os     = Safe-Try { Get-CimInstance Win32_OperatingSystem } 'Win32_OperatingSystem'
  $netIPv4  = Safe-Try { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue } 'Get-NetIPAddress'
  $adapters = Safe-Try { Get-NetAdapter -ErrorAction SilentlyContinue } 'Get-NetAdapter'
  $ipStr = (@($netIPv4) | Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -Unique) -join ', '
  $macStr = (@($adapters) | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress } | Select-Object -ExpandProperty MacAddress -Unique) -join ', '

  # --------------------------------------------------------------------------------
  # User Profiles (Recent Activity Only)
  # --------------------------------------------------------------------------------
  # Collect user profiles that have been active within the ProfileDays window.
  # Only non-special profiles are included (excludes system profiles).
  # Profiles are used later for per-user registry hive scanning.
  $profiles = @()
  $cutoffDate = (Get-Date).AddDays(-1 * [math]::Abs($ProfileDays))
  $profileCim = Safe-Try { Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue } 'Win32_UserProfile'
  if ($profileCim){
    foreach($p in $profileCim){
      if ([string]::IsNullOrWhiteSpace($p.LocalPath)) { continue }
      if ($p.Special) { continue }
      if ($p.LocalPath -like 'C:\\Windows\\ServiceProfiles\\*' -or $p.LocalPath -like 'C:\\Windows\\System32\\Config\\SystemProfile*') { continue }
      $lut = Convert-LastUseTime $p.LastUseTime
      if ($lut -and $lut -lt $cutoffDate) { continue }
      $profiles += [pscustomobject]@{ SID=$p.SID; LocalPath=$p.LocalPath; LastUseTime=if($lut){$lut.ToString('o')}else{$null}; Special=$p.Special }
    }
  }

  # --------------------------------------------------------------------------------
  # Auto-Admin Logon Configuration
  # --------------------------------------------------------------------------------
  # Check registry for automatic logon settings that may contain domain references.
  # Scans both 64-bit and 32-bit registry views.
  $auto = Safe-Try {
    $views = if ([Environment]::Is64BitOperatingSystem){ @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) } else { @([Microsoft.Win32.RegistryView]::Registry32) }
    foreach($v in $views){
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $v)
      $key = $base.OpenSubKey('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
      if ($null -ne $key){
        $vals = @{ AutoAdminLogon=$key.GetValue('AutoAdminLogon'); ForceAutoLogon=$key.GetValue('ForceAutoLogon'); DefaultUserName=$key.GetValue('DefaultUserName'); DefaultDomainName=$key.GetValue('DefaultDomainName') }
        $enabled = ($vals.AutoAdminLogon -eq '1')
        return     [pscustomobject]@{ Enabled=$enabled; ForceAutoLogon=($vals.ForceAutoLogon -eq '1'); DefaultUserName=[string]$vals.DefaultUserName; DefaultDomainName=[string]$vals.DefaultDomainName }
      }
    }
    [pscustomobject]@{ Enabled=$false }
  } 'AutoAdminLogon'

  # --------------------------------------------------------------------------------
  # Installed Applications
  # --------------------------------------------------------------------------------
  # Collect applications from:
  # - HKLM (machine-level, all users)
  # - Per-user hives (loaded during profile loop)
  # - AppX packages (if IncludeAppx is enabled)
  $apps = @()
  $apps += Safe-Try {
    $view = if ([Environment]::Is64BitOperatingSystem){ [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Registry32 }
    $root64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    Get-UninstallItemsFromHive -root $root64
  } 'Apps HKLM'

  # --------------------------------------------------------------------------------
  # Drive Maps (Per-Profile)
  # --------------------------------------------------------------------------------
  # Initialize drive maps collection (populated during profile loop)
  $driveMaps = @()

  # --------------------------------------------------------------------------------
  # ODBC Data Sources
  # --------------------------------------------------------------------------------
  # Collect ODBC DSN entries from machine-level registry first,
  # then per-user during profile loop
  $odbc = @()
  $odbc += Get-OdbcFromRegPath -regPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBC.INI' -scope 'Machine64'
  $odbc += Get-OdbcFromRegPath -regPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBC.INI' -scope 'Machine32'

  # --------------------------------------------------------------------------------
  # Credential Manager (Per-Profile)
  # --------------------------------------------------------------------------------
  # Initialize credential manager collection (populated during profile loop)
  $credentialManager = @()

  # --------------------------------------------------------------------------------
  # Per-Profile Data Collection Loop
  # --------------------------------------------------------------------------------
  # Combined per-profile loop: load hive once, perform all per-user operations, unload once.
  # This is more efficient than loading/unloading the hive multiple times per profile.
  foreach($prof in $profiles){
    $sid = $prof.SID
    $ntuser = Join-Path $prof.LocalPath 'NTUSER.DAT'
    $loaded = Safe-Try { Load-UserHive -sid $sid -ntuserPath $ntuser } "Load hive $sid"
    try {
      # Apps discovery
      foreach($path in @(
        "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "Registry::HKEY_USERS\$sid\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
      )){
        if (Test-Path $path){
          $subkeys = Get-ChildItem $path -ErrorAction SilentlyContinue
          foreach($sk in $subkeys){
            try {
              $p = Get-ItemProperty $sk.PSPath -ErrorAction Stop
              if ($p.DisplayName){
                $apps += [pscustomobject]@{
                  DisplayName=[string]$p.DisplayName; DisplayVersion=[string]$p.DisplayVersion; Publisher=[string]$p.Publisher;
                  InstallLocation=[string]$p.InstallLocation; KeyPath=$sk.PSPath; Scope="User:$sid"
                }
              }
            } catch {}
          }
        }
      }

      # Drive maps discovery
      $base = "Registry::HKEY_USERS\$sid\Network"
      if (Test-Path $base){
        $letters = Get-ChildItem $base -ErrorAction SilentlyContinue
        foreach($letterKey in $letters){
          $props = Safe-Try { Get-ItemProperty $letterKey.PSPath } "Read drive $($letterKey.PSChildName) for $sid"
          if ($props -and $props.RemotePath){
            $driveMaps += [pscustomobject]@{ SID=$sid; Drive=$letterKey.PSChildName; Remote=[string]$props.RemotePath; Provider=[string]$props.ProviderName; Persistent=$true }
          }
        }
      }

      # ODBC discovery
      $odbc += Get-OdbcFromRegPath -regPath "Registry::HKEY_USERS\$sid\Software\ODBC\ODBC.INI" -scope "User:$sid"

      # Credential Manager discovery
      $credentialManager += Safe-Try {
        Get-CredentialManagerDomainReferences -ProfileSID $sid -DomainMatchers $matchers -Log $script:log
      } "CredentialManager for $sid"
    }
    finally {
      Remove-Variable p,sk,subkeys,letterKey,props -ErrorAction SilentlyContinue
      [gc]::Collect(); [gc]::WaitForPendingFinalizers();
      Safe-Try { Unload-UserHive -sid $sid -didLoad $loaded } "Unload hive $sid" | Out-Null
    }
  }

  # --------------------------------------------------------------------------------
  # Current User Credential Manager
  # --------------------------------------------------------------------------------
  # Check current user's credentials (cmdkey only works for current user context)
  $credentialManager += Safe-Try {
    Get-CredentialManagerDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'CredentialManager current user'

  # Filter out null values from credentialManager array (Safe-Try returns null on error)
  $credentialManager = @($credentialManager | Where-Object { $null -ne $_ })

  # --------------------------------------------------------------------------------
  # Certificates
  # --------------------------------------------------------------------------------
  # Scan certificate stores for old domain references in subject names, issuers, etc.
  $certificates = Safe-Try {
    Get-CertificatesWithDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'Certificates'

  # --------------------------------------------------------------------------------
  # Firewall Rules
  # --------------------------------------------------------------------------------
  # Scan Windows Firewall rules for old domain references in service names, etc.
  $firewallRules = Safe-Try {
    Get-FirewallRulesWithDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'FirewallRules'

  # --------------------------------------------------------------------------------
  # IIS (Web Server)
  # --------------------------------------------------------------------------------
  # Scan IIS sites and application pools for old domain references in bindings, identities, etc.
  $iisConfiguration = Safe-Try {
    Get-IISDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'IIS'

  # --------------------------------------------------------------------------------
  # SQL Server (presence + version always; domain refs when instances exist)
  # --------------------------------------------------------------------------------
  $sqlServerPresence = Safe-Try { Get-SqlServerPresence -Log $script:log } 'SqlServerPresence'
  if (-not $sqlServerPresence) { $sqlServerPresence = [pscustomobject]@{ Installed = $false; Version = $null } }
  $sqlServerConfiguration = Safe-Try {
    Get-SqlDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'SQL Server'

  # --------------------------------------------------------------------------------
  # Event Logs
  # --------------------------------------------------------------------------------
  # Scan Windows event logs for old domain references in event messages.
  # Only scans events from the last EventLogDays days.
  $eventLogDomainReferences = Safe-Try {
    Get-EventLogDomainReferences -DomainMatchers $matchers -DaysBack $EventLogDays -Log $script:log
  } 'EventLogDomainReferences'

  # --------------------------------------------------------------------------------
  # Application Configuration Files
  # --------------------------------------------------------------------------------
  # Scan common application configuration file locations for old domain references.
  # This runs on all systems, not just SQL servers.
  $applicationConfigFiles = Safe-Try {
    Get-ApplicationConfigDomainReferences -DomainMatchers $matchers -Log $script:log
  } 'ApplicationConfigFiles'

  # --------------------------------------------------------------------------------
  # Oracle discovery (server + client indicators)
  # --------------------------------------------------------------------------------
  $oracleDiscovery = Safe-Try {
    Get-OracleDiscovery -Log $script:log
  } 'Oracle'

  # --------------------------------------------------------------------------------
  # RDS/RDP licensing detection (best-effort, non-expensive)
  # --------------------------------------------------------------------------------
  $rdsLicensing = Safe-Try {
    Get-RDSLicensingDiscovery -Log $script:log
  } 'RDSLicensing'

  # --------------------------------------------------------------------------------
  # AppX Packages (Optional)
  # --------------------------------------------------------------------------------
  # Include Windows Store apps if IncludeAppx parameter is enabled
  if ($IncludeAppx){
    $apps += Safe-Try {
      Get-AppxPackage -AllUsers | Select-Object @{n='DisplayName';e={$_.Name}}, @{n='DisplayVersion';e={$_.Version.ToString()}}, @{n='Publisher';e={$_.Publisher}}, @{n='InstallLocation';e={$_.InstallLocation}}, @{n='KeyPath';e={'Appx:' + $_.PackageFullName}}, @{n='Scope';e={'AppxAllUsers'}}
    } 'Appx packages'
  }

  # --------------------------------------------------------------------------------
  # Services & Scheduled Tasks
  # --------------------------------------------------------------------------------
  # Collect Windows services and scheduled tasks information.
  # These are scanned for old domain references in service accounts and task actions.
  $services = Safe-Try { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName } 'Services'
  if (-not $services) { $services = @() }

  $tasks = @()
  $tasks = Safe-Try {
    Get-ScheduledTask | ForEach-Object {
      $t = $_
      $actions = @()
      foreach($a in @($t.Actions | Where-Object { $_ -ne $null })){
        $typeName = if ($a -is [Microsoft.Management.Infrastructure.CimInstance]) { $a.CimClass.CimClassName } else { $a.GetType().Name }
        $p = $a.PSObject.Properties
        $get = { param($n) if ($p[$n]) { $p[$n].Value } else { $null } }
        $exec = & $get 'Execute'; if (-not $exec) { $exec = & $get 'Path' }
        $arguments = & $get 'Arguments'
        $workdir = (& $get 'WorkingDirectory'); if (-not $workdir) { $workdir = & $get 'WorkingDir' }
        if ($exec){
          $actions += [pscustomobject]@{ ActionType='Exec'; Execute=$exec; Arguments=$arguments; WorkingDir=$workdir; Summary=$null; ClassId=$null; Data=$null }
        }
        elseif ($typeName -match 'ComHandler'){
          $actions += [pscustomobject]@{ ActionType='ComHandler'; Execute=$null; Arguments=$null; WorkingDir=$null; ClassId=(& $get 'ClassId'); Data=(& $get 'Data'); Summary=$null }
        }
        else {
          $actions += [pscustomobject]@{ ActionType=$typeName; Execute=$null; Arguments=$null; WorkingDir=$null; Summary=($a | Out-String).Trim(); ClassId=$null; Data=$null }
        }
      }
      [pscustomobject]@{ Path = $t.TaskPath + $t.TaskName; UserId=$t.Principal.UserId; LogonType=[string]$t.Principal.LogonType; RunLevel=[string]$t.Principal.RunLevel; Enabled=$t.Settings.Enabled; Actions=$actions }
    }
  } 'ScheduledTasks'
  if (-not $tasks -or $tasks.Count -eq 0){
    $tasks = Safe-Try {
      $csv = schtasks.exe /Query /FO CSV /V | ConvertFrom-Csv
      $csv | ForEach-Object { [pscustomobject]@{ Path = $_.'TaskName'; UserId = $_.'Run As User'; LogonType = $_.'Logon Mode'; RunLevel = $_.'Run Level'; Enabled = $_.'Scheduled Task State' -eq 'Enabled'; Actions = @([pscustomobject]@{ ActionType='Exec'; Execute=$_."Task To Run"; Arguments=$null; WorkingDir=$null; Summary=$null; ClassId=$null; Data=$null }) } }
    } 'ScheduledTasksFallback'
    if (-not $tasks) { $tasks = @() }
  }

  # --------------------------------------------------------------------------------
  # Local Groups & Administrators
  # --------------------------------------------------------------------------------
  # Collect local group memberships, with special focus on Administrators group.
  $localGroupsToCheck = @('Administrators','Remote Desktop Users','Power Users')
  $localGroupMembers = foreach($g in $localGroupsToCheck){ Get-LocalGroupMembersSafe $g }
  $localAdministrators = Safe-Try { Get-LocalAdministratorsDetailed } 'LocalAdministrators'

  # --------------------------------------------------------------------------------
  # Printers
  # --------------------------------------------------------------------------------
  # Collect installed printer information, including network printers.
  $printers = Safe-Try {
    if (Get-Command Get-Printer -ErrorAction SilentlyContinue){
      Get-Printer | Select-Object Name,DriverName,PortName,ShareName,ComputerName,Type,Location,Comment
    } else {
      Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,ShareName,SystemName,ServerName,Network
    }
  } 'Printers'
  if (-not $printers) { $printers = @() }
#endregion

#region ============================================================================
# MAIN EXECUTION - Domain Reference Detection
# ============================================================================

  # --------------------------------------------------------------------------------
  # Domain Reference Detection
  # --------------------------------------------------------------------------------
  # Scan all collected data for references to the old domain.
  # This section builds the flags object that summarizes all findings.

  # Helper function for domain matching
  function Has-OldDomain([string]$s){ $matchers.Match($s) }

  # --------------------------------------------------------------------------------
  # Services Detection
  # --------------------------------------------------------------------------------
  $log.Write('Detect: starting services')
  # Check services running as old domain accounts
  $servicesRunAsOldDomain = @()
  foreach($svc in @($services)){
    if ($null -eq $svc) { continue }
    if (Has-OldDomain $svc.StartName) { $servicesRunAsOldDomain += $svc.Name }
  }

  # Check service executable paths for old domain references
  $servicesOldPathRefs = @()
  foreach($svc in @($services)){
    if ($null -eq $svc) { continue }
    $exe = Get-ExecutableFromCommand $svc.PathName
    $hay = @($svc.PathName,$exe) -join ' '
    if (Has-OldDomain $hay) { $servicesOldPathRefs += $svc.Name }
  }

  # --------------------------------------------------------------------------------
  # Scheduled Tasks Detection
  # --------------------------------------------------------------------------------
  $log.Write('Detect: starting tasksForDetection')
  $tasksForDetection = @()
  foreach($t in @($tasks)){
    if ($null -eq $t) { continue }
    $isMsTask = Test-IsMicrosoftTaskPath -taskPath $t.Path
    if ($isMsTask) {
      $hasOldRefInActions = $false
      foreach($a in @($t.Actions)){
        if ($null -eq $a) { continue }
        $hay = @($a.Execute,$a.Arguments,$a.WorkingDir) -join ' '
        if (Has-OldDomain $hay) { $hasOldRefInActions = $true; break }
      }
      $hasOldRefInPrincipal = Has-OldDomain $t.UserId
      if ($hasOldRefInActions -or $hasOldRefInPrincipal) { $tasksForDetection += $t }
    } else {
      $tasksForDetection += $t
    }
  }

  $log.Write('Detect: starting tasksWithOldActionRefs')
  $tasksWithOldAccounts   = @()
  $tasksWithOldActionRefs = @()
  foreach($t in @($tasksForDetection)){
    if ($null -eq $t) { continue }
    if (Has-OldDomain $t.UserId) { $tasksWithOldAccounts += $t.Path }
    foreach($a in @($t.Actions)){
      if ($null -eq $a) { continue }
      $hay = @($a.Execute,$a.Arguments,$a.WorkingDir) -join ' '
      if (Has-OldDomain $hay) { $tasksWithOldActionRefs += $t.Path; break }
    }
  }
  $tasksWithOldAccounts   = $tasksWithOldAccounts   | Sort-Object -Unique
  $tasksWithOldActionRefs = $tasksWithOldActionRefs | Sort-Object -Unique

  # --------------------------------------------------------------------------------
  # Printers, ODBC, Local Groups, and Drive Maps Detection
  # --------------------------------------------------------------------------------
  $log.Write('Detect: starting printers/odbc/groups/drives')
  $printersToOldDomain = @()
  foreach($pr in @($printers)){
    if ($null -eq $pr) { continue }
    $vals = @()
    foreach($n in 'ShareName','PortName','ComputerName','SystemName','ServerName'){
      $prop = $pr.PSObject.Properties[$n]
      if ($prop -and $prop.Value){ $vals += [string]$prop.Value }
    }
    $s = ($vals -join ' ')
    if (Has-OldDomain $s) { $printersToOldDomain += $pr.Name }
  }

  $odbcOldDomain = @()
  foreach($d in @($odbc)){
    if ($null -eq $d) { continue }
    if (Has-OldDomain $d.Server) { $odbcOldDomain += $d.Name }
  }

  $localGroupsOldDomainMembers = @()
  foreach($m in @($localGroupMembers)){
    if ($null -eq $m) { continue }
    if (Has-OldDomain $m.Name) { $localGroupsOldDomainMembers += ("{0}: {1}" -f $m.Group,$m.Name) }
  }

  $localAdministratorsOldDomain = @()
  foreach($m in @($localAdministrators)){
    if ($null -eq $m) { continue }
    if (Has-OldDomain $m.Name) { $localAdministratorsOldDomain += $m.Name }
  }

  $driveMapsToOld = @()
  foreach($m in @($driveMaps)){
    if ($null -eq $m) { continue }
    if (Has-OldDomain $m.Remote) { $driveMapsToOld += ("{0}->{1}" -f $m.Drive,$m.Remote) }
  }

  $log.Write('Detect: starting credential manager')
  $credentialManagerOldDomain = @()
  foreach($cm in @($credentialManager)){
    if ($null -eq $cm) { continue }
    if ($cm.HasDomainReference) {
      $entry = if ($cm.Target) { $cm.Target } else { $cm.UserName }
      if ($cm.UserName) { $entry = "{0} ({1})" -f $entry, $cm.UserName }
      $credentialManagerOldDomain += ("{0}: {1}" -f $cm.Profile, $entry)
    }
  }
  $credentialManagerOldDomain = $credentialManagerOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting certificates')
  $certificatesOldDomain = @()
  if ($certificates) {
    foreach($cert in @($certificates)){
      if ($null -eq $cert) { continue }
      if ($cert.HasDomainReference) {
        $certificatesOldDomain += ("{0}: {1} ({2})" -f $cert.Store, $cert.Thumbprint, $cert.MatchedField)
      }
    }
  }
  $certificatesOldDomain = $certificatesOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting firewall rules')
  $firewallRulesOldDomain = @()
  if ($firewallRules) {
    foreach($rule in @($firewallRules)){
      if ($null -eq $rule) { continue }
      if ($rule.HasDomainReference) {
        $firewallRulesOldDomain += ("{0}: {1} ({2})" -f $rule.Name, $rule.DisplayName, $rule.MatchedField)
      }
    }
  }
  $firewallRulesOldDomain = $firewallRulesOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting IIS')
  $iisSitesOldDomain = @()
  $iisAppPoolsOldDomain = @()
  if ($iisConfiguration) {
    # Check sites
    if ($iisConfiguration.Sites) {
      foreach($site in @($iisConfiguration.Sites)){
        if ($null -eq $site) { continue }
        if ($site.HasDomainReference) {
          $matchedFieldsStr = if ($site.MatchedFields) { ($site.MatchedFields -join ', ') } else { 'Unknown' }
          $iisSitesOldDomain += ("{0} ({1})" -f $site.Name, $matchedFieldsStr)
        }
      }
    }
    # Check app pools
    if ($iisConfiguration.AppPools) {
      foreach($pool in @($iisConfiguration.AppPools)){
        if ($null -eq $pool) { continue }
        if ($pool.HasDomainReference) {
          $matchedFieldsStr = if ($pool.MatchedFields) { ($pool.MatchedFields -join ', ') } else { 'Unknown' }
          $iisAppPoolsOldDomain += ("{0} ({1})" -f $pool.Name, $matchedFieldsStr)
        }
      }
    }
  }
  $iisSitesOldDomain = $iisSitesOldDomain | Sort-Object -Unique
  $iisAppPoolsOldDomain = $iisAppPoolsOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting SQL Server')
  $sqlServerOldDomain = @()
  if ($sqlServerConfiguration) {
    foreach($sqlInstance in @($sqlServerConfiguration)){
      if ($null -eq $sqlInstance) { continue }
      
      # Check domain logins
      if ($sqlInstance.DomainLogins -and $sqlInstance.DomainLogins.Count -gt 0) {
        foreach($login in @($sqlInstance.DomainLogins)){
          if ($null -eq $login) { continue }
          $sqlServerOldDomain += ("{0}: Login {1}" -f $sqlInstance.InstanceName, $login.LoginName)
        }
      }
      
      # Check linked servers
      if ($sqlInstance.LinkedServersWithDomainReferences -and $sqlInstance.LinkedServersWithDomainReferences.Count -gt 0) {
        foreach($linkedServer in @($sqlInstance.LinkedServersWithDomainReferences)){
          if ($null -eq $linkedServer) { continue }
          $matchedFieldsStr = if ($linkedServer.MatchedFields) { ($linkedServer.MatchedFields -join ', ') } else { 'Unknown' }
          $sqlServerOldDomain += ("{0}: Linked Server {1} ({2})" -f $sqlInstance.InstanceName, $linkedServer.LinkedServerName, $matchedFieldsStr)
        }
      }
      
      # Check config files
      if ($sqlInstance.ConfigFilesWithDomainReferences -and $sqlInstance.ConfigFilesWithDomainReferences.Count -gt 0) {
        foreach($configFile in @($sqlInstance.ConfigFilesWithDomainReferences)){
          if ($null -eq $configFile) { continue }
          $pathVal = if ($configFile.PSObject.Properties['FilePath']) { $configFile.FilePath } elseif ($configFile.PSObject.Properties['FullName']) { $configFile.FullName } else { [string]$configFile }
          $sqlServerOldDomain += ("{0}: Config File {1}" -f $sqlInstance.InstanceName, $pathVal)
        }
      }
    }
  }
  $sqlServerOldDomain = $sqlServerOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting event logs')
  $eventLogOldDomain = @()
  if ($eventLogDomainReferences) {
    foreach($event in @($eventLogDomainReferences)){
      if ($null -eq $event) { continue }
      $eventLogOldDomain += ("{0}: Event {1} at {2}" -f $event.LogName, $event.Id, $event.TimeCreated)
    }
  }
  $eventLogOldDomain = $eventLogOldDomain | Sort-Object -Unique

  $log.Write('Detect: starting application config files')
  $appConfigOldDomain = @()
  if ($applicationConfigFiles) {
    if ($applicationConfigFiles.FilesWithDomainReferences -and $applicationConfigFiles.FilesWithDomainReferences.Count -gt 0) {
      foreach($configFile in @($applicationConfigFiles.FilesWithDomainReferences)){
        if ($null -eq $configFile) { continue }
        $pathVal = if ($configFile.PSObject.Properties['FilePath']) { $configFile.FilePath } elseif ($configFile.PSObject.Properties['FullName']) { $configFile.FullName } else { [string]$configFile }
        $appConfigOldDomain += ("Config File: {0}" -f $pathVal)
      }
    }
    if ($applicationConfigFiles.FilesWithCredentials -and $applicationConfigFiles.FilesWithCredentials.Count -gt 0) {
      foreach($configFile in @($applicationConfigFiles.FilesWithCredentials)){
        if ($null -eq $configFile) { continue }
        $pathVal = if ($configFile.PSObject.Properties['FilePath']) { $configFile.FilePath } elseif ($configFile.PSObject.Properties['FullName']) { $configFile.FullName } else { [string]$configFile }
        $appConfigOldDomain += ("Config File (Credentials): {0}" -f $pathVal)
      }
    }
  }
  $appConfigOldDomain = $appConfigOldDomain | Sort-Object -Unique

  $taskCombined = @($tasksWithOldAccounts + $tasksWithOldActionRefs) | Sort-Object -Unique

  # --------------------------------------------------------------------------------
  # Build Detection Flags Object
  # --------------------------------------------------------------------------------
  # Consolidate all domain reference findings into a structured flags object
  $flags = [pscustomobject]@{
    ServicesRunAsOldDomain         = @($servicesRunAsOldDomain)
    ServicesOldPathRefs            = @($servicesOldPathRefs)
    ScheduledTasksWithOldAccounts  = @($tasksWithOldAccounts)
    ScheduledTasksWithOldActionRefs= @($tasksWithOldActionRefs)
    DriveMapsToOldDomain           = @($driveMapsToOld)
    LocalGroupsOldDomainMembers    = @($localGroupsOldDomainMembers)
    PrintersToOldDomain            = @($printersToOldDomain)
    OdbcOldDomain                  = @($odbcOldDomain)
    LocalAdministratorsOldDomain   = @($localAdministratorsOldDomain)
    CredentialManagerOldDomain     = @($credentialManagerOldDomain)
    CertificatesOldDomain          = @($certificatesOldDomain)
    FirewallRulesOldDomain         = @($firewallRulesOldDomain)
    IISSitesOldDomain              = @($iisSitesOldDomain)
    IISAppPoolsOldDomain           = @($iisAppPoolsOldDomain)
    SqlServerOldDomain             = @($sqlServerOldDomain)
    EventLogDomainReferences       = @($eventLogOldDomain)
    ApplicationConfigFilesOldDomain = @($appConfigOldDomain)
  }

  # --------------------------------------------------------------------------------
  # Build Summary Object
  # --------------------------------------------------------------------------------
  # Create summary with counts and overall detection status
  # Summary counts (safe)
  function Get-CountSafe { param($x) @(@($x) | Where-Object { $_ -ne $null -and $_ -ne '' } | Sort-Object -Unique).Count }
  $summary = [pscustomobject]@{
    HasOldDomainRefs = ((Get-CountSafe $flags.ServicesRunAsOldDomain) -or (Get-CountSafe $flags.ServicesOldPathRefs) -or (Get-CountSafe $tasksWithOldAccounts) -or (Get-CountSafe $tasksWithOldActionRefs) -or (Get-CountSafe $taskCombined) -or (Get-CountSafe $flags.DriveMapsToOldDomain) -or (Get-CountSafe $flags.LocalGroupsOldDomainMembers) -or (Get-CountSafe $flags.PrintersToOldDomain) -or (Get-CountSafe $flags.OdbcOldDomain) -or (Get-CountSafe $flags.LocalAdministratorsOldDomain) -or (Get-CountSafe $flags.CredentialManagerOldDomain) -or (Get-CountSafe $flags.CertificatesOldDomain) -or (Get-CountSafe $flags.FirewallRulesOldDomain) -or (Get-CountSafe $flags.IISSitesOldDomain) -or (Get-CountSafe $flags.IISAppPoolsOldDomain) -or (Get-CountSafe $flags.SqlServerOldDomain) -or (Get-CountSafe $flags.EventLogDomainReferences) -or (Get-CountSafe $flags.ApplicationConfigFilesOldDomain))
    Counts = [pscustomobject]@{
      Services       = (Get-CountSafe $flags.ServicesRunAsOldDomain)
      ServicesPath   = (Get-CountSafe $flags.ServicesOldPathRefs)
      TaskPrincipals = (Get-CountSafe $flags.ScheduledTasksWithOldAccounts)
      TaskActions    = (Get-CountSafe $flags.ScheduledTasksWithOldActionRefs)
      Tasks          = (Get-CountSafe $taskCombined)
      DriveMaps      = (Get-CountSafe $flags.DriveMapsToOldDomain)
      LocalGroups    = (Get-CountSafe $flags.LocalGroupsOldDomainMembers)
      Printers       = (Get-CountSafe $flags.PrintersToOldDomain)
      ODBC           = (Get-CountSafe $flags.OdbcOldDomain)
      LocalAdmins    = (Get-CountSafe $flags.LocalAdministratorsOldDomain)
      CredentialManager = (Get-CountSafe $flags.CredentialManagerOldDomain)
      Certificates   = (Get-CountSafe $flags.CertificatesOldDomain)
      FirewallRules  = (Get-CountSafe $flags.FirewallRulesOldDomain)
      IISSites       = (Get-CountSafe $flags.IISSitesOldDomain)
      IISAppPools    = (Get-CountSafe $flags.IISAppPoolsOldDomain)
      SqlServer      = (Get-CountSafe $flags.SqlServerOldDomain)
      EventLogs      = (Get-CountSafe $flags.EventLogDomainReferences)
      ApplicationConfigFiles = (Get-CountSafe $flags.ApplicationConfigFilesOldDomain)
    }
  }
#endregion

#region ============================================================================
# MAIN EXECUTION - Data Filtering (Slim Mode)
# ============================================================================

  # --------------------------------------------------------------------------------
  # Slim / Noise-Filtered View
  # --------------------------------------------------------------------------------
  # Filter out Microsoft-built-in applications and services for cleaner output.
  # The filtered data is used when SlimOutputOnly is enabled, but the JSON structure remains identical.
  
  # --------------------------------------------------------------------------------
  # Installed Applications Filtering
  # --------------------------------------------------------------------------------
  # Define patterns for Microsoft apps to exclude
  $msAppNoiseNamePatterns = @(
    '^Microsoft Visual C\+\+','^Microsoft \.(NET|Windows Desktop Runtime)',
    '^Update for Windows','^Windows (SDK|Driver|Feature|Media Player|Maps)',
    '^Office 16 Click-to-Run Extensibility Component$'
  )
  # Add optional exclusions based on user preferences
  if (-not $KeepEdgeOneDrive) { $msAppNoiseNamePatterns += @('^Microsoft Edge( WebView2 Runtime)?$','^Microsoft OneDrive$') }
  if (-not $KeepMsStoreApps)  { $msAppNoiseNamePatterns += @('^App Installer$','^Microsoft Store$') }
  if (-not $KeepOffice)       { $msAppNoiseNamePatterns += @('^Microsoft 365 Apps','^Microsoft Project','^Microsoft Visio') }

  <#
  .SYNOPSIS
      Tests if an application should be filtered out as Microsoft noise.

  .DESCRIPTION
      Determines if an application is a Microsoft-built-in application that should
      be filtered out in slim mode based on publisher, location, and name patterns.

  .PARAMETER app
      The application object to test.

  .OUTPUTS
      Boolean indicating if the app should be filtered out.
  #>
  function Test-IsMicrosoftAppNoise($app) {
    if (-not $app) { return $false }
    $pub = [string]$app.Publisher
    $dn  = [string]$app.DisplayName
    $loc = [string]$app.InstallLocation
    $isMsPublisher = ($pub -match '(?i)^Microsoft')
    $isWindowsLoc  = ($loc -match '(?i)^C:\\Windows\\|^%windir%') -or ($loc -match '(?i)\\WindowsApps\\')
    $nameIsNoise   = $false
    foreach ($rx in $msAppNoiseNamePatterns) { if ($dn -match $rx) { $nameIsNoise = $true; break } }
    return ($isMsPublisher -and ($isWindowsLoc -or $nameIsNoise))
  }

#endregion

#region ============================================================================
# MAIN EXECUTION - Data Filtering (Slim Mode)
# ============================================================================

  # --------------------------------------------------------------------------------
  # Slim / Noise-Filtered View
  # --------------------------------------------------------------------------------
  # Filter out Microsoft-built-in applications and services for cleaner output.
  # The filtered data is used when SlimOutputOnly is enabled, but the JSON structure remains identical.
  
  # --------------------------------------------------------------------------------
  # Installed Applications Filtering
  # --------------------------------------------------------------------------------
  # Define patterns for Microsoft apps to exclude
  $msAppNoiseNamePatterns = @(
    '^Microsoft Visual C\+\+','^Microsoft \.(NET|Windows Desktop Runtime)',
    '^Update for Windows','^Windows (SDK|Driver|Feature|Media Player|Maps)',
    '^Office 16 Click-to-Run Extensibility Component$'
  )
  # Add optional exclusions based on user preferences
  if (-not $KeepEdgeOneDrive) { $msAppNoiseNamePatterns += @('^Microsoft Edge( WebView2 Runtime)?$','^Microsoft OneDrive$') }
  if (-not $KeepMsStoreApps)  { $msAppNoiseNamePatterns += @('^App Installer$','^Microsoft Store$') }
  if (-not $KeepOffice)       { $msAppNoiseNamePatterns += @('^Microsoft 365 Apps','^Microsoft Project','^Microsoft Visio') }

  <#
  .SYNOPSIS
      Tests if an application should be filtered out as Microsoft noise.

  .DESCRIPTION
      Determines if an application is a Microsoft-built-in application that should
      be filtered out in slim mode based on publisher, location, and name patterns.

  .PARAMETER app
      The application object to test.

  .OUTPUTS
      Boolean indicating if the app should be filtered out.
  #>
  function Test-IsMicrosoftAppNoise($app) {
    if (-not $app) { return $false }
    $pub = [string]$app.Publisher
    $dn  = [string]$app.DisplayName
    $loc = [string]$app.InstallLocation
    $isMsPublisher = ($pub -match '(?i)^Microsoft')
    $isWindowsLoc  = ($loc -match '(?i)^C:\\Windows\\|^%windir%') -or ($loc -match '(?i)\\WindowsApps\\')
    $nameIsNoise   = $false
    foreach ($rx in $msAppNoiseNamePatterns) { if ($dn -match $rx) { $nameIsNoise = $true; break } }
    return ($isMsPublisher -and ($isWindowsLoc -or $nameIsNoise))
  }

  $appsFiltered = @()
  foreach ($a in @($apps)) {
    $isNoise = Test-IsMicrosoftAppNoise $a
    if (-not $isNoise) { $appsFiltered += $a; continue }
    if ($KeepOffice -and ($a.DisplayName -match '(?i)Microsoft (365|Office|Project|Visio)')) { $appsFiltered += $a; continue }
    if ($KeepEdgeOneDrive -and ($a.DisplayName -match '(?i)Microsoft (Edge|WebView2|OneDrive)')) { $appsFiltered += $a; continue }
  }

  # --------------------------------------------------------------------------------
  # Services Filtering
  # --------------------------------------------------------------------------------
  $servicesToKeepByName = @{}
  foreach ($n in @($flags.ServicesRunAsOldDomain + $flags.ServicesOldPathRefs)) { if ($n) { $servicesToKeepByName[$n] = $true } }

  $servicesFiltered = @()
  foreach ($svc in @($services)) {
    if ($null -eq $svc) { continue }
    if ($SlimOnlyRunningServices -and ($svc.State -ne 'Running' -or $svc.StartMode -eq 'Disabled')) { continue }
    if ($servicesToKeepByName.ContainsKey($svc.Name)) { $servicesFiltered += $svc; continue }
    $isMsBin = Test-IsMicrosoftBinary $svc.PathName
    $isWinPath = ([string]$svc.PathName) -match '(?i)^\s*"?C:\\Windows\\'
    if ($isMsBin -and $isWinPath) { continue }
    $servicesFiltered += $svc
  }

  # --------------------------------------------------------------------------------
  # Scheduled Tasks Filtering
  # --------------------------------------------------------------------------------
  # Drop \Microsoft\... tasks, and root Edge/OneDrive unless opted-in; keep detection-flagged tasks
  $taskKeepSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($p in @($flags.ScheduledTasksWithOldAccounts + $flags.ScheduledTasksWithOldActionRefs)) { if ($p) { [void]$taskKeepSet.Add($p) } }

  $tasksFiltered = @()
  foreach ($t in @($tasks)) {
    if ($null -eq $t) { continue }
    $isMsTask         = Test-IsMicrosoftTaskPath -taskPath $t.Path
    $isFlagged        = $taskKeepSet.Contains($t.Path)
    $isEdgeOrOneDrive = ($t.Path -match '(?i)^\\+(MicrosoftEdgeUpdate|OneDrive)')
    if ($isFlagged) { $tasksFiltered += $t; continue }
    if ($isMsTask) { continue }
    if (-not $KeepEdgeOneDrive -and $isEdgeOrOneDrive) { continue }
    $tasksFiltered += $t
  }

  # --------------------------------------------------------------------------------
  # Printers Filtering
  # --------------------------------------------------------------------------------
  $printerNoiseDrivers = '(?i)(Microsoft XPS Document Writer|Microsoft Print To PDF|Send to Microsoft OneNote|Fax)'
  $printersFiltered = @()
  foreach ($pr in @($printers)) {
    if ($null -eq $pr) { continue }
    $isVirtual = ([string]$pr.DriverName) -match $printerNoiseDrivers
    $isNetwork = ([string]$pr.PortName) -match '^(\\\\|TCP|IP_)'
    if (-not $isVirtual -or $isNetwork) { $printersFiltered += $pr }
  }

  # --------------------------------------------------------------------------------
  # Slim Counts Summary
  # --------------------------------------------------------------------------------
  # Track counts of filtered items for reporting
  $SlimCounts = [pscustomobject]@{
    Apps     = @($appsFiltered).Count
    Services = @($servicesFiltered).Count
    Tasks    = @($tasksFiltered).Count
    Printers = @($printersFiltered).Count
  }
#endregion

#region ============================================================================
# MAIN EXECUTION - Additional Data Collection (After Main Loop)
# ============================================================================

  # --------------------------------------------------------------------------------
  # Shared Folders and DNS Configuration
  # --------------------------------------------------------------------------------
  # Collect shared folders with ACLs and DNS configuration after main data collection

<#
.SYNOPSIS
    Retrieves the Group Policy Machine Distinguished Name.

.DESCRIPTION
    Reads the GPO machine DN from the registry, which indicates which OU the
    computer is in within Active Directory.

.OUTPUTS
    The Distinguished Name string, or $null if not found.
#>
function Get-GPOMachineDN {
    $regPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine'
    $valueName = 'Distinguished-Name'
    $dn = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        $key = $base.OpenSubKey($regPath)
        if ($key -ne $null) {
            $dn = $key.GetValue($valueName)
        }
    } catch {}
    return $dn
}

<#
.SYNOPSIS
    Retrieves shared folders with their ACL information.

.DESCRIPTION
    Enumerates Windows file shares and attempts to read their ACLs to identify
    domain references in permissions.

.PARAMETER Log
    Logger object for writing log messages.

.OUTPUTS
    PSCustomObject with Shares and Errors arrays.
#>
function Get-SharedFoldersWithACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        $Log
    )
    
    $results = @()
    $errors = @()
    
    try {
        $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | Where-Object { $_.Type -eq 0 }
    } catch {
        $errorMsg = "Failed to enumerate shares: $($_.Exception.Message)"
        if ($Log) { $Log.Write($errorMsg, 'WARN') }
        $errors += [pscustomobject]@{
            ShareName = $null
            FolderPath = $null
            ErrorType = 'EnumerationFailed'
            ErrorMessage = $errorMsg
            ErrorDetails = $_.Exception.GetType().FullName
        }
        return [pscustomobject]@{
            Shares = $results
            Errors = $errors
        }
    }
    
    foreach ($share in $shares) {
        if ($null -eq $share) { continue }
        
        $shareName = $share.Name
        $path = $share.Path
        
        # Check if path exists
        if ([string]::IsNullOrWhiteSpace($path)) {
            $errorMsg = "Share path is empty for share: $shareName"
            if ($Log) { $Log.Write($errorMsg, 'WARN') }
            $errors += [pscustomobject]@{
                ShareName = $shareName
                FolderPath = $null
                ErrorType = 'PathEmpty'
                ErrorMessage = $errorMsg
                ErrorDetails = $null
            }
            continue
        }
        
        # Check if path exists on filesystem
        if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $errorMsg = "Share path does not exist: $path"
            if ($Log) { $Log.Write("Share '$shareName': $errorMsg", 'WARN') }
            $errors += [pscustomobject]@{
                ShareName = $shareName
                FolderPath = $path
                ErrorType = 'PathNotFound'
                ErrorMessage = $errorMsg
                ErrorDetails = $null
            }
            continue
        }
        
        # Attempt to read ACL
        try {
            $acl = Get-Acl -Path $path -ErrorAction Stop
            $hasAces = $false
            foreach ($ace in $acl.Access) {
                $hasAces = $true
                $results += [pscustomobject]@{
                    ShareName    = $shareName
                    FolderPath   = $path
                    Identity     = $ace.IdentityReference
                    AccessControl= $ace.FileSystemRights
                    AccessType   = $ace.AccessControlType
                    Inheritance  = $ace.IsInherited
                }
            }
            if (-not $hasAces) {
                # Path exists but has no ACEs (unusual but valid)
                if ($Log) { $Log.Write("Share '$shareName': Path exists but contains no access control entries", 'INFO') }
            }
        } catch [System.UnauthorizedAccessException] {
            $errorMsg = "Access denied when reading ACL for share: $shareName"
            if ($Log) { $Log.Write("Share '$shareName': $errorMsg - Path: $path", 'WARN') }
            $errors += [pscustomobject]@{
                ShareName = $shareName
                FolderPath = $path
                ErrorType = 'AccessDenied'
                ErrorMessage = $errorMsg
                ErrorDetails = $_.Exception.GetType().FullName
            }
        } catch [System.Management.Automation.ItemNotFoundException] {
            $errorMsg = "Share path not found (may have been deleted): $path"
            if ($Log) { $Log.Write("Share '$shareName': $errorMsg", 'WARN') }
            $errors += [pscustomobject]@{
                ShareName = $shareName
                FolderPath = $path
                ErrorType = 'PathNotFound'
                ErrorMessage = $errorMsg
                ErrorDetails = $_.Exception.GetType().FullName
            }
        } catch {
            $errorMsg = "Unexpected error reading ACL for share: $shareName"
            if ($Log) { $Log.Write("Share '$shareName': $errorMsg - $($_.Exception.Message)", 'WARN') }
            $errors += [pscustomobject]@{
                ShareName = $shareName
                FolderPath = $path
                ErrorType = 'UnexpectedError'
                ErrorMessage = "$errorMsg - $($_.Exception.Message)"
                ErrorDetails = $_.Exception.GetType().FullName
            }
        }
    }
    
    return [pscustomobject]@{
        Shares = $results
        Errors = $errors
    }
}

  $gpoDN = Safe-Try { Get-GPOMachineDN } 'Get-GPOMachineDN'
  $sharedFoldersResult = Safe-Try { Get-SharedFoldersWithACL -Log $script:log } 'Get-SharedFoldersWithACL'
  # Extract shares and errors from the result (handle both old format and new format for backwards compatibility)
  if ($sharedFoldersResult -and $sharedFoldersResult.PSObject.Properties['Shares']) {
    $sharedFolders = $sharedFoldersResult.Shares
    $sharedFoldersErrors = $sharedFoldersResult.Errors
  } else {
    # Fallback for old format (if Safe-Try returns null or old structure)
    $sharedFolders = if ($sharedFoldersResult) { $sharedFoldersResult } else { @() }
    $sharedFoldersErrors = @()
  }
  $dnsConfiguration = Safe-Try { Get-DnsConfigurationForMigration -DomainMatchers $matchers -Log $script:log } 'Get-DnsConfigurationForMigration'
#endregion

#region ============================================================================
# MAIN EXECUTION - Output Generation
# ============================================================================

  # --------------------------------------------------------------------------------
  # Build Result Object
  # --------------------------------------------------------------------------------
  # Assemble all collected data into the final JSON structure
  $metadata = [pscustomobject]@{
    GpoMachineDN = $gpoDN
    ComputerName      = $env:COMPUTERNAME
    CollectedAt       = (Get-Date).ToString('o')
    UserContext       = $env:USERNAME
    Domain            = $system.Domain
    OldDomainFqdn     = $OldDomainFqdn
    OldDomainNetBIOS  = $OldDomainNetBIOS
    NewDomainFqdn     = $NewDomainFqdn
    ProfileDays       = $ProfileDays
    PlantId           = $PlantId
    Version           = $ScriptVersion
  }

  $sysInfo = [pscustomobject]@{
    Hostname     = $env:COMPUTERNAME
    Manufacturer = $system.Manufacturer
    Model        = $system.Model
    OSVersion    = if ($os) { "$( $os.Caption) $( $os.Version) (Build $( $os.BuildNumber))" } else { $null }
    IPAddress    = $ipStr
    MACAddress   = $macStr
    LoggedInUser = $system.UserName
  }

  # Determine which data to use based on SlimOutputOnly setting
  # When SlimOutputOnly is true, use filtered data; otherwise use full data
  # This ensures the JSON structure is identical regardless of the setting
  $installedAppsData = if ($SlimOutputOnly) { $appsFiltered } else { (@($apps) | Sort-Object DisplayName,DisplayVersion -Unique) }
  $servicesData = if ($SlimOutputOnly) { $servicesFiltered } else { $services }
  $scheduledTasksData = if ($SlimOutputOnly) { $tasksFiltered } else { $tasks }
  $printersData = if ($SlimOutputOnly) { $printersFiltered } else { $printers }

  # Build consistent JSON structure regardless of SlimOutputOnly setting
  # Properties that are only available in full mode are set to $null in slim mode
  $result = [pscustomobject]@{
    Metadata = $metadata
    System   = $sysInfo
    Profiles = if ($SlimOutputOnly) { $null } else { $profiles }
    SharedFolders = [pscustomobject]@{
      Shares = $sharedFolders
      Errors = $sharedFoldersErrors
    }
    InstalledApps  = $installedAppsData
    Services       = $servicesData
    ScheduledTasks = $scheduledTasksData
    LocalGroupMembers    = if ($SlimOutputOnly) { $null } else { $localGroupMembers }
    LocalAdministrators  = if ($SlimOutputOnly) { $null } else { $localAdministrators }
    MappedDrives  = if ($SlimOutputOnly) { $null } else { $driveMaps }
    Printers      = $printersData
    OdbcDsn       = if ($SlimOutputOnly) { $null } else { $odbc }
    AutoAdminLogon= if ($SlimOutputOnly) { $null } else { $auto }
    CredentialManager = $credentialManager
    Certificates = $certificates
    FirewallRules = $firewallRules
    DnsConfiguration = $dnsConfiguration
    IIS = $iisConfiguration
    SqlServerInstalled = $sqlServerPresence.Installed
    SqlServerVersion   = $sqlServerPresence.Version
    SqlServer = $sqlServerConfiguration
    EventLogDomainReferences = $eventLogDomainReferences
    ApplicationConfigFiles = $applicationConfigFiles
    Oracle = if ($oracleDiscovery) { $oracleDiscovery } else { [pscustomobject]@{ OracleInstalled = $false; OracleVersion = $null; IsOracleServerLikely = $false; OracleServices = @(); OracleHomes = @(); OracleClientInstalled = $false; OracleODBCDrivers = @(); TnsnamesFiles = @(); SqlNetConfigPaths = @(); Errors = @('Discovery not run or failed') } }
    RDSLicensing = if ($rdsLicensing) { $rdsLicensing } else { [pscustomobject]@{ IsRDSSessionHost = $false; RDSRoleInstalled = $null; RdsLicensingRoleInstalled = $false; LicensingMode = 'Unknown'; LicenseServerConfigured = @(); RDSLicensingEvidence = @(); IsRDSLicensingLikelyInUse = $false; Errors = @('Discovery not run or failed') } }
    SecurityAgents = $securityAgents
    Detection     = [pscustomobject]@{ OldDomain = $flags; Summary = $summary }
  }

  # --------------------------------------------------------------------------------
  # Write Output Files
  # --------------------------------------------------------------------------------
  Ensure-Directory $OutputRoot
  $fname = ('{0}_{1}.json' -f $env:COMPUTERNAME, (Get-Date).ToString('MM-dd-yyyy'))
  $localPath = Join-Path $OutputRoot $fname
  try {
    # Convert to JSON with proper depth and error handling
    # Use depth 10 to ensure deeply nested structures (e.g., Detection.OldDomain, IIS.Sites.Bindings) are fully serialized
    $json = $null
    $jsonConversionError = $null
    try {
      # Determine compatibility mode if not already set
      if (-not $script:CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
          $script:CompatibilityMode = 'Full'
        } else {
          $script:CompatibilityMode = 'Legacy3to4'
        }
      }
      
      if ($script:CompatibilityMode -eq 'Full') {
        $json = $result | ConvertTo-Json -Depth 10 -ErrorAction Stop
      } else {
        # Legacy path for PS 3.0–4.0 (-Depth parameter available but may have limitations)
        try {
          $json = $result | ConvertTo-Json -Depth 10 -ErrorAction Stop
        } catch {
          if ($script:log) { $script:log.Write("ConvertTo-Json -Depth failed, using default depth: $($_.Exception.Message)", 'WARN') }
          $json = $result | ConvertTo-Json -ErrorAction Stop
        }
      }
      
      # Validate JSON is not empty
      if ([string]::IsNullOrWhiteSpace($json)) {
        throw "JSON conversion resulted in empty string"
      }
      
      # Validate JSON can be parsed (ensures valid JSON format for Power BI)
      try {
        $null = $json | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "Generated JSON is not valid JSON format: $($_.Exception.Message)"
      }
    } catch {
      $jsonConversionError = $_.Exception.Message
      $script:log.Write("JSON conversion failed: $jsonConversionError", 'ERROR')
      throw
    }
    
    # Write JSON to file with UTF-8 encoding (no BOM for Power BI compatibility)
    try {
      # Determine compatibility mode if not already set
      if (-not $script:CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
          $script:CompatibilityMode = 'Full'
        } else {
          $script:CompatibilityMode = 'Legacy3to4'
        }
      }
      
      if ($script:CompatibilityMode -eq 'Full') {
        # Use UTF8NoBOM encoding for Power BI compatibility
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($localPath, $json, $utf8NoBom)
      } else {
        # Legacy path for PS 3.0–4.0
        [System.IO.File]::WriteAllText($localPath, $json, [System.Text.Encoding]::UTF8)
      }
      $script:log.Write("Wrote JSON locally: $localPath")
    } catch {
      $script:log.Write("Failed to write JSON file: $($_.Exception.Message)", 'ERROR')
      throw
    }
  } catch {
    # If JSON conversion or file write fails, generate error JSON instead
    $errorMessage = if ($jsonConversionError) { "JSON conversion failed: $jsonConversionError" } else { "Failed to write JSON file: $($_.Exception.Message)" }
    $script:log.Write("Fatal error during JSON output: $errorMessage", 'ERROR')
    
    # Generate error JSON structure (reuse the error generation logic from catch block)
    $hostname = $env:COMPUTERNAME
    $domain = $null
    try {
      # Determine compatibility mode if not already set
      if (-not $script:CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
          $script:CompatibilityMode = 'Full'
        } else {
          $script:CompatibilityMode = 'Legacy3to4'
        }
      }
      
      if ($script:CompatibilityMode -eq 'Full') {
        $systemInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
      } else {
        $systemInfo = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
      }
      if ($systemInfo) {
        $domain = $systemInfo.Domain
      }
    } catch {
      # Ignore errors getting system info
    }
    
    $errorResult = [pscustomobject]@{
      Schema = $null
      Metadata = [pscustomobject]@{
        GpoMachineDN = $null
        ComputerName = $hostname
        CollectedAt = (Get-Date).ToString('o')
        UserContext = $env:USERNAME
        Domain = $domain
        OldDomainFqdn = if ($OldDomainFqdn) { $OldDomainFqdn } else { $null }
        OldDomainNetBIOS = if ($OldDomainNetBIOS) { $OldDomainNetBIOS } else { $null }
        NewDomainFqdn = if ($NewDomainFqdn) { $NewDomainFqdn } else { $null }
        ProfileDays = if ($ProfileDays) { $ProfileDays } else { $null }
        PlantId = if ($PlantId) { $PlantId } else { $null }
        Version = $ScriptVersion
      }
      System = [pscustomobject]@{
        Hostname = $hostname
        Manufacturer = $null
        Model = $null
        OSVersion = $null
        IPAddress = $null
        MACAddress = $null
        LoggedInUser = $null
      }
      Profiles = @()
      SharedFolders = [pscustomobject]@{ Shares = @(); Errors = @() }
      InstalledApps = @()
      Services = @()
      ScheduledTasks = @()
      LocalGroupMembers = @()
      LocalAdministrators = @()
      LocalAccounts = [pscustomobject]@{ Users = @(); Groups = @() }
      MappedDrives = @()
      Printers = @()
      OdbcDsn = @()
      AutoAdminLogon = $null
      CredentialManager = @()
      Certificates = @()
      Endpoints = @()
      FirewallRules = @()
      DnsConfiguration = $null
      IIS = $null
      SqlServer = $null
      EventLogDomainReferences = @()
      ApplicationConfigFiles = [pscustomobject]@{ FilesWithDomainReferences = @(); FilesWithCredentials = @() }
      SqlServerInstalled = $false
      SqlServerVersion   = $null
      Oracle = [pscustomobject]@{ OracleInstalled = $false; OracleVersion = $null; IsOracleServerLikely = $false; OracleServices = @(); OracleHomes = @(); OracleClientInstalled = $false; OracleODBCDrivers = @(); TnsnamesFiles = @(); SqlNetConfigPaths = @(); Errors = $null }
      RDSLicensing = [pscustomobject]@{ IsRDSSessionHost = $false; RDSRoleInstalled = $null; RdsLicensingRoleInstalled = $false; LicensingMode = 'Unknown'; LicenseServerConfigured = @(); RDSLicensingEvidence = @(); IsRDSLicensingLikelyInUse = $false; Errors = $null }
      SecurityAgents = [pscustomobject]@{
        CrowdStrike = [pscustomobject]@{ Tenant = $null; TenantId = $null; HasDomainReference = $false }
        Qualys = [pscustomobject]@{ Tenant = $null; TenantId = $null; HasDomainReference = $false }
        SCCM = [pscustomobject]@{ Tenant = $null; Found = $false; FoundDomains = @(); HasDomainReference = $false }
      }
      QuestConfig = @()
      References = [pscustomobject]@{ OldDomain = @(); ScriptAutomation = @() }
      AppSpecific = $null
      DatabaseConnections = @()
      ServerSummary = [pscustomobject]@{ FileServers = @(); PrintServers = @() }
      Detection = [pscustomobject]@{
        OldDomain = @{}
        Summary = [pscustomobject]@{
          HasOldDomainRefs = $false
          Counts = [pscustomobject]@{
            Services = 0; ServicesPath = 0; TaskPrincipals = 0; TaskActions = 0; Tasks = 0
            DriveMaps = 0; LocalGroups = 0; Printers = 0; ODBC = 0; LocalAdmins = 0
            CredentialManager = 0; Certificates = 0; CertificateEndpoints = 0; FirewallRules = 0
            IISSites = 0; IISAppPools = 0; SqlServer = 0; EventLogs = 0; ApplicationConfigFiles = 0
            HardCodedReferences = 0; ScriptAutomation = 0; DatabaseConnections = 0; AppSpecific = 0
            FileServers = 0; PrintServers = 0
          }
        }
      }
      Error = [pscustomobject]@{
        HasError = $true
        ErrorMessage = $errorMessage
        ErrorType = "JSON_OUTPUT_ERROR"
        ErrorStackTrace = $null
        InnerException = $null
        Timestamp = (Get-Date).ToString('o')
      }
    }
    
    try {
      # Determine compatibility mode if not already set
      if (-not $script:CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
          $script:CompatibilityMode = 'Full'
        } else {
          $script:CompatibilityMode = 'Legacy3to4'
        }
      }
      
      if ($script:CompatibilityMode -eq 'Full') {
        $errorJson = $errorResult | ConvertTo-Json -Depth 10
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($localPath, $errorJson, $utf8NoBom)
      } else {
        try {
          $errorJson = $errorResult | ConvertTo-Json -Depth 10
        } catch {
          $errorJson = $errorResult | ConvertTo-Json
        }
        [System.IO.File]::WriteAllText($localPath, $errorJson, [System.Text.Encoding]::UTF8)
      }
      $script:log.Write("Wrote error JSON to: $localPath")
    } catch {
      $script:log.Write("Failed to write error JSON: $($_.Exception.Message)", 'ERROR')
      throw
    }
    
    throw
  }

  if ($EmitStdOut){
    [pscustomobject]@{
      Computer          = $env:COMPUTERNAME
      PlantId           = $PlantId
      HasOldRefs        = $summary.HasOldDomainRefs
      CrowdStrikeTenant = $securityAgents.CrowdStrike.Tenant
      QualysTenant      = $securityAgents.Qualys.Tenant
      SCCMTenant        = $securityAgents.SCCM.Tenant
      CountServices     = $summary.Counts.Services
      CountServicesPath = $summary.Counts.ServicesPath
      CountTaskPrincipals = $summary.Counts.TaskPrincipals
      CountTaskActions    = $summary.Counts.TaskActions
      CountTasks          = $summary.Counts.Tasks
      CountDrives         = $summary.Counts.DriveMaps
      CountLocalGr        = $summary.Counts.LocalGroups
      CountPrinters       = $summary.Counts.Printers
      CountODBC           = $summary.Counts.ODBC
      CountLocalAdm       = $summary.Counts.LocalAdmins
      CountCredentialMgr  = $summary.Counts.CredentialManager
      CountCertificates   = $summary.Counts.Certificates
      CountFirewallRules  = $summary.Counts.FirewallRules
      CountIISSites       = $summary.Counts.IISSites
      CountIISAppPools    = $summary.Counts.IISAppPools
      CountSqlServer      = $summary.Counts.SqlServer
      CountEventLogs      = $summary.Counts.EventLogs
      CountApplicationConfigFiles = $summary.Counts.ApplicationConfigFiles
      SlimApps            = $SlimCounts.Apps
      SlimServices        = $SlimCounts.Services
      SlimTasks           = $SlimCounts.Tasks
      SlimPrinters        = $SlimCounts.Printers
      CollectedAt         = (Get-Date).ToString('o')
      Version             = $ScriptVersion
    } | ConvertTo-Json -Compress | Write-Output
  }

  # Use validated CentralShare if available
  if ($script:centralShareValidated -and $script:centralShareValidated.IsValid -and $script:centralShareValidated.IsWritable -and $script:centralShareValidated.ValidatedPath) {
    try {
      $validatedPath = $script:centralShareValidated.ValidatedPath
      $targetDir = Join-Path $validatedPath 'workstations'
      Ensure-Directory $targetDir
      $dest = Join-Path $targetDir $fname
      Copy-Item -Path $localPath -Destination $dest -Force
      $script:log.Write("Copied JSON to central share: $dest")
    } catch {
      $script:log.Write("Central copy failed: $($_.Exception.Message)", 'WARN')
    }
  } elseif ($script:centralShareValidated -and -not $script:centralShareValidated.IsValid) {
    # Log the validation failure reason
    $script:log.Write("Skipping central share copy due to validation failure: $($script:centralShareValidated.ErrorMessage)", 'WARN')
  }

  $script:log.Write("Discovery completed successfully.")
  exit 0
}
catch {
  $errorMessage = $_.Exception.Message
  $errorStackTrace = if ($_.ScriptStackTrace) { $_.ScriptStackTrace } else { $null }
  $errorInnerException = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $null }
  
  # Log full technical details to log file
  if ($script:log) {
    $script:log.Write("Fatal error: $errorMessage", 'ERROR')
    if ($errorStackTrace) {
      $script:log.Write("Stack trace: $errorStackTrace", 'ERROR')
    }
    if ($errorInnerException) {
      $script:log.Write("Inner exception: $errorInnerException", 'ERROR')
    }
  }
  
  # Show human-readable error on console
  $humanError = Get-HumanReadableError -ErrorMessage $_.Exception -Context "running discovery"
  Write-Error $humanError
  
  # Generate valid JSON error structure for PowerBI reporting
  try {
    # Get basic system info for error JSON
    $hostname = $env:COMPUTERNAME
    $domain = $null
    try {
      # Determine compatibility mode if not already set
      if (-not $script:CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
          $script:CompatibilityMode = 'Full'
        } else {
          $script:CompatibilityMode = 'Legacy3to4'
        }
      }
      
      if ($script:CompatibilityMode -eq 'Full') {
        $systemInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
      } else {
        $systemInfo = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
      }
      if ($systemInfo) {
        $domain = $systemInfo.Domain
      }
    } catch {
      # Ignore errors getting system info
    }
    
    # Build minimal valid JSON structure with error information
    # PlantId is included in Metadata for PowerBI pivoting
    $errorResult = [pscustomobject]@{
      Schema = $null
      Metadata = [pscustomobject]@{
        GpoMachineDN = $null
        ComputerName = $hostname
        CollectedAt = (Get-Date).ToString('o')
        UserContext = $env:USERNAME
        Domain = $domain
        OldDomainFqdn = if ($OldDomainFqdn) { $OldDomainFqdn } else { $null }
        OldDomainNetBIOS = if ($OldDomainNetBIOS) { $OldDomainNetBIOS } else { $null }
        NewDomainFqdn = if ($NewDomainFqdn) { $NewDomainFqdn } else { $null }
        ProfileDays = if ($ProfileDays) { $ProfileDays } else { $null }
        PlantId = if ($PlantId) { $PlantId } else { $null }
        Version = $ScriptVersion
      }
      System = [pscustomobject]@{
        Hostname = $hostname
        Manufacturer = $null
        Model = $null
        OSVersion = $null
        IPAddress = $null
        MACAddress = $null
        LoggedInUser = $null
      }
      Profiles = @()
      SharedFolders = [pscustomobject]@{
        Shares = @()
        Errors = @()
      }
      InstalledApps = @()
      Services = @()
      ScheduledTasks = @()
      LocalGroupMembers = @()
      LocalAdministrators = @()
      LocalAccounts = [pscustomobject]@{
        Users = @()
        Groups = @()
      }
      MappedDrives = @()
      Printers = @()
      OdbcDsn = @()
      AutoAdminLogon = $null
      CredentialManager = @()
      Certificates = @()
      Endpoints = @()
      FirewallRules = @()
      DnsConfiguration = $null
      IIS = $null
      SqlServer = $null
      EventLogDomainReferences = @()
      ApplicationConfigFiles = [pscustomobject]@{
        FilesWithDomainReferences = @()
        FilesWithCredentials = @()
      }
      SqlServerInstalled = $false
      SqlServerVersion   = $null
      Oracle = [pscustomobject]@{ OracleInstalled = $false; OracleVersion = $null; IsOracleServerLikely = $false; OracleServices = @(); OracleHomes = @(); OracleClientInstalled = $false; OracleODBCDrivers = @(); TnsnamesFiles = @(); SqlNetConfigPaths = @(); Errors = $null }
      RDSLicensing = [pscustomobject]@{ IsRDSSessionHost = $false; RDSRoleInstalled = $null; RdsLicensingRoleInstalled = $false; LicensingMode = 'Unknown'; LicenseServerConfigured = @(); RDSLicensingEvidence = @(); IsRDSLicensingLikelyInUse = $false; Errors = $null }
      SecurityAgents = [pscustomobject]@{
        CrowdStrike = [pscustomobject]@{ Tenant = $null; TenantId = $null; HasDomainReference = $false }
        Qualys = [pscustomobject]@{ Tenant = $null; TenantId = $null; HasDomainReference = $false }
        SCCM = [pscustomobject]@{ Tenant = $null; Found = $false; FoundDomains = @(); HasDomainReference = $false }
      }
      QuestConfig = @()
      References = [pscustomobject]@{
        OldDomain = @()
        ScriptAutomation = @()
      }
      AppSpecific = $null
      DatabaseConnections = @()
      ServerSummary = [pscustomobject]@{
        FileServers = @()
        PrintServers = @()
      }
      Detection = [pscustomobject]@{
        OldDomain = @{}
        Summary = [pscustomobject]@{
          HasOldDomainRefs = $false
          Counts = [pscustomobject]@{
            Services = 0
            ServicesPath = 0
            TaskPrincipals = 0
            TaskActions = 0
            Tasks = 0
            DriveMaps = 0
            LocalGroups = 0
            Printers = 0
            ODBC = 0
            LocalAdmins = 0
            CredentialManager = 0
            Certificates = 0
            CertificateEndpoints = 0
            FirewallRules = 0
            IISSites = 0
            IISAppPools = 0
            SqlServer = 0
            EventLogs = 0
            ApplicationConfigFiles = 0
            HardCodedReferences = 0
            ScriptAutomation = 0
            DatabaseConnections = 0
            AppSpecific = 0
            FileServers = 0
            PrintServers = 0
          }
        }
      }
      Error = [pscustomobject]@{
        HasError = $true
        ErrorMessage = $errorMessage
        ErrorType = $_.Exception.GetType().FullName
        ErrorStackTrace = $errorStackTrace
        InnerException = $errorInnerException
        Timestamp = (Get-Date).ToString('o')
      }
    }
    
    # Write error JSON to file
    Ensure-Directory $OutputRoot
    $fname = ('{0}_{1}.json' -f $hostname, (Get-Date).ToString('MM-dd-yyyy'))
    $localPath = Join-Path $OutputRoot $fname
    
    # Determine compatibility mode if not already set
    if (-not $script:CompatibilityMode) {
      if ($PSVersionTable.PSVersion.Major -ge 5) {
        $script:CompatibilityMode = 'Full'
      } else {
        $script:CompatibilityMode = 'Legacy3to4'
      }
    }
    
    # Determine compatibility mode if not already set
    if (-not $script:CompatibilityMode) {
      if ($PSVersionTable.PSVersion.Major -ge 5) {
        $script:CompatibilityMode = 'Full'
      } else {
        $script:CompatibilityMode = 'Legacy3to4'
      }
    }
    
    if ($script:CompatibilityMode -eq 'Full') {
      $json = $errorResult | ConvertTo-Json -Depth 10
      # Use UTF8NoBOM encoding for Power BI compatibility
      $utf8NoBom = New-Object System.Text.UTF8Encoding $false
      [System.IO.File]::WriteAllText($localPath, $json, $utf8NoBom)
    } else {
      try {
        $json = $errorResult | ConvertTo-Json -Depth 10
      } catch {
        $json = $errorResult | ConvertTo-Json
      }
      [System.IO.File]::WriteAllText($localPath, $json, [System.Text.Encoding]::UTF8)
    }
    
    if ($script:log) {
      $script:log.Write("Wrote error JSON to: $localPath")
    }
    
    # Emit error summary to stdout if requested - PlantId is included for PowerBI pivoting
    if ($EmitStdOut) {
      [pscustomobject]@{
        Computer = $hostname
        PlantId = if ($PlantId) { $PlantId } else { $null }
        HasError = $true
        ErrorMessage = $errorMessage
        CollectedAt = (Get-Date).ToString('o')
        Version = $ScriptVersion
      } | ConvertTo-Json -Compress | Write-Output
    }
    
    # Try to copy to central share if configured
    if ($script:centralShareValidated -and $script:centralShareValidated.IsValid -and $script:centralShareValidated.IsWritable -and $script:centralShareValidated.ValidatedPath) {
      try {
        $validatedPath = $script:centralShareValidated.ValidatedPath
        $targetDir = Join-Path $validatedPath 'workstations'
        Ensure-Directory $targetDir
        $dest = Join-Path $targetDir $fname
        Copy-Item -Path $localPath -Destination $dest -Force
        if ($script:log) {
          $script:log.Write("Copied error JSON to central share: $dest")
        }
      } catch {
        if ($script:log) {
          $script:log.Write("Central copy failed: $($_.Exception.Message)", 'WARN')
        }
      }
    }
  } catch {
    # If we can't even write the error JSON, at least try to log it
    if ($script:log) {
      $script:log.Write("Failed to write error JSON: $($_.Exception.Message)", 'ERROR')
    }
    $techError = "Fatal error occurred and could not write error JSON: $errorMessage"
    Write-Error (Get-HumanReadableError -ErrorMessage $techError -Context "writing error information")
  }
  
  exit 1
}
#endregion
#endregion