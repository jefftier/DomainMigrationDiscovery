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
    Default: 'olddomain.com'

.PARAMETER NewDomainFqdn
    Fully Qualified Domain Name (FQDN) of the new domain.
    Must be a valid FQDN format (e.g., 'example.com' or 'subdomain.example.com').

.PARAMETER OldDomainNetBIOS
    NetBIOS name of the old domain (optional, but recommended for better detection).
    Must be 15 characters or less, alphanumeric with hyphens allowed.
    Example: 'OLDDOMAIN'

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
        -OldDomainFqdn "olddomain.com" `
        -NewDomainFqdn "newdomain.com" `
        -OldDomainNetBIOS "OLDDOMAIN" `
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

.NOTES
    - Requires PowerShell 3.0 or higher (full features require 5.1+)
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
  [string]$OldDomainFqdn = "olddomain.com",
  
  [ValidateScript({
    if ([string]::IsNullOrWhiteSpace($_)) {
      throw "NewDomainFqdn cannot be empty. Please provide a valid FQDN (e.g., 'example.com' or 'subdomain.example.com')."
    }
    if ($_ -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$') {
      throw "NewDomainFqdn must be a valid FQDN (e.g., 'example.com' or 'subdomain.example.com'). It must contain at least one dot and only alphanumeric characters, hyphens, and dots. Provided value: '$_'"
    }
    return $true
  })]
  [string]$NewDomainFqdn = "newdomain.com",
  
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
  [switch]$SlimOnlyRunningServices = $false
)

# PowerShell version compatibility bootstrap
# Must be placed after param block to allow scriptblock parsing when executed remotely
if (-not $PSVersionTable -or -not $PSVersionTable.PSVersion) {
    Write-Error "Unable to determine PowerShell version. This script requires at least PowerShell 3.0."
    exit 1
}

$script:PSMajorVersion = $PSVersionTable.PSVersion.Major

if ($script:PSMajorVersion -lt 3) {
    Write-Output "This server is not compatible with this discovery script. PowerShell 3.0 or higher is required."
    exit 1
}

if ($script:PSMajorVersion -lt 5) {
    $script:CompatibilityMode = 'Legacy3to4'
}
else {
    $script:CompatibilityMode = 'Full'
}

#region ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================
# Full (PS 5.1+) path
if ($script:CompatibilityMode -eq 'Full') {
    Set-StrictMode -Version Latest
}
else {
    # Legacy path for PS 3.0–4.0
    Set-StrictMode -Off
}
$ErrorActionPreference = 'Stop'
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
$CrowdStrikeTenantMap = @{
    '<CU_HEX_VALUE_1>' = 'Tenant 1'
    '<CU_HEX_VALUE_2>' = 'Tenant 2'
    'DEFAULT' = 'Default Tenant'  # Used when CU is found but not in the map above
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
$QualysTenantMap = @{
    '<QUALYS_ACTIVATION_ID>' = 'Qualys Tenant'
    'DEFAULT' = 'Default Tenant'  # Used when ActivationID is found but not in the map above
    'UNKNOWN' = 'Unknown'  # Used when ActivationID is not found
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
    $msg = "$topic failed: $($_.Exception.Message)"
    if ($script:log) { $script:log.Write($msg,'WARN') } else { Write-Warning $msg }
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
    Netbios = if ($netbios) { [regex]("(?i)\b$([regex]::Escape($netbios))\b") } else { $null }
    Fqdn    = if ($fqdn)   { [regex]("(?i)$([regex]::Escape($fqdn))") } else { $null }
    Upn     = if ($fqdn)   { [regex]("(?i)@$([regex]::Escape($fqdn))$") } else { $null }
    LdapDn  = if ($fqdn)   { [regex]("(?i)$([regex]::Escape($dn))") } else { $null }
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
    Retrieves security agent tenant information.

.DESCRIPTION
    Collects information about CrowdStrike and Qualys security agents, including
    their tenant configuration. Uses the user-configurable tenant maps to identify
    which tenant each agent is configured for.

.PARAMETER Log
    Logger object for writing log messages.

.OUTPUTS
    PSCustomObject with CrowdStrike and Qualys tenant information.
#>
function Get-SecurityAgentsTenantInfo {
    [CmdletBinding()]
    param($Log)
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
    }
}

function Get-QuestOdmadConfig {
    [CmdletBinding()]
    param($Log)
    if ($Log) { $Log.Write('Detect: starting Quest ODMAD configuration check') }

    $regPath = 'SOFTWARE\\WOW6432NODE\\Quest\\On Demand Migration For Active Directory\\ODMAD_AD'
    
    # Read each registry value safely
    $agentKey = Get-RegistryValueMultiView -Hive LocalMachine -Path $regPath -Name 'AgentKey'
    $deviceName = Get-RegistryValueMultiView -Hive LocalMachine -Path $regPath -Name 'DeviceName'
    $domainName = Get-RegistryValueMultiView -Hive LocalMachine -Path $regPath -Name 'DomainName'
    $tenantId = Get-RegistryValueMultiView -Hive LocalMachine -Path $regPath -Name 'TenantId'
    $hostname = Get-RegistryValueMultiView -Hive LocalMachine -Path $regPath -Name 'Hostname'
    
    # If no values were found, return null
    if (-not $agentKey -and -not $deviceName -and -not $domainName -and -not $tenantId -and -not $hostname) {
        return $null
    }
    
    [pscustomobject]@{
        RegPath   = 'HKLM:\SOFTWARE\WOW6432NODE\Quest\On Demand Migration For Active Directory\ODMAD_AD'
        AgentKey  = if ($agentKey) { $agentKey.String } else { $null }
        DeviceName = if ($deviceName) { $deviceName.String } else { $null }
        DomainName = if ($domainName) { $domainName.String } else { $null }
        TenantId   = if ($tenantId) { $tenantId.String } else { $null }
        Hostname   = if ($hostname) { $hostname.String } else { $null }
    }
}

function Get-LocalGroupMembersSafe([string]$group){
  $members = @()
  try {
    # Full (PS 5.1+) path
    if ($script:CompatibilityMode -eq 'Full') {
      if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){
        $members = Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object {
          [pscustomobject]@{
            Group = $group
            Name  = $_.Name
            ObjectClass = $_.ObjectClass
            PrincipalSource = $_.PrincipalSource
            SID = $_.SID.Value
          }
        }
        return $members
      }
    }
  } catch {
    # Log the error but continue to fallback
    if ($script:log) { $script:log.Write("Get-LocalGroupMember failed for group '$group', using ADSI fallback: $($_.Exception.Message)", 'WARN') }
  }
  
  # Legacy path for PS 3.0–4.0 or fallback if Get-LocalGroupMember fails
  try {
    $grp = [ADSI]"WinNT://./$group,group"
    $members = $grp.psbase.Invoke('Members') | ForEach-Object {
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
  } catch {
    if ($script:log) { $script:log.Write("ADSI fallback for group '$group' failed: $($_.Exception.Message)", 'WARN') }
  }
  return $members
}

function Get-LocalAdministratorsDetailed{
  $items = @()
  try {
    # Full (PS 5.1+) path
    if ($script:CompatibilityMode -eq 'Full') {
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
    }
  } catch {
    # Log the error but continue to fallback
    if ($script:log) { $script:log.Write("Get-LocalGroupMember failed, using ADSI fallback: $($_.Exception.Message)", 'WARN') }
  }
  
  # Legacy path for PS 3.0–4.0 or fallback if Get-LocalGroupMember fails
  try {
    $grp = [ADSI]"WinNT://./Administrators,group"
    $items = $grp.psbase.Invoke('Members') | ForEach-Object {
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
  } catch {
    if ($script:log) { $script:log.Write("ADSI fallback for LocalAdministrators failed: $($_.Exception.Message)", 'WARN') }
  }
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
  # Full (PS 5.1+) path
  if ($script:CompatibilityMode -eq 'Full') {
    $system = Safe-Try { Get-CimInstance Win32_ComputerSystem } 'Win32_ComputerSystem'
    $os     = Safe-Try { Get-CimInstance Win32_OperatingSystem } 'Win32_OperatingSystem'
  }
  else {
    # Legacy path for PS 3.0–4.0
    $system = Safe-Try { Get-WmiObject -Class Win32_ComputerSystem } 'Win32_ComputerSystem'
    $os     = Safe-Try { Get-WmiObject -Class Win32_OperatingSystem } 'Win32_OperatingSystem'
  }
  $securityAgents = Get-SecurityAgentsTenantInfo -Log $script:log
  $questConfig = Get-QuestOdmadConfig -Log $script:log
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
  # Full (PS 5.1+) path
  if ($script:CompatibilityMode -eq 'Full') {
    $profileCim = Safe-Try { Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue } 'Win32_UserProfile'
  }
  else {
    # Legacy path for PS 3.0–4.0
    $profileCim = Safe-Try { Get-WmiObject -Class Win32_UserProfile -ErrorAction SilentlyContinue } 'Win32_UserProfile'
  }
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
  # SQL Server
  # --------------------------------------------------------------------------------
  # Scan SQL Server instances for old domain references in logins, linked servers, etc.
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
  # Full (PS 5.1+) path
  if ($script:CompatibilityMode -eq 'Full') {
    $services = Safe-Try { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName } 'Services'
  }
  else {
    # Legacy path for PS 3.0–4.0
    $services = Safe-Try { Get-WmiObject -Class Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName } 'Services'
  }
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
      # Full (PS 5.1+) path
      if ($script:CompatibilityMode -eq 'Full') {
        Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,ShareName,SystemName,ServerName,Network
      }
      else {
        # Legacy path for PS 3.0–4.0
        Get-WmiObject -Class Win32_Printer | Select-Object Name,DriverName,PortName,ShareName,SystemName,ServerName,Network
      }
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
          $sqlServerOldDomain += ("{0}: Config File {1}" -f $sqlInstance.InstanceName, $configFile.FilePath)
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
        $appConfigOldDomain += ("Config File: {0}" -f $configFile.FilePath)
      }
    }
    if ($applicationConfigFiles.FilesWithCredentials -and $applicationConfigFiles.FilesWithCredentials.Count -gt 0) {
      foreach($configFile in @($applicationConfigFiles.FilesWithCredentials)){
        if ($null -eq $configFile) { continue }
        $appConfigOldDomain += ("Config File (Credentials): {0}" -f $configFile.FilePath)
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

  <#
  .SYNOPSIS
      Discovers Windows Credential Manager entries that reference the old domain.

  .DESCRIPTION
      Scans Windows Credential Manager (Windows Vault) and cmdkey.exe output for 
      credentials that contain references to the old domain. Checks both registry-based 
      credentials and command-line accessible credentials.

  .PARAMETER ProfileSID
      Security Identifier (SID) of the user profile to scan. If not provided, scans 
      the current user's credentials.

  .PARAMETER ProfilePath
      Path to the user profile directory. Currently not used but reserved for future use.

  .PARAMETER DomainMatchers
      Domain matching object containing regex patterns for old domain detection.

  .PARAMETER Log
      Logger object for writing log messages.

  .OUTPUTS
      Array of PSCustomObject with properties: Profile, Target, UserName, Source, HasDomainReference

  .NOTES
      - Only adds entries that have meaningful values (Target or UserName)
      - Passwords are not extracted (they are encrypted in Windows Vault)
      - cmdkey.exe only works for the current user context
  #>
  function Get-CredentialManagerDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory=$false)]
      [string]$ProfileSID,
      [Parameter(Mandatory=$false)]
      [string]$ProfilePath,
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    
    # Check registry-based credentials (Windows Vault and Internet Settings)
    $regPaths = @()
    if ($ProfileSID) {
      # For loaded user hives
      $regPaths += "Registry::HKEY_USERS\$ProfileSID\Software\Microsoft\Vault"
      $regPaths += "Registry::HKEY_USERS\$ProfileSID\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Credentials"
    } else {
      # For current user
      $regPaths += "Registry::HKEY_CURRENT_USER\Software\Microsoft\Vault"
      $regPaths += "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Credentials"
    }
    
    foreach ($regPath in $regPaths) {
      if (-not (Test-Path $regPath)) { continue }
      
      try {
        $vaultKeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
        foreach ($vaultKey in $vaultKeys) {
          try {
            $target = $null
            $userName = $null
            
            # Try to read common credential properties
            $props = Get-ItemProperty -Path $vaultKey.PSPath -ErrorAction SilentlyContinue
            if ($props) {
              # Check various property names that might contain target/username
              $target = if ($props.Target) { [string]$props.Target } 
                       elseif ($props.Name) { [string]$props.Name }
                       elseif ($props.Resource) { [string]$props.Resource }
                       else { $vaultKey.PSChildName }
              
              $userName = if ($props.UserName) { [string]$props.UserName }
                          elseif ($props.User) { [string]$props.User }
                          elseif ($props.Account) { [string]$props.Account }
            } else {
              $target = $vaultKey.PSChildName
            }
            
            # Only add entry if we have at least one meaningful value (target or username)
            if ($target -or $userName) {
              # Check if target or username contains domain reference
              $hasDomainRef = $false
              if ($target -and $DomainMatchers.Match($target)) { $hasDomainRef = $true }
              if (-not $hasDomainRef -and $userName -and $DomainMatchers.Match($userName)) { $hasDomainRef = $true }
              
              $profileName = if ($ProfileSID) { $ProfileSID } else { $env:USERNAME }
              $results += [pscustomobject]@{
                Profile = $profileName
                Target = $target
                UserName = $userName
                Source = 'Registry'
                HasDomainReference = $hasDomainRef
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error reading vault key $($vaultKey.PSPath): $($_.Exception.Message)", 'WARN') }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error accessing registry path ${regPath}: $($_.Exception.Message)", 'WARN') }
      }
    }
    
    # Check cmdkey.exe for current user (only works for current user context)
    if (-not $ProfileSID) {
      try {
        $cmdkeyPath = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
        if (Test-Path $cmdkeyPath) {
          $cmdkeyOutput = & $cmdkeyPath /list 2>&1
          if ($LASTEXITCODE -eq 0 -and $cmdkeyOutput) {
            $currentTarget = $null
            $currentUser = $null
            $inEntry = $false
            
            foreach ($line in $cmdkeyOutput) {
              $lineStr = [string]$line
              if ($lineStr -match '^Target:\s*(.+)') {
                # If we have a previous entry, save it before starting a new one
                if ($inEntry -and $currentTarget) {
                  $hasDomainRef = $false
                  if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
                  if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
                  
                  $results += [pscustomobject]@{
                    Profile = $env:USERNAME
                    Target = $currentTarget
                    UserName = $currentUser
                    Source = 'CmdKey'
                    HasDomainReference = $hasDomainRef
                  }
                }
                $currentTarget = $Matches[1].Trim()
                $currentUser = $null
                $inEntry = $true
              }
              elseif ($lineStr -match '^Type:\s*(.+)') {
                # Type line, continue
              }
              elseif ($lineStr -match '^User:\s*(.+)') {
                $currentUser = $Matches[1].Trim()
              }
              elseif ([string]::IsNullOrWhiteSpace($lineStr) -and $inEntry) {
                # Empty line indicates end of credential entry
                if ($currentTarget) {
                  $hasDomainRef = $false
                  if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
                  if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
                  
                  $results += [pscustomobject]@{
                    Profile = $env:USERNAME
                    Target = $currentTarget
                    UserName = $currentUser
                    Source = 'CmdKey'
                    HasDomainReference = $hasDomainRef
                  }
                }
                $currentTarget = $null
                $currentUser = $null
                $inEntry = $false
              }
            }
            
            # Handle last entry if output doesn't end with empty line
            if ($inEntry -and $currentTarget) {
              $hasDomainRef = $false
              if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
              if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
              
              $results += [pscustomobject]@{
                Profile = $env:USERNAME
                Target = $currentTarget
                UserName = $currentUser
                Source = 'CmdKey'
                HasDomainReference = $hasDomainRef
              }
            }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error running cmdkey.exe: $($_.Exception.Message)", 'WARN') }
      }
    }
    
    return $results
  }

  function Get-CertificatesWithDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    $stores = @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')
    
    foreach ($storePath in $stores) {
      try {
        if (-not (Test-Path -LiteralPath $storePath -ErrorAction SilentlyContinue)) { continue }
        
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
        foreach ($cert in $certs) {
          try {
            if ($null -eq $cert) { continue }
            
            $subject = [string]$cert.Subject
            $issuer = [string]$cert.Issuer
            $sanText = $null
            $matchedField = $null
            $hasDomainReference = $false
            
            # Extract Subject Alternative Name extension
            try {
              $sanExt = $cert.Extensions | Where-Object { 
                ($_.Oid.FriendlyName -eq 'Subject Alternative Name') -or 
                ($_.Oid.Value -eq '2.5.29.17')
              } | Select-Object -First 1
              
              if ($sanExt) {
                $sanText = $sanExt.Format($false)
              }
            } catch {
              if ($Log) { $Log.Write("Error reading SAN extension for cert $($cert.Thumbprint): $($_.Exception.Message)", 'WARN') }
            }
            
            # Check Subject
            if (-not [string]::IsNullOrWhiteSpace($subject) -and $DomainMatchers.Match($subject)) {
              $hasDomainReference = $true
              $matchedField = 'Subject'
            }
            
            # Check Issuer
            if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($issuer) -and $DomainMatchers.Match($issuer)) {
              $hasDomainReference = $true
              $matchedField = 'Issuer'
            }
            
            # Check SAN
            if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($sanText) -and $DomainMatchers.Match($sanText)) {
              $hasDomainReference = $true
              $matchedField = 'SAN'
            }
            
            # Return all certificates, but flag those with domain references
            $results += [pscustomobject]@{
              Store = $storePath
              Thumbprint = $cert.Thumbprint
              Subject = $subject
              Issuer = $issuer
              NotAfter = if ($cert.NotAfter) { $cert.NotAfter.ToString('o') } else { $null }
              HasDomainReference = $hasDomainReference
              MatchedField = $matchedField
            }
          } catch {
            if ($Log) { $Log.Write("Error processing certificate $($cert.Thumbprint): $($_.Exception.Message)", 'WARN') }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error accessing certificate store $storePath : $($_.Exception.Message)", 'WARN') }
      }
    }
    
    return $results
  }

  function Get-FirewallRulesWithDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    
    # Check if firewall cmdlets are available (Windows 8/Server 2012+)
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
      if ($Log) { $Log.Write('Get-NetFirewallRule cmdlet not available on this OS version', 'WARN') }
      return $results
    }
    
    try {
      $rules = Get-NetFirewallRule -ErrorAction Stop
      
      foreach ($rule in $rules) {
        try {
          if ($null -eq $rule) { continue }
          
          $name = [string]$rule.Name
          $displayName = [string]$rule.DisplayName
          $description = [string]$rule.Description
          $group = [string]$rule.Group
          $direction = [string]$rule.Direction
          $action = [string]$rule.Action
          
          # Get address filter
          $localUser = $null
          $remoteUser = $null
          $applicationPath = $null
          $serviceName = $null
          
          try {
            $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($addrFilter) {
              $localUser = [string]$addrFilter.LocalUser
              $remoteUser = [string]$addrFilter.RemoteUser
            }
          } catch {
            # Address filter may not be available for all rules
          }
          
          # Get application filter
          try {
            $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($appFilter) {
              $applicationPath = [string]$appFilter.Program
              $serviceName = [string]$appFilter.Service
            }
          } catch {
            # Application filter may not be available for all rules
          }
          
          # Check all relevant fields for domain references
          $matchedField = $null
          $hasDomainReference = $false
          
          # Check DisplayName
          if (-not [string]::IsNullOrWhiteSpace($displayName) -and $DomainMatchers.Match($displayName)) {
            $hasDomainReference = $true
            $matchedField = 'DisplayName'
          }
          
          # Check Description
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($description) -and $DomainMatchers.Match($description)) {
            $hasDomainReference = $true
            $matchedField = 'Description'
          }
          
          # Check Group
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($group) -and $DomainMatchers.Match($group)) {
            $hasDomainReference = $true
            $matchedField = 'Group'
          }
          
          # Check LocalUser
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($localUser) -and $DomainMatchers.Match($localUser)) {
            $hasDomainReference = $true
            $matchedField = 'LocalUser'
          }
          
          # Check RemoteUser
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($remoteUser) -and $DomainMatchers.Match($remoteUser)) {
            $hasDomainReference = $true
            $matchedField = 'RemoteUser'
          }
          
          # Check ApplicationPath
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($applicationPath) -and $DomainMatchers.Match($applicationPath)) {
            $hasDomainReference = $true
            $matchedField = 'ApplicationPath'
          }
          
          # Check ServiceName
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($serviceName) -and $DomainMatchers.Match($serviceName)) {
            $hasDomainReference = $true
            $matchedField = 'ServiceName'
          }
          
          # Return all rules, but flag those with domain references
          $results += [pscustomobject]@{
            Name = $name
            DisplayName = $displayName
            Direction = $direction
            Action = $action
            ApplicationPath = $applicationPath
            LocalUser = $localUser
            RemoteUser = $remoteUser
            HasDomainReference = $hasDomainReference
            MatchedField = $matchedField
          }
        } catch {
          if ($Log) { $Log.Write("Error processing firewall rule $($rule.Name): $($_.Exception.Message)", 'WARN') }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error accessing firewall rules: $($_.Exception.Message)", 'WARN') }
    }
    
    return $results
  }

  function Get-IISDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $result = [pscustomobject]@{
      Sites = @()
      AppPools = @()
    }
    
    # Check if IIS is installed
    $iisInstalled = $false
    
    # Method 1: Check Windows Feature (Server OS)
    try {
      if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $webServerFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        if ($webServerFeature -and $webServerFeature.InstallState -eq 'Installed') {
          $iisInstalled = $true
        }
      }
    } catch {
      # Get-WindowsFeature may not be available on client OS
    }
    
    # Method 2: Check if WebAdministration module is available (works on both Server and Client OS)
    if (-not $iisInstalled) {
      try {
        if (Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue) {
          # Try to import and check if IIS is actually running
          Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
          if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
            # Try to access IIS configuration to confirm it's installed
            try {
              $testSite = Get-Website -ErrorAction Stop | Select-Object -First 1
              $iisInstalled = $true
            } catch {
              # IIS module available but IIS not installed or not accessible
            }
          }
        }
      } catch {
        # WebAdministration module not available
      }
    }
    
    # Method 3: Check if IIS service exists
    if (-not $iisInstalled) {
      try {
        $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
        if ($w3svc) {
          $iisInstalled = $true
        }
      } catch {
        # Service check failed
      }
    }
    
    if (-not $iisInstalled) {
      if ($Log) { $Log.Write('IIS (Web-Server role) is not installed on this system', 'INFO') }
      return $null
    }
    
    # IIS is installed, proceed with discovery
    try {
      # Ensure WebAdministration module is loaded
      if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
        Import-Module WebAdministration -ErrorAction Stop | Out-Null
      }
      
      # Get Websites
      try {
        $websites = Get-Website -ErrorAction Stop
        foreach ($site in $websites) {
          try {
            if ($null -eq $site) { continue }
            
            $siteName = [string]$site.Name
            $bindings = @()
            $matchedFields = @()
            $hasDomainReference = $false
            
            # Get bindings for the site
            try {
              $siteBindings = Get-WebBinding -Name $siteName -ErrorAction SilentlyContinue
              foreach ($binding in $siteBindings) {
                if ($null -eq $binding) { continue }
                
                $bindingInfo = [pscustomobject]@{
                  Protocol = [string]$binding.Protocol
                  BindingInformation = [string]$binding.BindingInformation
                  HostHeader = $null
                  IPAddress = $null
                  Port = $null
                }
                
                # Parse binding information (format: IP:Port:HostHeader)
                $bindingInfoStr = [string]$binding.BindingInformation
                if ($bindingInfoStr -match '^([^:]+):(\d+):(.+)$') {
                  $bindingInfo.IPAddress = $Matches[1]
                  $bindingInfo.Port = $Matches[2]
                  $bindingInfo.HostHeader = $Matches[3]
                } elseif ($bindingInfoStr -match '^([^:]+):(\d+)$') {
                  $bindingInfo.IPAddress = $Matches[1]
                  $bindingInfo.Port = $Matches[2]
                }
                
                # Check binding for domain references
                $bindingCheckStr = "$($bindingInfo.HostHeader) $($bindingInfo.BindingInformation)"
                if ($DomainMatchers.Match($bindingCheckStr)) {
                  $hasDomainReference = $true
                  if (-not ($matchedFields -contains 'Binding')) {
                    $matchedFields += 'Binding'
                  }
                }
                
                $bindings += $bindingInfo
              }
            } catch {
              if ($Log) { $Log.Write("Error getting bindings for site $siteName : $($_.Exception.Message)", 'WARN') }
            }
            
            # Check site name for domain references
            if ($DomainMatchers.Match($siteName)) {
              $hasDomainReference = $true
              if (-not ($matchedFields -contains 'Name')) {
                $matchedFields += 'Name'
              }
            }
            
            # Get applications and check their paths
            try {
              $applications = Get-WebApplication -Site $siteName -ErrorAction SilentlyContinue
              foreach ($app in $applications) {
                if ($null -eq $app) { continue }
                $appPath = [string]$app.Path
                if ($DomainMatchers.Match($appPath)) {
                  $hasDomainReference = $true
                  if (-not ($matchedFields -contains 'ApplicationPath')) {
                    $matchedFields += 'ApplicationPath'
                  }
                }
              }
            } catch {
              # Applications may not exist or may not be accessible
            }
            
            $result.Sites += [pscustomobject]@{
              Name = $siteName
              State = [string]$site.State
              Bindings = $bindings
              HasDomainReference = $hasDomainReference
              MatchedFields = $matchedFields
            }
          } catch {
            if ($Log) { $Log.Write("Error processing website $($site.Name): $($_.Exception.Message)", 'WARN') }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error getting websites: $($_.Exception.Message)", 'WARN') }
      }
      
      # Get Application Pools
      try {
        # Try to get app pools directly from IIS provider
        $appPoolItems = @()
        try {
          $appPoolItems = Get-ChildItem "IIS:\AppPools" -ErrorAction Stop
        } catch {
          # Fallback to Get-WebAppPoolState if direct access fails
          $appPoolStates = Get-WebAppPoolState -ErrorAction SilentlyContinue
          if ($appPoolStates) {
            foreach ($state in $appPoolStates) {
              try {
                $poolItem = Get-Item "IIS:\AppPools\$($state.Name)" -ErrorAction Stop
                $appPoolItems += $poolItem
              } catch {
                # Skip if we can't access the pool
              }
            }
          }
        }
        
        foreach ($poolItem in $appPoolItems) {
          $poolName = $poolItem.Name
          try {
            if ([string]::IsNullOrWhiteSpace($poolName)) { continue }
            
            $matchedFields = @()
            $hasDomainReference = $false
            $identityType = $null
            $identityUser = $null
            
            # Get application pool configuration
            try {
              # Get process model identity
              $processModel = $poolItem.processModel
              if ($processModel) {
                $identityType = [string]$processModel.identityType
                $identityUser = [string]$processModel.userName
                
                # Check identity user for domain references
                if (-not [string]::IsNullOrWhiteSpace($identityUser)) {
                  if ($DomainMatchers.Match($identityUser)) {
                    $hasDomainReference = $true
                    if (-not ($matchedFields -contains 'IdentityUser')) {
                      $matchedFields += 'IdentityUser'
                    }
                  }
                }
              }
            } catch {
              if ($Log) { $Log.Write("Error getting app pool details for $poolName : $($_.Exception.Message)", 'WARN') }
            }
            
            # Check pool name for domain references
            if ($DomainMatchers.Match($poolName)) {
              $hasDomainReference = $true
              if (-not ($matchedFields -contains 'Name')) {
                $matchedFields += 'Name'
              }
            }
            
            $result.AppPools += [pscustomobject]@{
              Name = $poolName
              IdentityType = $identityType
              IdentityUser = $identityUser
              HasDomainReference = $hasDomainReference
              MatchedFields = $matchedFields
            }
          } catch {
            if ($Log) { $Log.Write("Error processing app pool $poolName : $($_.Exception.Message)", 'WARN') }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error getting application pools: $($_.Exception.Message)", 'WARN') }
      }
      
    } catch {
      if ($Log) { $Log.Write("Error accessing IIS configuration: $($_.Exception.Message)", 'WARN') }
      return $null
    }
    
    return $result
  }

  function Get-SqlDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    
    # Step 1: Detect SQL Server instances
    $sqlInstances = @()
    
    # Method 1: Check for SQL Server services (MSSQL*)
    try {
      $sqlServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -like 'MSSQL*' -or 
        $_.Name -like 'MSSQLSERVER' -or
        $_.DisplayName -like '*SQL Server*'
      }
      
      foreach ($svc in $sqlServices) {
        # Extract instance name from service name
        # MSSQLSERVER = default instance
        # MSSQL$INSTANCENAME = named instance
        $instanceName = if ($svc.Name -eq 'MSSQLSERVER') { 
          $env:COMPUTERNAME 
        } elseif ($svc.Name -like 'MSSQL$*') {
          $svc.Name -replace 'MSSQL\$', ''
        } else {
          $svc.Name
        }
        
        if ($instanceName -and -not ($sqlInstances | Where-Object { $_.InstanceName -eq $instanceName })) {
          $sqlInstances += [pscustomobject]@{
            InstanceName = $instanceName
            ServiceName = $svc.Name
            DisplayName = $svc.DisplayName
            State = $svc.Status
            DetectionMethod = 'Service'
          }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error detecting SQL services: $($_.Exception.Message)", 'WARN') }
    }
    
    # Method 2: Check registry for SQL Server instances
    try {
      $regPaths = @(
        'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL',
        'SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL'
      )
      
      foreach ($regPath in $regPaths) {
        try {
          $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
          $key = $base.OpenSubKey($regPath)
          if ($key) {
            foreach ($instanceName in $key.GetValueNames()) {
              if ($instanceName -and -not ($sqlInstances | Where-Object { $_.InstanceName -eq $instanceName })) {
                $sqlInstances += [pscustomobject]@{
                  InstanceName = $instanceName
                  ServiceName = $null
                  DisplayName = $null
                  State = $null
                  DetectionMethod = 'Registry'
                }
              }
            }
            $key.Close()
          }
        } catch {
          # Registry path may not exist, continue
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error checking registry for SQL instances: $($_.Exception.Message)", 'WARN') }
    }
    
    # If no instances detected, return null
    if ($sqlInstances.Count -eq 0) {
      if ($Log) { $Log.Write('No SQL Server instances detected on this system', 'INFO') }
      return $null
    }
    
    if ($Log) { $Log.Write("Detected $($sqlInstances.Count) SQL Server instance(s)", 'INFO') }
    
    # Step 2: For each instance, attempt to query for domain references
    foreach ($instance in $sqlInstances) {
      $instanceName = $instance.InstanceName
      $domainLogins = @()
      $linkedServersWithDomainRefs = @()
      $configFilesWithDomainRefs = @()
      
      # Build connection string
      $serverName = if ($instanceName -eq $env:COMPUTERNAME) { 
        $env:COMPUTERNAME 
      } else { 
        "$env:COMPUTERNAME\$instanceName" 
      }
      
      # Try SMO first (SQL Server Management Objects)
      $smoAvailable = $false
      try {
        # Check if SMO type is already loaded
        $smoType = [Microsoft.SqlServer.Management.Smo.Server] -as [Type]
        if ($smoType) {
          $smoAvailable = $true
        } else {
          # Try to load SMO assembly
          try {
            Add-Type -AssemblyName 'Microsoft.SqlServer.Smo' -ErrorAction Stop
            $smoAvailable = $true
          } catch {
            # Try alternative loading method
            try {
              $smoPath = Get-ChildItem -Path "$env:ProgramFiles\Microsoft SQL Server" -Recurse -Filter 'Microsoft.SqlServer.Smo.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
              if ($smoPath -and (Test-Path $smoPath.FullName)) {
                Add-Type -Path $smoPath.FullName -ErrorAction Stop
                $smoAvailable = $true
              }
            } catch {
              # SMO not available, will try other methods
            }
          }
        }
      } catch {
        # SMO not available, will try other methods
      }
      
      if ($smoAvailable) {
        try {
          # Use SMO to query SQL Server
          $server = New-Object Microsoft.SqlServer.Management.Smo.Server($serverName)
          
          # Query Windows logins
          try {
            foreach ($login in $server.Logins) {
              if ($login.LoginType -eq 'WindowsUser' -or $login.LoginType -eq 'WindowsGroup') {
                $loginName = $login.Name
                if ($DomainMatchers.Match($loginName)) {
                  $domainLogins += [pscustomobject]@{
                    LoginName = $loginName
                    LoginType = $login.LoginType
                    DefaultDatabase = $login.DefaultDatabase
                    IsDisabled = $login.IsDisabled
                  }
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error querying logins for instance $instanceName : $($_.Exception.Message)", 'WARN') }
          }
          
          # Query linked servers
          try {
            foreach ($linkedServer in $server.LinkedServers) {
              $linkedServerName = $linkedServer.Name
              $hasDomainRef = $false
              $matchedFields = @()
              
              # Check server name
              if ($DomainMatchers.Match($linkedServerName)) {
                $hasDomainRef = $true
                $matchedFields += 'ServerName'
              }
              
              # Check provider string
              if (-not $hasDomainRef -and $linkedServer.ProviderString -and $DomainMatchers.Match($linkedServer.ProviderString)) {
                $hasDomainRef = $true
                $matchedFields += 'ProviderString'
              }
              
              # Check remote login (if configured)
              if (-not $hasDomainRef -and $linkedServer.RemoteLogin -and $DomainMatchers.Match($linkedServer.RemoteLogin)) {
                $hasDomainRef = $true
                $matchedFields += 'RemoteLogin'
              }
              
              if ($hasDomainRef) {
                $linkedServersWithDomainRefs += [pscustomobject]@{
                  LinkedServerName = $linkedServerName
                  ProviderName = $linkedServer.ProviderName
                  DataSource = $linkedServer.DataSource
                  RemoteLogin = $linkedServer.RemoteLogin
                  MatchedFields = $matchedFields
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error querying linked servers for instance $instanceName : $($_.Exception.Message)", 'WARN') }
          }
        } catch {
          if ($Log) { $Log.Write("Error connecting to SQL instance $instanceName via SMO: $($_.Exception.Message)", 'WARN') }
          $smoAvailable = $false  # Mark SMO as failed so we try fallback
        }
      }
      
      # Fallback: Try Invoke-Sqlcmd if SMO not available or failed
      if (-not $smoAvailable) {
        try {
          if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
            # Query Windows logins
            try {
              # Get all Windows logins and filter in PowerShell (more flexible than SQL LIKE)
              $loginQuery = @"
SELECT 
    name AS LoginName,
    type_desc AS LoginType,
    default_database_name AS DefaultDatabase,
    is_disabled AS IsDisabled
FROM sys.server_principals
WHERE type IN ('U', 'G')
"@
              $loginResults = Invoke-Sqlcmd -ServerInstance $serverName -Query $loginQuery -ErrorAction SilentlyContinue
              if ($loginResults) {
                foreach ($row in $loginResults) {
                  $loginName = $row.LoginName
                  if ($DomainMatchers.Match($loginName)) {
                    $domainLogins += [pscustomobject]@{
                      LoginName = $loginName
                      LoginType = $row.LoginType
                      DefaultDatabase = $row.DefaultDatabase
                      IsDisabled = $row.IsDisabled
                    }
                  }
                }
              }
            } catch {
              if ($Log) { $Log.Write("Error querying logins via Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
            }
            
            # Query linked servers
            try {
              $linkedServerQuery = @"
SELECT 
    srv.name AS LinkedServerName,
    srv.provider AS ProviderName,
    srv.data_source AS DataSource,
    srv.catalog AS Catalog,
    ls.remote_name AS RemoteLogin
FROM sys.servers srv
LEFT JOIN sys.linked_logins ls ON srv.server_id = ls.server_id
WHERE srv.is_linked = 1
"@
              $linkedServerResults = Invoke-Sqlcmd -ServerInstance $serverName -Query $linkedServerQuery -ErrorAction SilentlyContinue
              if ($linkedServerResults) {
                foreach ($row in $linkedServerResults) {
                  $hasDomainRef = $false
                  $matchedFields = @()
                  
                  $linkedServerName = $row.LinkedServerName
                  if ($DomainMatchers.Match($linkedServerName)) {
                    $hasDomainRef = $true
                    $matchedFields += 'ServerName'
                  }
                  
                  if (-not $hasDomainRef -and $row.DataSource -and $DomainMatchers.Match($row.DataSource)) {
                    $hasDomainRef = $true
                    $matchedFields += 'DataSource'
                  }
                  
                  if (-not $hasDomainRef -and $row.RemoteLogin -and $DomainMatchers.Match($row.RemoteLogin)) {
                    $hasDomainRef = $true
                    $matchedFields += 'RemoteLogin'
                  }
                  
                  if ($hasDomainRef) {
                    $linkedServersWithDomainRefs += [pscustomobject]@{
                      LinkedServerName = $linkedServerName
                      ProviderName = $row.ProviderName
                      DataSource = $row.DataSource
                      RemoteLogin = $row.RemoteLogin
                      MatchedFields = $matchedFields
                    }
                  }
                }
              }
            } catch {
              if ($Log) { $Log.Write("Error querying linked servers via Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
            }
          } else {
            if ($Log) { $Log.Write("SQL tools (SMO or Invoke-Sqlcmd) not available for instance $instanceName", 'WARN') }
          }
        } catch {
          if ($Log) { $Log.Write("Error using Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
        }
      }
      
      # Step 3: Scan for configuration files that might contain SQL references
      try {
        $configPaths = @()
        
        # Common SQL Server configuration file locations
        $sqlInstallPaths = @(
          "C:\Program Files\Microsoft SQL Server",
          "C:\Program Files (x86)\Microsoft SQL Server"
        )
        
        foreach ($basePath in $sqlInstallPaths) {
          if (Test-Path $basePath) {
            $configPaths += Get-ChildItem -Path $basePath -Recurse -Include *.config,*.ini,*.conf,*.xml -ErrorAction SilentlyContinue | Select-Object -First 50
          }
        }
        
        # Also check common application config locations
        $appConfigPaths = @(
          "$env:ProgramFiles\*\*.config",
          "$env:ProgramFiles(x86)\*\*.config",
          "$env:ProgramData\*\*.config",
          "$env:APPDATA\*\*.config"
        )
        
        foreach ($pattern in $appConfigPaths) {
          try {
            $configPaths += Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 20
          } catch {
            # Pattern may not match, continue
          }
        }
        
        # Scan files for domain references in connection strings
        foreach ($configFile in $configPaths) {
          try {
            if (-not (Test-Path -LiteralPath $configFile.FullName)) { continue }
            
            # Full (PS 5.1+) path
            if ($script:CompatibilityMode -eq 'Full') {
                $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction SilentlyContinue
            }
            else {
                # Legacy path for PS 3.0–4.0 (Get-Content -Raw not available)
                try {
                    $content = [System.IO.File]::ReadAllText($configFile.FullName)
                }
                catch {
                    $content = $null
                }
            }
            if ($content -and $DomainMatchers.Match($content)) {
              # Extract connection strings or relevant sections
              $matchedLines = @()
              $lines = Get-Content -Path $configFile.FullName -ErrorAction SilentlyContinue
              foreach ($line in $lines) {
                if ($DomainMatchers.Match($line)) {
                  $matchedLines += $line.Trim()
                }
              }
              
              if ($matchedLines.Count -gt 0) {
                $configFilesWithDomainRefs += [pscustomobject]@{
                  FilePath = $configFile.FullName
                  FileName = $configFile.Name
                  MatchedLines = $matchedLines[0..([Math]::Min(5, $matchedLines.Count - 1))]  # Limit to first 5 matches
                  TotalMatches = $matchedLines.Count
                }
              }
            }
          } catch {
            # Skip files that can't be read
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error scanning configuration files: $($_.Exception.Message)", 'WARN') }
      }
      
      # Build result for this instance
      $results += [pscustomobject]@{
        InstanceName = $instanceName
        ServiceName = $instance.ServiceName
        DetectionMethod = $instance.DetectionMethod
        DomainLogins = $domainLogins
        LinkedServersWithDomainReferences = $linkedServersWithDomainRefs
        ConfigFilesWithDomainReferences = $configFilesWithDomainRefs
      }
    }
    
    return $results
  }

  function Get-ApplicationConfigDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    $configFilesWithDomainRefs = @()
    $configFilesWithCredentials = @()
    
    try {
      if ($Log) { $Log.Write('Scanning application configuration files for domain references and credentials', 'INFO') }
      
      # Common application configuration file patterns
      $configFilePatterns = @(
        '*.config',
        '*.ini',
        '*.conf',
        '*.xml',
        '*.json',
        '*.properties',
        '*.yaml',
        '*.yml',
        'web.config',
        'app.config',
        'appsettings.json',
        'connectionstrings.config',
        'settings.ini'
      )
      
      # Common application configuration file locations (non-recursive first level)
      $appConfigLocations = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:ProgramData",
        "$env:ALLUSERSPROFILE",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:USERPROFILE"
      )
      
      # Also check common application subdirectories
      $appSubdirs = @(
        '\AppData\Local',
        '\AppData\Roaming',
        '\Documents',
        '\Application Data'
      )
      
      $allConfigPaths = @()
      
      # Scan Program Files and Program Files (x86) - limit depth to avoid performance issues
      foreach ($basePath in @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")) {
        if (Test-Path $basePath) {
          try {
            # Look for common config files in first-level subdirectories (one level deep)
            Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
              $appDir = $_.FullName
              foreach ($pattern in $configFilePatterns) {
                try {
                  $files = Get-ChildItem -Path $appDir -Filter $pattern -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 10
                  if ($files) {
                    $allConfigPaths += $files
                  }
                } catch {
                  # Skip directories we can't access
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error scanning $basePath : $($_.Exception.Message)", 'WARN') }
          }
        }
      }
      
      # Scan ProgramData - common location for application configs
      if (Test-Path $env:ProgramData) {
        try {
          Get-ChildItem -Path $env:ProgramData -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $appDir = $_.FullName
            foreach ($pattern in $configFilePatterns) {
              try {
                $files = Get-ChildItem -Path $appDir -Filter $pattern -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 10
                if ($files) {
                  $allConfigPaths += $files
                }
              } catch {
                # Skip directories we can't access
              }
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error scanning ProgramData: $($_.Exception.Message)", 'WARN') }
        }
      }
      
      # Scan user profile directories for config files
      $userProfilesPath = "$env:SystemDrive\Users"
      if (Test-Path $userProfilesPath) {
        try {
          Get-ChildItem -Path $userProfilesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userDir = $_.FullName
            $appDataLocal = Join-Path $userDir 'AppData\Local'
            $appDataRoaming = Join-Path $userDir 'AppData\Roaming'
            
            foreach ($userAppPath in @($appDataLocal, $appDataRoaming)) {
              if (Test-Path $userAppPath) {
                try {
                  foreach ($pattern in $configFilePatterns) {
                    $files = Get-ChildItem -Path $userAppPath -Filter $pattern -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 5
                    if ($files) {
                      $allConfigPaths += $files
                    }
                  }
                } catch {
                  # Skip directories we can't access
                }
              }
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error scanning user profiles: $($_.Exception.Message)", 'WARN') }
        }
      }
      
      # Remove duplicates
      $allConfigPaths = $allConfigPaths | Sort-Object FullName -Unique
      
      if ($Log) { $Log.Write("Found $($allConfigPaths.Count) configuration files to scan", 'INFO') }
      
      # Scan each file for domain references and credentials
      $filesScanned = 0
      $maxFilesToScan = 500  # Limit to avoid performance issues
      
      foreach ($configFile in $allConfigPaths) {
        if ($filesScanned -ge $maxFilesToScan) {
          if ($Log) { $Log.Write("Reached maximum file scan limit ($maxFilesToScan), stopping scan", 'INFO') }
          break
        }
        
        try {
          if (-not (Test-Path -LiteralPath $configFile.FullName)) { continue }
          
          # Skip very large files (> 5MB) to avoid memory issues
          $fileInfo = Get-Item -LiteralPath $configFile.FullName -ErrorAction SilentlyContinue
          if ($fileInfo -and $fileInfo.Length -gt 5MB) { continue }
          
          $content = $null
          $matchedLines = @()
          $hasDomainRef = $false
          $hasCredentials = $false
          $credentialPatterns = @()
          
          # Full (PS 5.1+) path
          if ($script:CompatibilityMode -eq 'Full') {
            try {
              # Try to read as text
              $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction Stop -Encoding UTF8
            } catch {
              # Try alternative encoding
              try {
                $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction Stop -Encoding Default
              } catch {
                # Skip files we can't read
                continue
              }
            }
          }
          else {
            # Legacy path for PS 3.0–4.0 (Get-Content -Raw and -Encoding not available)
            try {
              # Try UTF8 first
              $content = [System.IO.File]::ReadAllText($configFile.FullName, [System.Text.Encoding]::UTF8)
            } catch {
              try {
                # Try default encoding
                $content = [System.IO.File]::ReadAllText($configFile.FullName)
              } catch {
                # Skip files we can't read
                continue
              }
            }
          }
          
          if (-not $content) { continue }
          
          $filesScanned++
          
          # Check for domain references
          if ($DomainMatchers.Match($content)) {
            $hasDomainRef = $true
            $lines = $content -split "`r?`n"
            foreach ($line in $lines) {
              if ($DomainMatchers.Match($line)) {
                $matchedLines += $line.Trim()
                if ($matchedLines.Count -ge 10) { break }  # Limit matched lines
              }
            }
          }
          
          # Check for embedded credentials (connection strings, passwords, etc.)
          # Look for common patterns that might indicate credentials
          $credentialIndicators = @(
            'password\s*[=:]\s*["'']?[^"'']+["'']?',  # password=value or password:value
            'pwd\s*[=:]\s*["'']?[^"'']+["'']?',       # pwd=value
            'passwd\s*[=:]\s*["'']?[^"'']+["'']?',    # passwd=value
            'connectionstring\s*[=:]\s*["'']?[^"'']+["'']?',  # connectionstring=value
            'connection\s*string\s*[=:]\s*["'']?[^"'']+["'']?',  # connection string=value
            'user\s*id\s*[=:]\s*["'']?[^"'']+["'']?',  # user id=value
            'userid\s*[=:]\s*["'']?[^"'']+["'']?',     # userid=value
            'uid\s*[=:]\s*["'']?[^"'']+["'']?',        # uid=value
            'integrated\s+security\s*[=:]\s*["'']?true["'']?',  # integrated security=true (Windows auth)
            'trusted_connection\s*[=:]\s*["'']?true["'']?'     # trusted_connection=true
          )
          
          foreach ($pattern in $credentialIndicators) {
            if ($content -match $pattern -and -not $hasCredentials) {
              $hasCredentials = $true
              $credentialPatterns += $pattern
            }
          }
          
          # Also check if connection strings contain domain references (even if no explicit password)
          if ($content -match '(?i)connectionstring|connection\s+string|data\s+source|server\s*=') {
            if ($DomainMatchers.Match($content)) {
              $hasCredentials = $true
              $credentialPatterns += 'ConnectionStringWithDomain'
            }
          }
          
          # Record findings
          if ($hasDomainRef -or $hasCredentials) {
            $fileResult = [pscustomobject]@{
              FilePath = $configFile.FullName
              FileName = $configFile.Name
              FileSize = if ($fileInfo) { $fileInfo.Length } else { $null }
              HasDomainReference = $hasDomainRef
              HasCredentials = $hasCredentials
              MatchedLines = if ($matchedLines.Count -gt 0) { $matchedLines[0..([Math]::Min(10, $matchedLines.Count - 1))] } else { @() }
              TotalDomainMatches = $matchedLines.Count
              CredentialPatterns = $credentialPatterns
            }
            
            if ($hasDomainRef) {
              $configFilesWithDomainRefs += $fileResult
            }
            if ($hasCredentials) {
              $configFilesWithCredentials += $fileResult
            }
          }
        } catch {
          # Skip files that cause errors
          if ($Log) { $Log.Write("Error scanning file $($configFile.FullName): $($_.Exception.Message)", 'WARN') }
        }
      }
      
      if ($Log) { 
        $Log.Write("Scanned $filesScanned configuration files", 'INFO')
        $Log.Write("Found $($configFilesWithDomainRefs.Count) files with domain references", 'INFO')
        $Log.Write("Found $($configFilesWithCredentials.Count) files with potential credentials", 'INFO')
      }
      
    } catch {
      if ($Log) { $Log.Write("Error in application config file scanning: $($_.Exception.Message)", 'ERROR') }
    }
    
    # Return results
    if ($configFilesWithDomainRefs.Count -eq 0 -and $configFilesWithCredentials.Count -eq 0) {
      return $null
    }
    
    return [pscustomobject]@{
      FilesWithDomainReferences = $configFilesWithDomainRefs
      FilesWithCredentials = $configFilesWithCredentials
      TotalFilesScanned = $filesScanned
      TotalFilesWithDomainRefs = $configFilesWithDomainRefs.Count
      TotalFilesWithCredentials = $configFilesWithCredentials.Count
    }
  }

  function Get-DnsConfigurationForMigration {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $result = [pscustomobject]@{
      SuffixSearchList = $null
      Adapters = @()
      HasOldDomainReference = $false
    }
    
    # Get global DNS settings (suffix search list)
    try {
      if (Get-Command Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue) {
        $globalSettings = Get-DnsClientGlobalSetting -ErrorAction Stop
        if ($globalSettings) {
          $suffixList = @()
          if ($globalSettings.SuffixSearchList) {
            $suffixList = @($globalSettings.SuffixSearchList)
          }
          $result.SuffixSearchList = $suffixList
          
          # Check if any suffix contains old domain reference
          foreach ($suffix in $suffixList) {
            if ($DomainMatchers.Match($suffix)) {
              $result.HasOldDomainReference = $true
              break
            }
          }
        }
      } else {
        if ($Log) { $Log.Write('Get-DnsClientGlobalSetting cmdlet not available on this OS version', 'WARN') }
      }
    } catch {
      if ($Log) { $Log.Write("Error getting DNS global settings: $($_.Exception.Message)", 'WARN') }
    }
    
    # Get per-adapter DNS server addresses
    try {
      if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        $adapterDns = Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.AddressFamily -eq 'IPv4' }
        
        foreach ($adapter in $adapterDns) {
          $serverAddresses = @()
          if ($adapter.ServerAddresses) {
            $serverAddresses = @($adapter.ServerAddresses)
          }
          
          # Check if any server address contains old domain reference
          $adapterHasOldRef = $false
          foreach ($server in $serverAddresses) {
            if ($DomainMatchers.Match($server)) {
              $adapterHasOldRef = $true
              $result.HasOldDomainReference = $true
              break
            }
          }
          
          # Try to get connection-specific DNS suffix if available
          $connectionSuffix = $null
          try {
            # Get InterfaceGuid from NetAdapter to access registry
            $netAdapter = Get-NetAdapter -InterfaceAlias $adapter.InterfaceAlias -ErrorAction SilentlyContinue
            if ($netAdapter -and $netAdapter.InterfaceGuid) {
              $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($netAdapter.InterfaceGuid)"
              if (Test-Path $adapterRegPath) {
                $regProps = Get-ItemProperty -Path $adapterRegPath -ErrorAction SilentlyContinue
                if ($regProps) {
                  # Prefer Domain over DhcpDomain
                  $connectionSuffix = if ($regProps.'Domain') { $regProps.'Domain' } elseif ($regProps.'DhcpDomain') { $regProps.'DhcpDomain' } else { $null }
                  if ($connectionSuffix -and $DomainMatchers.Match($connectionSuffix)) {
                    $adapterHasOldRef = $true
                    $result.HasOldDomainReference = $true
                  }
                }
              }
            }
          } catch {
            # Connection-specific suffix is optional, so we silently continue
          }
          
          $result.Adapters += [pscustomobject]@{
            InterfaceAlias = $adapter.InterfaceAlias
            InterfaceIndex = $adapter.InterfaceIndex
            ServerAddresses = $serverAddresses
            ConnectionSpecificSuffix = $connectionSuffix
            HasOldDomainReference = $adapterHasOldRef
          }
        }
      } else {
        if ($Log) { $Log.Write('Get-DnsClientServerAddress cmdlet not available on this OS version', 'WARN') }
      }
    } catch {
      if ($Log) { $Log.Write("Error getting DNS adapter settings: $($_.Exception.Message)", 'WARN') }
    }
    
    return $result
  }

  function Get-EventLogDomainReferences {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)]
      $DomainMatchers,
      [Parameter(Mandatory)]
      [int]$DaysBack,
      [Parameter(Mandatory=$false)]
      $Log
    )
    
    $results = @()
    $maxEventsPerLog = 100
    $logNames = @('System', 'Security', 'Application')
    $startTime = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    
    if ($Log) { $Log.Write("Scanning event logs for domain references (last $DaysBack days, max $maxEventsPerLog per log)") }
    
    foreach ($logName in $logNames) {
      try {
        # Check if log exists and is accessible
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if (-not $logExists) {
          if ($Log) { $Log.Write("Event log '$logName' not found or not accessible", 'WARN') }
          continue
        }
        
        # Query events within time window (query more events since we'll filter many out)
        # Full (PS 5.1+) path
        if ($script:CompatibilityMode -eq 'Full') {
          $events = Get-WinEvent -LogName $logName -FilterHashtable @{
            StartTime = $startTime
          } -ErrorAction SilentlyContinue -MaxEvents ($maxEventsPerLog * 5)
        }
        else {
          # Legacy path for PS 3.0–4.0 (FilterHashtable available but using FilterXPath for compatibility)
          try {
            $xpathFilter = "*[System[TimeCreated[@SystemTime >= '{0:yyyy-MM-ddTHH:mm:ss.fffZ}']]]" -f $startTime.ToUniversalTime()
            $events = Get-WinEvent -LogName $logName -FilterXPath $xpathFilter -ErrorAction SilentlyContinue -MaxEvents ($maxEventsPerLog * 5)
          }
          catch {
            # If FilterXPath fails, try without time filter (less efficient but works)
            if ($Log) { $Log.Write("Event log query with time filter failed for '$logName', attempting without time filter: $($_.Exception.Message)", 'WARN') }
            $events = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue -MaxEvents ($maxEventsPerLog * 5)
            # Filter by time manually
            if ($events) {
              $events = $events | Where-Object { $_.TimeCreated -ge $startTime }
            }
          }
        }
        
        if (-not $events) { continue }
        
        $matchedCount = 0
        foreach ($event in $events) {
          # Stop if we've reached the limit
          if ($matchedCount -ge $maxEventsPerLog) { break }
          try {
            if ($null -eq $event) { continue }
            
            # Get message text
            $message = $null
            try {
              $message = $event.Message
            } catch {
              # Some events may not have readable messages, try to get formatted message
              try {
                $message = $event | Format-List -Property * | Out-String
              } catch {
                # If we can't get message, skip this event
                continue
              }
            }
            
            if ([string]::IsNullOrWhiteSpace($message)) { continue }
            
            # Check if message contains domain reference
            if ($DomainMatchers.Match($message)) {
              # Extract a snippet (truncate to 200 chars for performance)
              $snippet = $message
              if ($snippet.Length -gt 200) {
                $snippet = $message.Substring(0, 200) + '...'
              }
              
              $results += [pscustomobject]@{
                LogName = $logName
                TimeCreated = if ($event.TimeCreated) { $event.TimeCreated.ToString('o') } else { $null }
                Id = $event.Id
                LevelDisplayName = if ($event.LevelDisplayName) { $event.LevelDisplayName } else { $null }
                MessageSnippet = $snippet
              }
              
              $matchedCount++
              if ($matchedCount -ge $maxEventsPerLog) { break }
            }
          } catch {
            if ($Log) { $Log.Write("Error processing event $($event.Id) from log $logName : $($_.Exception.Message)", 'WARN') }
          }
        }
        
        if ($Log -and $matchedCount -gt 0) { 
          $Log.Write("Found $matchedCount domain reference(s) in $logName log") 
        }
      } catch {
        if ($Log) { $Log.Write("Error accessing event log '$logName': $($_.Exception.Message)", 'WARN') }
      }
    }
    
    return $results
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
        # Full (PS 5.1+) path
        if ($script:CompatibilityMode -eq 'Full') {
            $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | Where-Object { $_.Type -eq 0 }
        }
        else {
            # Legacy path for PS 3.0–4.0
            $shares = Get-WmiObject -Class Win32_Share -ErrorAction Stop | Where-Object { $_.Type -eq 0 }
        }
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
    SqlServer = $sqlServerConfiguration
    EventLogDomainReferences = $eventLogDomainReferences
    ApplicationConfigFiles = $applicationConfigFiles
    SecurityAgents = $securityAgents
    QuestConfig    = $questConfig
    Detection     = [pscustomobject]@{ OldDomain = $flags; Summary = $summary }
  }

  # --------------------------------------------------------------------------------
  # Write Output Files
  # --------------------------------------------------------------------------------
  Ensure-Directory $OutputRoot
  $fname = ('{0}_{1}.json' -f $env:COMPUTERNAME, (Get-Date).ToString('MM-dd-yyyy'))
  $localPath = Join-Path $OutputRoot $fname
  try {
    # Full (PS 5.1+) path
    if ($script:CompatibilityMode -eq 'Full') {
      $json = $result | ConvertTo-Json -Depth 8
    }
    else {
      # Legacy path for PS 3.0–4.0 (-Depth parameter available but may have limitations)
      try {
        $json = $result | ConvertTo-Json -Depth 8
      }
      catch {
        # Fallback to default depth if -Depth fails
        if ($Log) { $Log.Write("ConvertTo-Json -Depth failed, using default depth: $($_.Exception.Message)", 'WARN') }
        $json = $result | ConvertTo-Json
      }
    }
    # Full (PS 5.1+) path
    if ($script:CompatibilityMode -eq 'Full') {
      Set-Content -Path $localPath -Value $json -Encoding UTF8
    }
    else {
      # Legacy path for PS 3.0–4.0 (Set-Content -Encoding not available)
      [System.IO.File]::WriteAllText($localPath, $json, [System.Text.Encoding]::UTF8)
    }
    $script:log.Write("Wrote JSON locally: $localPath")
  } catch {
    $script:log.Write("Failed to write local JSON: $($_.Exception.Message)", 'ERROR'); throw
  }

  if ($EmitStdOut){
    [pscustomobject]@{
      Computer          = $env:COMPUTERNAME
      PlantId           = $PlantId
      HasOldRefs        = $summary.HasOldDomainRefs
      CrowdStrikeTenant = $securityAgents.CrowdStrike.Tenant
      QualysTenant      = $securityAgents.Qualys.Tenant
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
  $script:log.Write("Fatal error: $($_.Exception.Message)", 'ERROR')
  exit 1
}
#endregion