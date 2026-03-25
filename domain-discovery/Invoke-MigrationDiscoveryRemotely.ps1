param(
    [Parameter(Mandatory = $true)]
    [string]$ServerListPath,          # e.g. .\servers.txt

    [string]$ScriptPath = ".\Get-WorkstationDiscovery.ps1",

    # Where the *remote* script writes its local JSON/logs
    [string]$RemoteOutputRoot = "C:\temp\MigrationDiscovery\out",
    [string]$RemoteLogRoot    = "C:\temp\MigrationDiscovery\logs",

    # Optional central share where **you** (the jump host) will collect results
    # If not specified, JSON files remain on the remote servers only
    [string]$CollectorShare,

    # Domain config for your discovery script
    # These can be provided as parameters or loaded from ConfigFile
    [string]$OldDomainFqdn,

    [string]$NewDomainFqdn,

    [string]$OldDomainNetBIOS,
    [string]$NewDomainNetBIOS,

    [string]$PlantId,
    
    [string]$ConfigFile,      # Path to JSON configuration file for domain settings, tenant maps (CrowdStrike, Qualys), and EnCase registry paths
    
    [switch]$EmitStdOut,      # bubble up the summary object from each server
    [switch]$ExcludeConfigFiles,  # skip config file scanning on each remote (faster discovery)
    [switch]$LogTimeMetrics,      # log each discovery phase and duration on the remote
    [switch]$NoDiscoveryTimeouts, # do not apply timeouts to discovery steps on the remote
    [int]$DiscoveryTimeoutSeconds = 0,  # override all discovery timeouts with this value (seconds); ignored if NoDiscoveryTimeouts
    [switch]$UseParallel,     # simple fan-out option
    [switch]$AttemptWinRmHeal, # Optional: attempt to start WinRM service if connection fails (default: false)
    [switch]$UseSmbForResults, # If set, retrieve JSON via \\server\c$ or CollectorShare; default is WinRM return (no SMB)
    [System.Management.Automation.PSCredential]$Credential  # Optional: if not provided, will prompt or use current user
)

# Ensure core cmdlets (Get-Date, Write-Host, Test-Path, Write-Error, etc.) are available in constrained or minimal runspaces.
$null = Import-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue
$null = Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

# PowerShell version compatibility bootstrap
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

# Full (PS 5.1+) path
if ($script:CompatibilityMode -eq 'Full') {
    Set-StrictMode -Version Latest
}
else {
    # Legacy path for PS 3.0–4.0
    Set-StrictMode -Off
}
$ErrorActionPreference = 'Continue'  # Changed to Continue so errors don't stop execution

# Load configuration file early to get domain settings if not provided as parameters
if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile)) {
    try {
        $configContent = Get-Content -Path $ConfigFile -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop
        
        # Load domain settings from config file if not provided as parameters
        if ([string]::IsNullOrWhiteSpace($OldDomainFqdn) -and $config.PSObject.Properties['OldDomainFqdn']) {
            $OldDomainFqdn = $config.OldDomainFqdn
            Write-Host "Loaded OldDomainFqdn from config file: $OldDomainFqdn" -ForegroundColor Cyan
        }
        
        if ([string]::IsNullOrWhiteSpace($NewDomainFqdn) -and $config.PSObject.Properties['NewDomainFqdn']) {
            $NewDomainFqdn = $config.NewDomainFqdn
            Write-Host "Loaded NewDomainFqdn from config file: $NewDomainFqdn" -ForegroundColor Cyan
        }
        
        if ([string]::IsNullOrWhiteSpace($OldDomainNetBIOS) -and $config.PSObject.Properties['OldDomainNetBIOS']) {
            $OldDomainNetBIOS = $config.OldDomainNetBIOS
            Write-Host "Loaded OldDomainNetBIOS from config file: $OldDomainNetBIOS" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Warning "Failed to load configuration file '$ConfigFile': $($_.Exception.Message)"
    }
}

# Validate that required domain parameters are available (either from command line or config file)
if ([string]::IsNullOrWhiteSpace($OldDomainFqdn)) {
    $errorMsg = "OldDomainFqdn is required. Please provide it as a parameter (-OldDomainFqdn) or in the configuration file (ConfigFile parameter)."
    Write-Error $errorMsg
    throw $errorMsg
}

if ([string]::IsNullOrWhiteSpace($NewDomainFqdn)) {
    $errorMsg = "NewDomainFqdn is required. Please provide it as a parameter (-NewDomainFqdn) or in the configuration file (ConfigFile parameter)."
    Write-Error $errorMsg
    throw $errorMsg
}

# Initialize error logging
$script:ErrorLogPath = $null
function Write-ErrorLog {
    param(
        [string]$ServerName,
        [string]$ErrorMessage,
        [string]$ErrorType = "ERROR"
    )
    
    if (-not $script:ErrorLogPath) {
        # Determine script directory
        if ($MyInvocation.PSCommandPath) {
            $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
        }
        elseif ($PSScriptRoot) {
            $scriptDir = $PSScriptRoot
        }
        else {
            $scriptDir = (Get-Location).Path
        }
        
        # Create results directory if it doesn't exist
        $resultsDir = Join-Path $scriptDir "results"
        if (-not (Test-Path -Path $resultsDir)) {
            New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null
        }
        
        $script:ErrorLogPath = Join-Path $resultsDir "error.log"
    }
    
    # Use .NET for timestamp so error logging works even when Get-Date is not available (constrained runspace)
    $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "[$timestamp] [$ServerName] [$ErrorType] $ErrorMessage"

    try {
        Add-Content -Path $script:ErrorLogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        try { Write-Warning "Failed to write to error log: $($_.Exception.Message)" } catch { [Console]::Error.WriteLine("Failed to write to error log") }
        try { Write-Warning $logEntry } catch { [Console]::Error.WriteLine($logEntry) }
    }
}

function Write-DiscoveryScanResultsFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$HostScanRows,
        [string]$ServerListPath,
        [string]$PlantId,
        [string]$OrchestratorNote = 'Invoke-MigrationDiscoveryRemotely.ps1'
    )
    $HostScanRows = @($HostScanRows)
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    $hostObjs = foreach ($row in $HostScanRows) {
        if ($null -eq $row) { continue }
        [ordered]@{
            ServerListEntry             = $row.ServerListEntry
            ResolvedComputerName        = $row.ResolvedComputerName
            Outcome                     = $row.Outcome
            ConnectionErrorCategory     = $row.ConnectionErrorCategory
            JsonFileName                = $row.JsonFileName
            PowerShellVersion           = $row.PowerShellVersion
            CompatibilityMode           = $row.CompatibilityMode
            UnavailableSectionsSummary  = $row.UnavailableSectionsSummary
            ConfigFileIssue             = [bool]($row.ConfigFileIssue)
            DetailMessage               = $row.DetailMessage
        }
    }
    $payload = [ordered]@{
        Schema         = 'DomainMigrationDiscovery.ScanResults/v1'
        Orchestrator   = $OrchestratorNote
        GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
        ServerListPath = $ServerListPath
        PlantId        = if ($PlantId) { $PlantId } else { $null }
        Hosts          = @($hostObjs)
    }
    $outPath = Join-Path $OutputDirectory 'scan_results.json'
    ($payload | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $outPath -Encoding UTF8
    Write-Host "Scan results (all hosts from server list): $outPath" -ForegroundColor Cyan
}

function Merge-ScanRowsWithAllTargets {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServersInOrder,
        [AllowEmptyCollection()]
        [object[]]$ReturnedRows
    )
    $byKey = @{}
    foreach ($row in $ReturnedRows) {
        if ($null -eq $row) { continue }
        $k = $row.ServerListEntry
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $byKey[$k] = $row
    }
    $merged = New-Object System.Collections.ArrayList
    foreach ($s in $ServersInOrder) {
        if ($byKey.ContainsKey($s)) {
            $null = $merged.Add($byKey[$s])
        }
        else {
            $null = $merged.Add([pscustomobject]@{
                    ServerListEntry             = $s
                    ResolvedComputerName        = $null
                    Outcome                     = 'No result recorded (orchestrator did not capture this host)'
                    ConnectionErrorCategory     = $null
                    JsonFileName                = $null
                    PowerShellVersion           = $null
                    CompatibilityMode           = $null
                    UnavailableSectionsSummary  = $null
                    ConfigFileIssue             = $false
                    DetailMessage               = $null
                })
        }
    }
    return ,@($merged.ToArray())
}

if (-not (Test-Path -LiteralPath $ServerListPath)) {
    $errorMsg = "Server list file not found: $ServerListPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

# Read server names (ignore blank/comment lines); de-duplicate preserving first-seen order from the file
$servers = @(
    $seen = @{}
    Get-Content -Path $ServerListPath | ForEach-Object {
        if (-not $_) { return }
        $t = $_.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { return }
        if ($seen.ContainsKey($t)) { return }
        $seen[$t] = $true
        $t
    }
)

if ($servers.Count -eq 0) {
    $errorMsg = "No servers found in list file: $ServerListPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

Write-Host "Targets:" -ForegroundColor Cyan
$servers | ForEach-Object { Write-Host "  $_" }

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    $errorMsg = "Discovery script not found: $ScriptPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

# Get credentials if not provided and needed
if (-not $Credential) {
    $cred = Get-Credential -Message "Enter the account that has local admin rights on all servers (or press Cancel to use current user)"
    if ($cred) {
        $Credential = $cred
    }
    else {
        Write-Host "No credentials provided. Will attempt to use current user context." -ForegroundColor Yellow
        $Credential = $null
    }
}

# Read the script content to pass to remote execution
$scriptContent = Get-Content -Path $ScriptPath -Raw

# Resolve helper module path (same directory as discovery script) and read content for remote staging
$scriptDirForDiscovery = Split-Path (Resolve-Path -LiteralPath $ScriptPath) -Parent
$helperModulePath = Join-Path $scriptDirForDiscovery 'DomainMigrationDiscovery.Helpers.psm1'
if (-not (Test-Path -LiteralPath $helperModulePath)) {
    $errorMsg = "Helper module not found: $helperModulePath. Required for remote discovery."
    Write-Error $errorMsg
    throw $errorMsg
}
$helperModuleContent = Get-Content -Path $helperModulePath -Raw -ErrorAction Stop
$remoteRunDir = "C:\temp\MigrationDiscovery\run"

# Build a hashtable of parameters for the discovery script
$scriptParams = @{
    OutputRoot    = $RemoteOutputRoot
    LogRoot       = $RemoteLogRoot
    OldDomainFqdn = $OldDomainFqdn
    NewDomainFqdn = $NewDomainFqdn
}

if ($OldDomainNetBIOS) { $scriptParams['OldDomainNetBIOS'] = $OldDomainNetBIOS }
# Note: NewDomainNetBIOS is not a parameter in Get-WorkstationDiscovery.ps1, so we explicitly do NOT pass it
# This prevents PowerShell parameter binding errors on remote systems
if ($PlantId)          { $scriptParams['PlantId'] = $PlantId }
# When -PlantID is set, collect JSON under results\<plantid_lower>; otherwise results\out
$localOutputSubdir = if ([string]::IsNullOrWhiteSpace($PlantId)) { "out" } else { $PlantId.Trim().ToLower() }
if ($EmitStdOut)       { $scriptParams['EmitStdOut'] = $true }
if ($ExcludeConfigFiles) { $scriptParams['ExcludeConfigFiles'] = $true }
if ($LogTimeMetrics) { $scriptParams['LogTimeMetrics'] = $true }
if ($NoDiscoveryTimeouts) { $scriptParams['NoDiscoveryTimeouts'] = $true }
if ($DiscoveryTimeoutSeconds -gt 0) { $scriptParams['DiscoveryTimeoutSeconds'] = $DiscoveryTimeoutSeconds }

# Handle ConfigFile parameter
# If ConfigFile is provided, we need to copy it to each remote server
# The config file will be copied to C:\temp\MigrationDiscovery\config.json on each remote server
$remoteConfigPath = $null
if ($ConfigFile) {
    if (-not (Test-Path -LiteralPath $ConfigFile)) {
        Write-Warning "Configuration file not found: $ConfigFile. ConfigFile parameter will be ignored."
    }
    else {
        # Set the remote path where the config file will be copied
        $remoteConfigPath = "C:\temp\MigrationDiscovery\config.json"
        $scriptParams['ConfigFile'] = $remoteConfigPath
        Write-Host "ConfigFile will be copied to each remote server at: $remoteConfigPath" -ForegroundColor Cyan
    }
}

# Helper function to categorize WinRM/Invoke-Command errors
function Get-WinRmFailureCategory {
    param(
        [Parameter(Mandatory)]
        [string]$ErrorMessage,
        
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    # Returns one of: 'AuthError','NetworkError','WinRmServiceError','Unknown'
    
    # Authentication errors - do not attempt to heal
    if ($ErrorMessage -match 'access is denied' -or
        $ErrorMessage -match '401' -or
        $ErrorMessage -match '403' -or
        $ErrorMessage -match 'unauthorized' -or
        $ErrorMessage -match 'authentication failed' -or
        $ErrorMessage -match 'Kerberos' -or
        $ErrorMessage -match 'NTLM' -or
        $ErrorMessage -match 'credential' -or
        $ErrorRecord.CategoryInfo.Category -eq 'AuthenticationError' -or
        $ErrorRecord.CategoryInfo.Category -eq 'SecurityError')
    {
        return 'AuthError'
    }
    
    # Network/name resolution errors - do not attempt to heal
    if ($ErrorMessage -match 'WinRM cannot complete the operation' -or
        $ErrorMessage -match 'The network path was not found' -or
        $ErrorMessage -match 'No connection could be made' -or
        $ErrorMessage -match 'cannot resolve' -or
        $ErrorMessage -match 'host.*not found' -or
        $ErrorMessage -match 'RPC server is unavailable' -or
        $ErrorMessage -match 'network is unreachable' -or
        $ErrorRecord.CategoryInfo.Category -eq 'InvalidOperation' -and $ErrorMessage -match 'network')
    {
        return 'NetworkError'
    }
    
    # WinRM service errors - these are candidates for healing
    if ($ErrorMessage -match 'WinRM service' -or
        $ErrorMessage -match 'The WinRM client cannot process the request' -or
        $ErrorMessage -match 'WS-Management service' -or
        $ErrorMessage -match 'service.*not running' -or
        ($ErrorMessage -match 'cannot connect' -and $ErrorMessage -match 'WinRM') -or
        $ErrorRecord.Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException] -or
        $ErrorRecord.FullyQualifiedErrorId -match 'WinRM')
    {
        return 'WinRmServiceError'
    }
    
    return 'Unknown'
}

# Centralized WinRM connectivity helper
# This function handles all WinRM connectivity testing, error classification, optional healing, and remote script execution
#
# WinRM Auto-Heal Behavior:
# - When -AttemptWinRmHeal is NOT provided: Tests WinRM connectivity once. If it fails, logs the error and returns.
# - When -AttemptWinRmHeal IS provided: Tests WinRM connectivity. If it fails with a WinRM service error (not auth/network),
#   attempts to start the WinRM service on the remote system (PS 5.1: Get-Service/Set-Service -ComputerName; PS 6+: Get-CimInstance/Invoke-CimMethod)
#   After starting the service, waits 5 seconds, verifies the service is running, then retries the connectivity test once.
#   Authentication errors and network errors are never healed - only WinRM service errors are candidates for healing.
#
# Error Classification:
# - AuthError: Authentication/authorization failures (access denied, 401, credentials, etc.) - never healed
# - NetworkError: Network/name resolution failures (host unreachable, DNS failure, etc.) - never healed  
# - WinRmServiceError: WinRM service not running, listener unavailable, WinRM-specific faults - can be healed if -AttemptWinRmHeal is set
# - Unknown: Unclassified errors - can be healed if -AttemptWinRmHeal is set (treated as potential WinRM service issues)
function Ensure-WinRmAndConnect {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [scriptblock]$RemoteScriptBlock,
        
        [array]$RemoteScriptArguments = @(),
        
        [switch]$AttemptWinRmHeal,
        
        [System.Management.Automation.PSCredential]$Credential,
        
        [scriptblock]$WriteErrorLogFunction,

        # When set, skip the initial connectivity test and run the remote scriptblock directly.
        # Use when the caller has already established WinRM (e.g. same session after config copy).
        [switch]$SkipConnectivityTest,

        # When SkipConnectivityTest is set, optionally provide the actual computer name from a prior test.
        [string]$ActualComputerNameFromPriorTest = $null
    )
    
    # Result object to return
    $result = @{
        Success = $false
        ErrorCategory = $null
        ErrorMessage = $null
        Output = $null
        ActualComputerName = $null
    }
    
    # Step 1: Initial WinRM connectivity check (skip if caller already established connectivity)
    $connectivityTestPassed = $false
    $actualComputerName = $ActualComputerNameFromPriorTest

    if ($SkipConnectivityTest) {
        $connectivityTestPassed = $true
        if (-not $actualComputerName) { $actualComputerName = $ComputerName }
    }
    else {
    Write-Host "[$ComputerName] Testing WinRM connectivity..." -ForegroundColor Yellow
    try {
        $testParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = { $env:COMPUTERNAME }
            ErrorAction  = 'Stop'
        }
        if ($Credential) {
            $testParams['Credential'] = $Credential
        }
        
        # Add connection timeout to prevent hangs (PowerShell 5.1+) - OperationTimeout is in milliseconds
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30000
        }
        
        $testResult = Invoke-Command @testParams
        $actualComputerName = $testResult
        $connectivityTestPassed = $true
        Write-Host "[$ComputerName] WinRM connectivity successful (remote computer: $testResult)" -ForegroundColor Green
    }
    catch {
        $initialError = $_.Exception.Message
        $errorRecord = $_
        
        # Step 2: Classify the error
        $failureCategory = Get-WinRmFailureCategory -ErrorMessage $initialError -ErrorRecord $errorRecord
        
        # Log the categorized error (detailed message to log, brief to console)
        $errorMsg = "WinRM connectivity failed - categorized as $failureCategory. Error: $initialError"
        Write-Warning "[$ComputerName] WinRM failed: $failureCategory"
        if ($WriteErrorLogFunction) {
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
        }
        
        # Step 3: Handle based on error category
        
        # Authentication errors - do not attempt to heal
        if ($failureCategory -eq 'AuthError') {
            $result.ErrorCategory = 'AuthError'
            $result.ErrorMessage = $errorMsg
            return $result
        }
        
        # Network/name resolution errors - do not attempt to heal
        if ($failureCategory -eq 'NetworkError') {
            $result.ErrorCategory = 'NetworkError'
            $result.ErrorMessage = $errorMsg
            return $result
        }
        
        # WinRM service errors (or Unknown) - attempt heal only if requested
        if ($failureCategory -eq 'WinRmServiceError' -or $failureCategory -eq 'Unknown') {
            if (-not $AttemptWinRmHeal) {
                $errorMsg = "WinRM is not available and healing is disabled. Category: $failureCategory. Error: $initialError"
                Write-Warning "[$ComputerName] WinRM unavailable (healing disabled)"
                if ($WriteErrorLogFunction) {
                    & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
                }
                $result.ErrorCategory = $failureCategory
                $result.ErrorMessage = $errorMsg
                return $result
            }
            
            # Step 4: Attempt to start WinRM service on remote computer
            # PS 5.1: Get-Service/Set-Service support -ComputerName. PS 6+ (Core/7): -ComputerName removed; use CIM.
            Write-Host "[$ComputerName] Attempting to start WinRM service on remote computer..." -ForegroundColor Yellow
            $serviceStarted = $false

            try {
                if ($PSVersionTable.PSVersion.Major -le 5) {
                    # Windows PowerShell 5.1: use *-Service -ComputerName
                    $service = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                    if ($service.Status -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service is already running." -ForegroundColor Green
                        $serviceStarted = $true
                    }
                    else {
                        Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running -ErrorAction Stop
                        Start-Sleep -Seconds 10
                        $serviceCheck = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                        if ($serviceCheck.Status -eq 'Running') {
                            Write-Host "[$ComputerName] WinRM service successfully started; retrying WinRM connectivity..." -ForegroundColor Green
                            $serviceStarted = $true
                        }
                        else {
                            $errorMsg = "WinRM heal failed; service not running after attempt. Status: $($serviceCheck.Status)"
                            Write-Warning "[$ComputerName] WinRM heal failed"
                            if ($WriteErrorLogFunction) {
                                & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "WINRM_HEAL_ERROR"
                            }
                            $result.ErrorCategory = $failureCategory
                            $result.ErrorMessage = $errorMsg
                            return $result
                        }
                    }
                }
                else {
                    # PowerShell 6+ (Core/7): -ComputerName removed from *-Service; use CIM (works on Windows)
                    $cimParams = @{
                        ClassName    = 'Win32_Service'
                        Filter       = "Name='winrm'"
                        ComputerName = $ComputerName
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $cimParams['Credential'] = $Credential }
                    $svc = Get-CimInstance @cimParams
                    if ($svc.State -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service is already running." -ForegroundColor Green
                        $serviceStarted = $true
                    }
                    else {
                        $null = Invoke-CimMethod -InputObject $svc -MethodName StartService -ErrorAction Stop
                        Start-Sleep -Seconds 10
                        $svcCheck = Get-CimInstance @cimParams
                        if ($svcCheck.State -eq 'Running') {
                            Write-Host "[$ComputerName] WinRM service successfully started; retrying WinRM connectivity..." -ForegroundColor Green
                            $serviceStarted = $true
                        }
                        else {
                            $errorMsg = "WinRM heal failed; service not running after attempt. State: $($svcCheck.State)"
                            Write-Warning "[$ComputerName] WinRM heal failed"
                            if ($WriteErrorLogFunction) {
                                & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "WINRM_HEAL_ERROR"
                            }
                            $result.ErrorCategory = $failureCategory
                            $result.ErrorMessage = $errorMsg
                            return $result
                        }
                    }
                }
            }
            catch {
                $serviceError = $_.Exception.Message
                $errorMsg = "Failed to start WinRM service: $serviceError"
                Write-Warning "[$ComputerName] WinRM service start failed"
                if ($WriteErrorLogFunction) {
                    & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "WINRM_HEAL_ERROR"
                }
                $result.ErrorCategory = $failureCategory
                $result.ErrorMessage = $errorMsg
                return $result
            }
            
            # Step 5: Retry WinRM connectivity after healing
            if ($serviceStarted) {
                Write-Host "[$ComputerName] Retrying WinRM connectivity test..." -ForegroundColor Yellow
                try {
                    $testParams = @{
                        ComputerName = $ComputerName
                        ScriptBlock  = { $env:COMPUTERNAME }
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) {
                        $testParams['Credential'] = $Credential
                    }
                    
                    if ($PSVersionTable.PSVersion.Major -ge 5) {
                        $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30000
                    }
                    
                    $testResult = Invoke-Command @testParams
                    $actualComputerName = $testResult
                    $connectivityTestPassed = $true
                    Write-Host "[$ComputerName] WinRM connectivity successful after heal (remote computer: $testResult)" -ForegroundColor Green
                }
                catch {
                    $retryError = $_.Exception.Message
                    $errorMsg = "WinRM connection failed after attempting to start service. Initial error: $initialError. Retry error: $retryError"
                    Write-Warning "[$ComputerName] WinRM retry failed"
                    if ($WriteErrorLogFunction) {
                        & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
                    }
                    $result.ErrorCategory = $failureCategory
                    $result.ErrorMessage = $errorMsg
                    return $result
                }
            }
        }
    }
    }
    
    # Step 6: If connectivity test passed, run the main remote script
    if (-not $connectivityTestPassed) {
        $errorMsg = "WinRM connectivity failed: Unable to establish connection"
        Write-Warning "[$ComputerName] WinRM connection failed"
        if ($WriteErrorLogFunction) {
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
        }
        $result.ErrorCategory = 'Unknown'
        $result.ErrorMessage = $errorMsg
        return $result
    }
    
    # Execute the remote script block
    try {
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $RemoteScriptBlock
            ErrorAction  = 'Stop'
        }
        
        if ($Credential) {
            $invokeParams['Credential'] = $Credential
        }
        
        # Add connection timeout (PowerShell 5.1+) - OperationTimeout is in milliseconds (300000 = 5 min)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout 300000
        }
        
        # Add arguments if provided
        # ArgumentList expects an array matching the scriptblock's param() parameters in order
        if ($RemoteScriptArguments -and $RemoteScriptArguments.Count -gt 0) {
            $invokeParams['ArgumentList'] = $RemoteScriptArguments
        }
        
        $output = Invoke-Command @invokeParams
        
        $result.Success = $true
        $result.Output = $output
        $result.ActualComputerName = $actualComputerName
        
        return $result
    }
    catch {
        $execError = $_.Exception.Message
        $errorMsg = "Failed to execute remote script: $execError"
        Write-Warning "[$ComputerName] Script execution failed"
        if ($WriteErrorLogFunction) {
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "SCRIPT_EXECUTION_ERROR"
        }
        $result.ErrorCategory = 'Unknown'
        $result.ErrorMessage = $errorMsg
        return $result
    }
}

# Helper: run discovery on a single server
# Converted to scriptblock for parallel execution compatibility
# This scriptblock now uses the centralized Ensure-WinRmAndConnect helper for all WinRM operations
$InvokeDiscoveryOnServerScriptBlock = {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ScriptContent,
        [hashtable]$ScriptParams,
        [string]$CollectorShare,
        [string]$RemoteOutputRoot,
        [string]$RemoteLogRoot,
        [scriptblock]$WriteErrorLogFunction,
        [scriptblock]$EnsureWinRmAndConnectFunction,
        [string]$ConfigFile,
        [string]$RemoteConfigPath,
        [string]$CompatibilityMode,
        [switch]$AttemptWinRmHeal,
        [string]$HelperModuleContent,
        [string]$RemoteRunDir,
        [switch]$UseSmbForResults,
        [string]$LocalOutputSubdir
    )

    $scan = [ordered]@{
        ServerListEntry             = $ComputerName
        ResolvedComputerName        = $null
        Outcome                     = 'Unknown'
        ConnectionErrorCategory     = $null
        JsonFileName                = $null
        PowerShellVersion           = $null
        CompatibilityMode           = $null
        UnavailableSectionsSummary  = $null
        ConfigFileIssue             = $false
        DetailMessage               = $null
    }

    function Apply-DiscoveryBytesToScanRow {
        param([byte[]]$Bytes, [string]$JsonFileName, $ScanRow)
        if ($JsonFileName) { $ScanRow['JsonFileName'] = $JsonFileName }
        try {
            $jtxt = [System.Text.Encoding]::UTF8.GetString($Bytes)
            $j = $jtxt | ConvertFrom-Json
            $meta = $j.Metadata
            if ($meta) {
                $ScanRow['ResolvedComputerName'] = $meta.ComputerName
                $ScanRow['PowerShellVersion'] = [string]$meta.PowerShellVersion
                $ScanRow['CompatibilityMode'] = [string]$meta.CompatibilityMode
                $us = $meta.UnavailableSections
                if ($null -ne $us) {
                    if ($us -is [System.Array] -and $us.Count -gt 0) {
                        $ScanRow['UnavailableSectionsSummary'] = ($us | ForEach-Object { [string]$_ }) -join '; '
                    }
                    elseif ($us -is [string] -and $us.Trim() -ne '') {
                        $ScanRow['UnavailableSectionsSummary'] = $us
                    }
                }
                $compat = [string]$meta.CompatibilityMode
                if ($compat -eq 'Legacy3to4') {
                    $ScanRow['Outcome'] = 'Partial success (PowerShell 3/4 — limited sections)'
                }
                elseif ($ScanRow['UnavailableSectionsSummary']) {
                    $ScanRow['Outcome'] = 'Partial success (some sections not collected)'
                }
                else {
                    $ScanRow['Outcome'] = 'Fully successful'
                }
            }
            else {
                $ScanRow['Outcome'] = 'Fully successful'
                $ScanRow['DetailMessage'] = 'Collected JSON has no Metadata section.'
            }
        }
        catch {
            $ScanRow['Outcome'] = 'Fully successful'
            if (-not $ScanRow['DetailMessage']) {
                $ScanRow['DetailMessage'] = "Could not parse discovery JSON metadata: $($_.Exception.Message)"
            }
        }
    }

    function Apply-DiscoveryFileToScanRow {
        param([string]$Path, $ScanRow)
        if (-not (Test-Path -LiteralPath $Path)) {
            $ScanRow['Outcome'] = 'JSON collection failed (file missing after copy)'
            $ScanRow['DetailMessage'] = "Expected JSON not found at $Path"
            return
        }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $fn = [System.IO.Path]::GetFileName($Path)
        Apply-DiscoveryBytesToScanRow -Bytes $bytes -JsonFileName $fn -ScanRow $ScanRow
    }

    # Ensure core cmdlets (Get-Date, Write-Host, Test-Path, etc.) are available when this block runs in a thread-job runspace (PS 7 parallel).
    $null = Import-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue
    $null = Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

    # Determine compatibility mode locally (don't rely on script-level variables)
    if (-not $CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $CompatibilityMode = 'Full'
        } else {
            $CompatibilityMode = 'Legacy3to4'
        }
    }
    
    # Step 1: Establish WinRM connectivity using the centralized helper
    # First, test connectivity with a simple scriptblock to get the actual computer name
    $testScriptBlock = { $env:COMPUTERNAME }
    $testResult = & $EnsureWinRmAndConnectFunction `
        -ComputerName $ComputerName `
        -RemoteScriptBlock $testScriptBlock `
        -RemoteScriptArguments @() `
        -AttemptWinRmHeal:$AttemptWinRmHeal `
        -Credential $Credential `
        -WriteErrorLogFunction $WriteErrorLogFunction
    
    # Check if WinRM connectivity succeeded
    if (-not $testResult.Success) {
        $scan['ConnectionErrorCategory'] = $testResult.ErrorCategory
        $scan['Outcome'] = 'Could not connect (WinRM)'
        $scan['DetailMessage'] = $testResult.ErrorMessage
        return ([pscustomobject]$scan)
    }
    
    $actualComputerName = $testResult.ActualComputerName
    $scan['ResolvedComputerName'] = $actualComputerName

    # Step 2: Copy config file to remote server if provided (requires WinRM connectivity)
    if ($ConfigFile -and $RemoteConfigPath) {
        Write-Host "[$ComputerName] Copying configuration file to remote server..." -ForegroundColor Yellow
        try {
            # Create remote directory if it doesn't exist
            $remoteConfigDir = Split-Path -Parent $RemoteConfigPath
            $createDirParams = @{
                ComputerName = $ComputerName
                ScriptBlock  = {
                    param($DirPath)
                    if (-not (Test-Path -Path $DirPath)) {
                        New-Item -Path $DirPath -ItemType Directory -Force | Out-Null
                    }
                }
                ArgumentList = @($remoteConfigDir)
                ErrorAction  = 'Stop'
            }
            if ($Credential) {
                $createDirParams['Credential'] = $Credential
            }
            Invoke-Command @createDirParams | Out-Null
            
            # Copy the config file to remote server
            $sessionParams = @{
                ComputerName = $ComputerName
            }
            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }
            $session = New-PSSession @sessionParams
            
            try {
                Copy-Item -Path $ConfigFile -Destination $RemoteConfigPath -ToSession $session -Force -ErrorAction Stop
                Write-Host "[$ComputerName] Configuration file copied successfully" -ForegroundColor Green
            }
            catch {
                $errorMsg = "Failed to copy configuration file: $($_.Exception.Message)"
                Write-Warning "[$ComputerName] Config file copy failed"
                & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONFIG_FILE_ERROR"
                # Continue execution - the discovery script will run without config file
                $null = $ScriptParams.Remove('ConfigFile')
                $scan['ConfigFileIssue'] = $true
            }
            finally {
                if ($session) {
                    try {
                        Remove-PSSession $session -ErrorAction SilentlyContinue
                    }
                    catch {
                        & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage "Failed to remove PSSession: $($_.Exception.Message)" -ErrorType "WARNING"
                    }
                }
            }
        }
        catch {
            $errorMsg = "Failed to prepare remote directory for config file: $($_.Exception.Message)"
            Write-Warning "[$ComputerName] Config file setup failed"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONFIG_FILE_ERROR"
            # Continue execution - the discovery script will run without config file
            $null = $ScriptParams.Remove('ConfigFile')
            $scan['ConfigFileIssue'] = $true
        }
    }

    # Step 3: Run the discovery script using the centralized helper
    # WinRM connectivity is already established
    Write-Host "[$ComputerName] Starting discovery..." -ForegroundColor Cyan

    if (-not $UseSmbForResults) {
        # WinRM-return path: stage script + helper, run from path, read JSON, return gzip+base64 over WinRM
        $remoteScriptBlock = {
            param($HelperModuleContent, $RemoteRunDir, $ScriptContent, $ScriptParams, $RemoteOutputRoot, $RemoteLogRoot)
            $ErrorActionPreference = 'Stop'
            try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } catch { }
            if (-not (Test-Path -LiteralPath $RemoteRunDir)) {
                New-Item -Path $RemoteRunDir -ItemType Directory -Force | Out-Null
            }
            $scriptPath = Join-Path $RemoteRunDir 'Get-WorkstationDiscovery.ps1'
            $modulePath = Join-Path $RemoteRunDir 'DomainMigrationDiscovery.Helpers.psm1'
            [System.IO.File]::WriteAllText($scriptPath, $ScriptContent)
            [System.IO.File]::WriteAllText($modulePath, $HelperModuleContent)
            Push-Location $RemoteRunDir
            try {
                & ".\Get-WorkstationDiscovery.ps1" @ScriptParams
            } finally {
                Pop-Location
            }
            $jsonPath = Join-Path $RemoteOutputRoot ("{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date).ToString('MM-dd-yyyy'))
            if (-not (Test-Path -LiteralPath $jsonPath)) {
                throw "Discovery ran but JSON file not found: $jsonPath"
            }
            $bytes = [System.IO.File]::ReadAllBytes($jsonPath)
            $ms = New-Object System.IO.MemoryStream
            $gzip = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
            $gzip.Write($bytes, 0, $bytes.Length)
            $gzip.Close()
            $b64 = [Convert]::ToBase64String($ms.ToArray())
            $logFileName = $null
            $logPayload = $null
            if ($RemoteLogRoot -and (Test-Path -LiteralPath $RemoteLogRoot)) {
                $logPattern = "discovery_$env:COMPUTERNAME_*.log"
                $logFiles = Get-ChildItem -Path $RemoteLogRoot -Filter $logPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
                if ($logFiles) {
                    $logPath = $logFiles[0].FullName
                    $logFileName = [System.IO.Path]::GetFileName($logPath)
                    $logBytes = [System.IO.File]::ReadAllBytes($logPath)
                    $logMs = New-Object System.IO.MemoryStream
                    $logGzip = New-Object System.IO.Compression.GzipStream($logMs, [System.IO.Compression.CompressionMode]::Compress)
                    $logGzip.Write($logBytes, 0, $logBytes.Length)
                    $logGzip.Close()
                    $logPayload = [Convert]::ToBase64String($logMs.ToArray())
                }
            }
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                JsonFileName = [System.IO.Path]::GetFileName($jsonPath)
                JsonPath     = $jsonPath
                Encoding     = 'gzip+base64'
                Payload      = $b64
                LogFileName  = $logFileName
                LogPayload   = $logPayload
            }
        }
        $remoteScriptArguments = @($HelperModuleContent, $RemoteRunDir, $ScriptContent, $ScriptParams, $RemoteOutputRoot, $RemoteLogRoot)
        $discoveryResult = & $EnsureWinRmAndConnectFunction `
            -ComputerName $ComputerName `
            -RemoteScriptBlock $remoteScriptBlock `
            -RemoteScriptArguments $remoteScriptArguments `
            -AttemptWinRmHeal:$false `
            -Credential $Credential `
            -WriteErrorLogFunction $WriteErrorLogFunction `
            -SkipConnectivityTest `
            -ActualComputerNameFromPriorTest $actualComputerName

        if (-not $discoveryResult.Success) {
            $scan['Outcome'] = 'Discovery failed (remote execution)'
            $scan['DetailMessage'] = $discoveryResult.ErrorMessage
            return ([pscustomobject]$scan)
        }

        $payloadObj = $discoveryResult.Output
        if (-not $payloadObj -or -not $payloadObj.Payload) {
            $errorMsg = "Discovery ran but no JSON payload returned from $ComputerName"
            Write-Warning "[$ComputerName] No JSON payload returned"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
            $scan['Outcome'] = 'JSON not returned over WinRM'
            $scan['DetailMessage'] = $errorMsg
            return ([pscustomobject]$scan)
        }

        try {
            $compressed = [Convert]::FromBase64String($payloadObj.Payload)
            $in = New-Object System.IO.MemoryStream(,$compressed)
            $gzip = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            $out = New-Object System.IO.MemoryStream
            $gzip.CopyTo($out)
            $gzip.Close()
            $decodedBytes = $out.ToArray()

            if ($MyInvocation.PSCommandPath) { $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath }
            elseif ($PSScriptRoot) { $scriptDir = $PSScriptRoot }
            else { $scriptDir = (Get-Location).Path }
            $localOutputRoot = Join-Path $scriptDir "results\$LocalOutputSubdir"
            if (-not (Test-Path -Path $localOutputRoot)) {
                New-Item -Path $localOutputRoot -ItemType Directory -Force | Out-Null
            }
            $localPath = Join-Path $localOutputRoot $payloadObj.JsonFileName
            [System.IO.File]::WriteAllBytes($localPath, $decodedBytes)
            Write-Host "[$ComputerName] Received JSON over WinRM and wrote $localPath" -ForegroundColor Green
            Apply-DiscoveryBytesToScanRow -Bytes $decodedBytes -JsonFileName $payloadObj.JsonFileName -ScanRow $scan

            # Copy discovery log to results\log if returned
            if ($payloadObj.LogFileName -and $payloadObj.LogPayload) {
                try {
                    $logCompressed = [Convert]::FromBase64String($payloadObj.LogPayload)
                    $logIn = New-Object System.IO.MemoryStream(,$logCompressed)
                    $logGzip = New-Object System.IO.Compression.GzipStream($logIn, [System.IO.Compression.CompressionMode]::Decompress)
                    $logOut = New-Object System.IO.MemoryStream
                    $logGzip.CopyTo($logOut)
                    $logGzip.Close()
                    $logDecodedBytes = $logOut.ToArray()
                    $logDir = Join-Path $scriptDir "results\log"
                    if (-not (Test-Path -Path $logDir)) {
                        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                    }
                    $localLogPath = Join-Path $logDir $payloadObj.LogFileName
                    [System.IO.File]::WriteAllBytes($localLogPath, $logDecodedBytes)
                    Write-Host "[$ComputerName] Discovery log saved to $localLogPath" -ForegroundColor Green
                }
                catch {
                    Write-Warning "[$ComputerName] Failed to save discovery log: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $errorMsg = "Failed to decode JSON payload from $ComputerName : $($_.Exception.Message)"
            Write-Warning "[$ComputerName] Failed to decode JSON payload"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
            $scan['Outcome'] = 'JSON decode or save failed'
            $scan['DetailMessage'] = $errorMsg
            return ([pscustomobject]$scan)
        }

        # Optional: best-effort cleanup of staged files on remote
        try {
            $cleanupBlock = {
                param($RunDir)
                if (Test-Path -LiteralPath $RunDir) {
                    Remove-Item -LiteralPath (Join-Path $RunDir 'Get-WorkstationDiscovery.ps1') -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath (Join-Path $RunDir 'DomainMigrationDiscovery.Helpers.psm1') -Force -ErrorAction SilentlyContinue
                }
            }
            $cleanupParams = @{ ComputerName = $ComputerName; ScriptBlock = $cleanupBlock; ArgumentList = @($RemoteRunDir); ErrorAction = 'SilentlyContinue' }
            if ($Credential) { $cleanupParams['Credential'] = $Credential }
            Invoke-Command @cleanupParams | Out-Null
        }
        catch {
            # Ignore cleanup failures
        }

        Write-Host "[$ComputerName] Discovery completed." -ForegroundColor Green
        return ([pscustomobject]$scan)
    }

    # SMB/legacy path: stage script + helper and run from path (so helper module loads), then collect via CollectorShare or \\server\c$
    $remoteScriptBlock = {
        param($HelperModuleContent, $RemoteRunDir, $ScriptContent, $ScriptParams)
        $ErrorActionPreference = 'Stop'
        try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } catch { }
        if (-not (Test-Path -LiteralPath $RemoteRunDir)) {
            New-Item -Path $RemoteRunDir -ItemType Directory -Force | Out-Null
        }
        $scriptPath = Join-Path $RemoteRunDir 'Get-WorkstationDiscovery.ps1'
        $modulePath = Join-Path $RemoteRunDir 'DomainMigrationDiscovery.Helpers.psm1'
        [System.IO.File]::WriteAllText($scriptPath, $ScriptContent)
        [System.IO.File]::WriteAllText($modulePath, $HelperModuleContent)
        Push-Location $RemoteRunDir
        try {
            & ".\Get-WorkstationDiscovery.ps1" @ScriptParams
        } finally {
            Pop-Location
        }
    }
    $remoteScriptArguments = @($HelperModuleContent, $RemoteRunDir, $ScriptContent, $ScriptParams)
    $discoveryResult = & $EnsureWinRmAndConnectFunction `
        -ComputerName $ComputerName `
        -RemoteScriptBlock $remoteScriptBlock `
        -RemoteScriptArguments $remoteScriptArguments `
        -AttemptWinRmHeal:$false `
        -Credential $Credential `
        -WriteErrorLogFunction $WriteErrorLogFunction `
        -SkipConnectivityTest `
        -ActualComputerNameFromPriorTest $actualComputerName

    if (-not $discoveryResult.Success) {
        $scan['Outcome'] = 'Discovery failed (remote execution)'
        $scan['DetailMessage'] = $discoveryResult.ErrorMessage
        return ([pscustomobject]$scan)
    }

    $summary = $discoveryResult.Output
    $shouldEmitStdOut = $ScriptParams.ContainsKey('EmitStdOut') -and $ScriptParams['EmitStdOut'] -eq $true
    if ($summary -and $shouldEmitStdOut) {
        Write-Host "[$ComputerName] Summary:" -ForegroundColor Green
        $summary | ConvertTo-Json -Depth 4
    }

    $today = Get-Date
    $pattern = "{0}_{1}.json" -f $actualComputerName, $today.ToString('MM-dd-yyyy')
    $remotePath = Join-Path $RemoteOutputRoot $pattern

    if ($CollectorShare) {
        # Copy to specified collector share
        Write-Host "[$ComputerName] Collecting JSON from remote OutputRoot ($RemoteOutputRoot)..." -ForegroundColor Yellow

        # Create a session so we can copy files
        $sessionParams = @{
            ComputerName = $ComputerName
        }
        if ($Credential) {
            $sessionParams['Credential'] = $Credential
        }
        $session = New-PSSession @sessionParams

        try {
            if (-not (Test-Path -Path $CollectorShare)) {
                New-Item -Path $CollectorShare -ItemType Directory -Force | Out-Null
            }

            $destPath = Join-Path $CollectorShare $pattern

            Copy-Item -Path $remotePath -Destination $destPath -FromSession $session -Force -ErrorAction Stop

            Write-Host "[$ComputerName] Copied $remotePath -> $destPath" -ForegroundColor Green
            Apply-DiscoveryFileToScanRow -Path $destPath -ScanRow $scan

            # Copy discovery log to results\log
            if ($RemoteLogRoot) {
                try {
                    $getLogPathBlock = { param($LogRoot) $p = "discovery_$env:COMPUTERNAME_*.log"; $f = Get-ChildItem -Path $LogRoot -Filter $p -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { $f.FullName } }
                    $remoteLogPath = @(Invoke-Command -Session $session -ScriptBlock $getLogPathBlock -ArgumentList $RemoteLogRoot -ErrorAction SilentlyContinue)[0]
                    if ($remoteLogPath) {
                        if ($MyInvocation.PSCommandPath) { $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath }
                        elseif ($PSScriptRoot) { $scriptDir = $PSScriptRoot }
                        else { $scriptDir = (Get-Location).Path }
                        $logDir = Join-Path $scriptDir "results\log"
                        if (-not (Test-Path -Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
                        $logFileName = [System.IO.Path]::GetFileName($remoteLogPath)
                        $localLogPath = Join-Path $logDir $logFileName
                        Copy-Item -Path $remoteLogPath -Destination $localLogPath -FromSession $session -Force -ErrorAction Stop
                        Write-Host "[$ComputerName] Discovery log saved to $localLogPath" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "[$ComputerName] Failed to copy discovery log: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $errorMsg = "Failed to collect JSON from CollectorShare: $($_.Exception.Message)"
            Write-Warning "[$ComputerName] JSON collection failed"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
            $scan['Outcome'] = 'JSON collection failed (collector share)'
            $scan['DetailMessage'] = $errorMsg
            if ($session) {
                try { Remove-PSSession $session -ErrorAction SilentlyContinue }
                catch { & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage "Failed to remove PSSession: $($_.Exception.Message)" -ErrorType "WARNING" }
            }
            return ([pscustomobject]$scan)
        }
        finally {
            if ($session) { 
                try {
                    Remove-PSSession $session -ErrorAction SilentlyContinue
                }
                catch {
                    & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage "Failed to remove PSSession: $($_.Exception.Message)" -ErrorType "WARNING"
                }
            }
        }
    }
    else {
        # Copy to local directory structure mirroring remote path
        Write-Host "[$ComputerName] Collecting JSON from remote C$ admin share..." -ForegroundColor Yellow

        try {
            # Get the directory where this script is located
            if ($MyInvocation.PSCommandPath) {
                $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
            }
            elseif ($PSScriptRoot) {
                $scriptDir = $PSScriptRoot
            }
            else {
                $scriptDir = (Get-Location).Path
            }

            # Create local directory structure: {ScriptDir}\results\<out|plantid>
            $localOutputRoot = Join-Path $scriptDir "results\$LocalOutputSubdir"
            if (-not (Test-Path -Path $localOutputRoot)) {
                New-Item -Path $localOutputRoot -ItemType Directory -Force | Out-Null
            }

            # Build UNC path to remote admin share
            # Extract drive letter and convert to UNC path (e.g., C:\temp\... -> \\ComputerName\c$\temp\...)
            if ($RemoteOutputRoot -match '^([A-Z]):\\(.*)$') {
                $driveLetter = $matches[1].ToLower()
                $relativePath = $matches[2]
                $remoteUncPath = "\\$ComputerName\${driveLetter}$\$relativePath"
            }
            else {
                # Fallback: assume C: drive
                $remoteUncPath = $RemoteOutputRoot -replace '^C:', "\\$ComputerName\c$"
            }
            $remoteUncFile = Join-Path $remoteUncPath $pattern
            $localDestPath = Join-Path $localOutputRoot $pattern

            # Copy file using UNC path with credentials if provided
            if ($Credential) {
                # Extract drive letter to determine which admin share to use
                if ($RemoteOutputRoot -match '^([A-Z]):\\(.*)$') {
                    $driveLetter = $matches[1].ToLower()
                    $relativePath = $matches[2]
                }
                else {
                    # Fallback: assume C: drive
                    $driveLetter = "c"
                    $relativePath = $RemoteOutputRoot -replace '^C:\\', ''
                }
                
                # Use New-PSDrive to map the remote admin share with credentials
                $driveName = "TempDrive_$($ComputerName -replace '[^a-zA-Z0-9]', '')"
                try {
                    $psDriveParams = @{
                        Name = $driveName
                        PSProvider = "FileSystem"
                        Root = "\\$ComputerName\$driveLetter`$"
                        Credential = $Credential
                        Scope = "Script"
                    }
                    $null = New-PSDrive @psDriveParams -ErrorAction Stop
                    
                    try {
                        # Map the remote path using the temporary drive
                        $mappedRemotePath = "${driveName}:$relativePath"
                        $mappedRemoteFile = Join-Path $mappedRemotePath $pattern
                        Copy-Item -Path $mappedRemoteFile -Destination $localDestPath -Force -ErrorAction Stop
                    }
                    finally {
                        try {
                            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                        }
                        catch {
                            $errorMsg = "Failed to remove PSDrive $driveName`: $($_.Exception.Message)"
                            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "WARNING"
                        }
                    }
                }
                catch {
                    $errorMsg = "Failed to access remote ${driveLetter}`$ share: $($_.Exception.Message)"
                    & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
                    throw
                }
            }
            else {
                # No credentials - try direct UNC copy (uses current user context)
                Copy-Item -Path $remoteUncFile -Destination $localDestPath -Force -ErrorAction Stop
            }

            Write-Host "[$ComputerName] Copied $remoteUncFile -> $localDestPath" -ForegroundColor Green
            Apply-DiscoveryFileToScanRow -Path $localDestPath -ScanRow $scan

            # Copy discovery log to results\log via temporary session
            if ($RemoteLogRoot) {
                try {
                    $sessionParams = @{ ComputerName = $ComputerName }
                    if ($Credential) { $sessionParams['Credential'] = $Credential }
                    $logSession = New-PSSession @sessionParams -ErrorAction Stop
                    try {
                        $getLogPathBlock = { param($LogRoot) $p = "discovery_$env:COMPUTERNAME_*.log"; $f = Get-ChildItem -Path $LogRoot -Filter $p -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { $f.FullName } }
                        $remoteLogPath = @(Invoke-Command -Session $logSession -ScriptBlock $getLogPathBlock -ArgumentList $RemoteLogRoot -ErrorAction SilentlyContinue)[0]
                        if ($remoteLogPath) {
                            $logDir = Join-Path $scriptDir "results\log"
                            if (-not (Test-Path -Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
                            $logFileName = [System.IO.Path]::GetFileName($remoteLogPath)
                            $localLogPath = Join-Path $logDir $logFileName
                            Copy-Item -Path $remoteLogPath -Destination $localLogPath -FromSession $logSession -Force -ErrorAction Stop
                            Write-Host "[$ComputerName] Discovery log saved to $localLogPath" -ForegroundColor Green
                        }
                    }
                    finally {
                        Remove-PSSession $logSession -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-Warning "[$ComputerName] Failed to copy discovery log: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $errorMsg = "Failed to collect JSON from C$ share: $($_.Exception.Message)"
            Write-Warning "[$ComputerName] JSON collection failed"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
            Write-Host "[$ComputerName] JSON file is available on the remote server at: $remotePath" -ForegroundColor Cyan
            $scan['Outcome'] = 'JSON collection failed (admin share)'
            $scan['DetailMessage'] = $errorMsg
            return ([pscustomobject]$scan)
        }
    }
    
    Write-Host "[$ComputerName] Discovery completed." -ForegroundColor Green
    return ([pscustomobject]$scan)
}

# Initialize error log path early so it's available for summary
if (-not $script:ErrorLogPath) {
    if ($MyInvocation.PSCommandPath) {
        $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
    }
    elseif ($PSScriptRoot) {
        $scriptDir = $PSScriptRoot
    }
    else {
        $scriptDir = (Get-Location).Path
    }
    $resultsDir = Join-Path $scriptDir "results"
    if (-not (Test-Path -Path $resultsDir)) {
        New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null
    }
    $script:ErrorLogPath = Join-Path $resultsDir "error.log"
}

Write-Host "`nStarting discovery on $($servers.Count) server(s)..." -ForegroundColor Cyan

# Create scriptblocks for functions to pass to parallel execution
$writeErrorLogScriptBlock = ${function:Write-ErrorLog}
$ensureWinRmAndConnectScriptBlock = ${function:Ensure-WinRmAndConnect}

$collectedScanRows = New-Object System.Collections.ArrayList

# --- Execution: parallel (PS 7+ only when ThreadJob available) or sequential ---
# PS 5.1 and non-parallel: always use the sequential path below. Parallel is only used when
# -UseParallel is set AND PS version is 7+ AND Start-ThreadJob/Wait-Job/Remove-Job are present
# (so PS 5.1 and constrained runspaces never call ThreadJob and remain fully compatible).
$useParallelThreadJob = $false
$parallelFailed = $false
if ($UseParallel -and $script:CompatibilityMode -eq 'Full' -and $script:PSMajorVersion -ge 7) {
    $startThreadJobCmd = Get-Command Start-ThreadJob -ErrorAction SilentlyContinue
    $waitJobCmd         = Get-Command Wait-Job -ErrorAction SilentlyContinue
    $removeJobCmd       = Get-Command Remove-Job -ErrorAction SilentlyContinue
    if ($startThreadJobCmd -and $waitJobCmd -and $removeJobCmd) {
        $useParallelThreadJob = $true
    }
}

if ($useParallelThreadJob) {
    # Parallel path: invoke ThreadJob via command object (avoids "term not recognized" in some hosts).
    # Wrapped in try/catch so any failure (serialization, cmdlet, etc.) falls back to sequential.
    $parallelFailed = $false
    try {
        $throttleLimit = 10
        $running = New-Object System.Collections.ArrayList
        foreach ($server in $servers) {
            while ($running.Count -ge $throttleLimit) {
                $completed = @($running | Where-Object { $_.State -ne 'Running' })
                foreach ($j in $completed) { $null = $running.Remove($j) }
                if ($running.Count -ge $throttleLimit) { Start-Sleep -Milliseconds 100 }
            }
            $job = & $startThreadJobCmd -ScriptBlock $InvokeDiscoveryOnServerScriptBlock -ArgumentList @(
                $server,
                $Credential,
                $scriptContent,
                $scriptParams,
                $CollectorShare,
                $RemoteOutputRoot,
                $RemoteLogRoot,
                $writeErrorLogScriptBlock,
                $ensureWinRmAndConnectScriptBlock,
                $ConfigFile,
                $remoteConfigPath,
                $script:CompatibilityMode,
                [bool]$AttemptWinRmHeal.IsPresent,
                $helperModuleContent,
                $remoteRunDir,
                [bool]$UseSmbForResults.IsPresent,
                $localOutputSubdir
            )
            $null = $running.Add($job)
        }
        $jobArray = @($running)
        if ($jobArray.Count -gt 0) {
            & $waitJobCmd -Job $jobArray | Out-Null
            foreach ($jb in $jobArray) {
                $received = Receive-Job -Job $jb -ErrorAction SilentlyContinue
                foreach ($o in @($received)) {
                    if ($null -eq $o) { continue }
                    $pnames = @($o.PSObject.Properties | ForEach-Object { $_.Name })
                    if ($pnames -contains 'ServerListEntry') {
                        $null = $collectedScanRows.Add($o)
                    }
                }
            }
            & $removeJobCmd -Job $jobArray -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        $parallelFailed = $true
        Write-Warning "Parallel execution failed: $($_.Exception.Message). Falling back to sequential execution."
    }
}

if (-not $useParallelThreadJob -or $parallelFailed) {
    # Sequential path: PS 5.1 (with or without -UseParallel), PS 3–4, ThreadJob not available, or parallel failed
    $collectedScanRows = New-Object System.Collections.ArrayList
    if ($parallelFailed) {
        Write-Host "Running discovery sequentially after parallel failure." -ForegroundColor Yellow
    }
    elseif ($UseParallel) {
        Write-Host "Parallel execution requires PowerShell 7+ with Start-ThreadJob. Using sequential execution." -ForegroundColor Yellow
    }
    elseif ($script:CompatibilityMode -ne 'Full') {
        Write-Host "Parallel execution is not available in PowerShell versions below 5.1. Using sequential execution." -ForegroundColor Yellow
    }
    foreach ($server in $servers) {
        try {
            $oneRow = & $InvokeDiscoveryOnServerScriptBlock `
                -ComputerName $server `
                -Credential $Credential `
                -ScriptContent $scriptContent `
                -ScriptParams $scriptParams `
                -CollectorShare $CollectorShare `
                -RemoteOutputRoot $RemoteOutputRoot `
                -RemoteLogRoot $RemoteLogRoot `
                -WriteErrorLogFunction $writeErrorLogScriptBlock `
                -EnsureWinRmAndConnectFunction $ensureWinRmAndConnectScriptBlock `
                -ConfigFile $ConfigFile `
                -RemoteConfigPath $remoteConfigPath `
                -CompatibilityMode $script:CompatibilityMode `
                -AttemptWinRmHeal:$AttemptWinRmHeal `
                -HelperModuleContent $helperModuleContent `
                -RemoteRunDir $remoteRunDir `
                -UseSmbForResults:$UseSmbForResults `
                -LocalOutputSubdir $localOutputSubdir
            if ($oneRow) { $null = $collectedScanRows.Add($oneRow) }
        }
        catch {
            $errorMsg = "Unexpected error processing server: $($_.Exception.Message)"
            & $writeErrorLogScriptBlock -ServerName $server -ErrorMessage $errorMsg -ErrorType "FATAL"
            Write-Warning "[$server] Unexpected error (see error log)"
            $null = $collectedScanRows.Add([pscustomobject]@{
                    ServerListEntry             = $server
                    ResolvedComputerName        = $null
                    Outcome                     = 'Unexpected orchestrator error'
                    ConnectionErrorCategory     = $null
                    JsonFileName                = $null
                    PowerShellVersion           = $null
                    CompatibilityMode           = $null
                    UnavailableSectionsSummary  = $null
                    ConfigFileIssue             = $false
                    DetailMessage               = $errorMsg
                })
        }
    }
}

$orchestratorScriptDir = if ($MyInvocation.PSCommandPath) {
    Split-Path -Parent $MyInvocation.PSCommandPath
}
elseif ($PSScriptRoot) { $PSScriptRoot }
else { (Get-Location).Path }
$localResultsOutputRoot = Join-Path $orchestratorScriptDir "results\$localOutputSubdir"
$mergedScanRows = Merge-ScanRowsWithAllTargets -ServersInOrder $servers -ReturnedRows @($collectedScanRows.ToArray())
$listPathForReport = $ServerListPath
try { $listPathForReport = (Resolve-Path -LiteralPath $ServerListPath -ErrorAction Stop).Path } catch { }
Write-DiscoveryScanResultsFile `
    -OutputDirectory $localResultsOutputRoot `
    -HostScanRows $mergedScanRows `
    -ServerListPath $listPathForReport `
    -PlantId $PlantId

# Display summary
Write-Host "`n" + ("="*70) -ForegroundColor Cyan
Write-Host "Discovery execution completed." -ForegroundColor Green
if ($script:ErrorLogPath -and (Test-Path -LiteralPath $script:ErrorLogPath)) {
    $lineCount = Get-Content -LiteralPath $script:ErrorLogPath -ErrorAction SilentlyContinue | Measure-Object -Line
    $errorCount = if ($lineCount.Lines) { $lineCount.Lines } else { 0 }
    if ($errorCount -gt 0) {
        Write-Host "Errors were encountered during execution. Check error log:" -ForegroundColor Yellow
        Write-Host "  ${script:ErrorLogPath}" -ForegroundColor Yellow
        Write-Host "  Total error entries: $errorCount" -ForegroundColor Yellow
    }
    else {
        Write-Host "No errors encountered. Error log: ${script:ErrorLogPath}" -ForegroundColor Green
    }
}
Write-Host ("="*70) -ForegroundColor Cyan
