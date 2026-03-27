#Requires -Version 7.0
<#
.SYNOPSIS
    PS7-only orchestrator for migration discovery: runs discovery on multiple servers in parallel via New-PSSession + Invoke-Command fan-out.

.DESCRIPTION
    Same behavior and output as Invoke-MigrationDiscoveryRemotely.ps1 (PS5.1), but requires PowerShell 7+
    and uses New-PSSession/Invoke-Command fan-out with ThrottleLimit for speed. Produces identical JSON
    files (same names, paths, content). Writes a separate PS7 orchestrator summary report; does not alter
    existing error.log behavior. Do not use on PS5.1; use Invoke-MigrationDiscoveryRemotely.ps1 instead.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerListPath,          # e.g. .\servers.txt

    [string]$ScriptPath = ".\Get-WorkstationDiscovery.ps1",

    # Where the *remote* script writes its local JSON/logs
    [string]$RemoteOutputRoot = "C:\temp\MigrationDiscovery\out",
    [string]$RemoteLogRoot    = "C:\temp\MigrationDiscovery\logs",

    # Optional central share where **you** (the jump host) will collect results
    [string]$CollectorShare,

    # Domain config for your discovery script
    [string]$OldDomainFqdn,
    [string]$NewDomainFqdn,
    [string]$OldDomainNetBIOS,
    [string]$NewDomainNetBIOS,
    [string]$PlantId,

    [string]$ConfigFile,      # Path to JSON configuration file for domain settings, tenant maps, etc.

    [switch]$EmitStdOut,
    [switch]$ExcludeConfigFiles,
    [switch]$LogTimeMetrics,
    [switch]$NoDiscoveryTimeouts,
    [int]$DiscoveryTimeoutSeconds = 0,
    [switch]$AttemptWinRmHeal, # Optional: not applied in PS7 parallel mode (documented only)
    [switch]$UseSmbForResults, # If set, retrieve JSON via \\server\c$ or CollectorShare; default is WinRM return

    [int]$ThrottleLimit = 10,

    [System.Management.Automation.PSCredential]$Credential
)

# --- PS7-only guard: error early on PS5.1 ---
if (-not $PSVersionTable -or $PSVersionTable.PSVersion.Major -lt 7) {
    $msg = "This script requires PowerShell 7 or higher. Use Invoke-MigrationDiscoveryRemotely.ps1 for PowerShell 5.1."
    Write-Error $msg
    throw $msg
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Per-host failure stage tracking (never abort whole run)
$script:SessionCreateFailed = [System.Collections.ArrayList]::new()
# ErrorRecord (or exception) per server when New-PSSession fails (for Resolve-RemoteGatheringFailure)
$script:SessionCreateErrorByServer = @{}
$script:InvokeFailed        = [System.Collections.ArrayList]::new()
$script:CollectFailed      = [System.Collections.ArrayList]::new()
$script:SuccessHosts       = [System.Collections.ArrayList]::new()
$script:SuccessJsonByListEntry = @{}

# Load configuration file early (same as PS5.1 orchestrator)
if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile)) {
    try {
        $configContent = Get-Content -Path $ConfigFile -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop

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

# --- Error logging (same path/format as PS5.1; do not alter behavior) ---
$script:ErrorLogPath = $null
function Write-ErrorLog {
    param(
        [string]$ServerName,
        [string]$ErrorMessage,
        [string]$ErrorType = "ERROR"
    )
    if (-not $script:ErrorLogPath) {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $resultsDir = Join-Path $scriptDir "results"
        if (-not (Test-Path -Path $resultsDir)) { New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null }
        $script:ErrorLogPath = Join-Path $resultsDir "error.log"
    }
    $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "[$timestamp] [$ServerName] [$ErrorType] $ErrorMessage"
    try { Add-Content -Path $script:ErrorLogPath -Value $logEntry -ErrorAction SilentlyContinue }
    catch { Write-Warning "Failed to write to error log: $($_.Exception.Message)" }
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
        [string]$OrchestratorNote = 'Invoke-MigrationDiscoveryRemotely.PS7.ps1'
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
            FailureReasonCode           = $row.FailureReasonCode
            FailureReasonSummary        = $row.FailureReasonSummary
            TechnicalDetail             = $row.TechnicalDetail
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
    $merged = [System.Collections.ArrayList]::new()
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
                    FailureReasonCode           = $null
                    FailureReasonSummary        = $null
                    TechnicalDetail             = $null
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

function Get-InvokeResultListKey {
    param([object]$R)
    if (-not $R) { return $null }
    $k = $R.PSComputerName
    if ($null -ne $k -and "$k".Trim() -ne '') { return "$k".Trim() }
    return [string]$R.ComputerName
}

if (-not (Test-Path -LiteralPath $ServerListPath)) {
    $errorMsg = "Server list file not found: $ServerListPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

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

if (-not $Credential) {
    $cred = Get-Credential -Message "Enter the account that has local admin rights on all servers (or press Cancel to use current user)"
    if ($cred) { $Credential = $cred }
    else { Write-Host "No credentials provided. Will attempt to use current user context." -ForegroundColor Yellow }
}

$scriptContent = Get-Content -Path $ScriptPath -Raw
$scriptDirForDiscovery = Split-Path (Resolve-Path -LiteralPath $ScriptPath) -Parent
$helperModulePath = Join-Path $scriptDirForDiscovery 'DomainMigrationDiscovery.Helpers.psm1'
if (-not (Test-Path -LiteralPath $helperModulePath)) {
    $errorMsg = "Helper module not found: $helperModulePath. Required for remote discovery."
    Write-Error $errorMsg
    throw $errorMsg
}
$helperModuleContent = Get-Content -Path $helperModulePath -Raw -ErrorAction Stop
$remotingFailuresModulePath = Join-Path $scriptDirForDiscovery 'DomainMigrationDiscovery.RemotingFailures.psm1'
if (-not (Test-Path -LiteralPath $remotingFailuresModulePath)) {
    $errorMsg = "Remoting failures module not found: $remotingFailuresModulePath. Required for remote discovery."
    Write-Error $errorMsg
    throw $errorMsg
}
$null = Import-Module $remotingFailuresModulePath -Force -ErrorAction Stop
$remoteRunDir = "C:\temp\MigrationDiscovery\run"

# Build scriptParams for discovery script (identical to PS5.1 / Truth Map)
$scriptParams = @{
    OutputRoot    = $RemoteOutputRoot
    LogRoot       = $RemoteLogRoot
    OldDomainFqdn = $OldDomainFqdn
    NewDomainFqdn = $NewDomainFqdn
}
if ($OldDomainNetBIOS) { $scriptParams['OldDomainNetBIOS'] = $OldDomainNetBIOS }
if ($PlantId)          { $scriptParams['PlantId'] = $PlantId }
if ($EmitStdOut)       { $scriptParams['EmitStdOut'] = $true }
if ($ExcludeConfigFiles) { $scriptParams['ExcludeConfigFiles'] = $true }
if ($LogTimeMetrics) { $scriptParams['LogTimeMetrics'] = $true }
if ($NoDiscoveryTimeouts) { $scriptParams['NoDiscoveryTimeouts'] = $true }
if ($DiscoveryTimeoutSeconds -gt 0) { $scriptParams['DiscoveryTimeoutSeconds'] = $DiscoveryTimeoutSeconds }

$remoteConfigPath = $null
$configFileContent = $null
if ($ConfigFile) {
    if (-not (Test-Path -LiteralPath $ConfigFile)) {
        Write-Warning "Configuration file not found: $ConfigFile. ConfigFile parameter will be ignored."
    }
    else {
        $remoteConfigPath = "C:\temp\MigrationDiscovery\config.json"
        $scriptParams['ConfigFile'] = $remoteConfigPath
        $configFileContent = Get-Content -Path $ConfigFile -Raw -ErrorAction Stop
        Write-Host "ConfigFile will be copied to each remote server at: $remoteConfigPath" -ForegroundColor Cyan
    }
}

# Initialize results dir and error log path (same as PS5.1)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$resultsDir = Join-Path $scriptDir "results"
if (-not (Test-Path -Path $resultsDir)) { New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null }
$script:ErrorLogPath = Join-Path $resultsDir "error.log"
# When -PlantID is set, collect JSON under results\<plantid_lower>; otherwise results\out
$localOutputSubdir = if ([string]::IsNullOrWhiteSpace($PlantId)) { "out" } else { $PlantId.Trim().ToLower() }

# Remote scriptblock: staging + discovery + return payload or success (Truth Map exact)
$remoteDiscoveryScriptBlock = {
    param(
        [string]$HelperModuleContent,
        [string]$RemoteRunDir,
        [string]$ScriptContent,
        [string]$ParamOutputRoot,
        [string]$ParamLogRoot,
        [string]$ParamOldDomainFqdn,
        [string]$ParamNewDomainFqdn,
        [string]$ParamOldDomainNetBIOS,
        [string]$ParamPlantId,
        [bool]$ParamEmitStdOut,
        [bool]$ParamExcludeConfigFiles,
        [bool]$ParamLogTimeMetrics,
        [bool]$ParamNoDiscoveryTimeouts,
        [int]$ParamDiscoveryTimeoutSeconds,
        [string]$ParamConfigFile,
        [string]$RemoteOutputRoot,
        [string]$RemoteLogRoot,
        [string]$ConfigContent,
        [bool]$UseSmbForResults
    )
    $ErrorActionPreference = 'Stop'
    try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue } catch { }

    if (-not (Test-Path -LiteralPath $RemoteRunDir)) {
        New-Item -Path $RemoteRunDir -ItemType Directory -Force | Out-Null
    }
    $scriptPath = Join-Path $RemoteRunDir 'Get-WorkstationDiscovery.ps1'
    $modulePath = Join-Path $RemoteRunDir 'DomainMigrationDiscovery.Helpers.psm1'
    [System.IO.File]::WriteAllText($scriptPath, $ScriptContent)
    [System.IO.File]::WriteAllText($modulePath, $HelperModuleContent)

    if (-not [string]::IsNullOrWhiteSpace($ConfigContent)) {
        $configPath = Join-Path (Split-Path -Parent $RemoteRunDir) 'config.json'
        $configDir = Split-Path -Parent $configPath
        if (-not (Test-Path -LiteralPath $configDir)) { New-Item -Path $configDir -ItemType Directory -Force | Out-Null }
        [System.IO.File]::WriteAllText($configPath, $ConfigContent)
    }

    # Reconstruct real [hashtable] from individual parameters for splatting
    $ScriptParams = @{
        OutputRoot    = $ParamOutputRoot
        LogRoot       = $ParamLogRoot
        OldDomainFqdn = $ParamOldDomainFqdn
        NewDomainFqdn = $ParamNewDomainFqdn
    }
    if ($ParamOldDomainNetBIOS)          { $ScriptParams['OldDomainNetBIOS'] = $ParamOldDomainNetBIOS }
    if ($ParamPlantId)                   { $ScriptParams['PlantId'] = $ParamPlantId }
    if ($ParamEmitStdOut)                { $ScriptParams['EmitStdOut'] = $true }
    if ($ParamExcludeConfigFiles)        { $ScriptParams['ExcludeConfigFiles'] = $true }
    if ($ParamLogTimeMetrics)            { $ScriptParams['LogTimeMetrics'] = $true }
    if ($ParamNoDiscoveryTimeouts)       { $ScriptParams['NoDiscoveryTimeouts'] = $true }
    if ($ParamDiscoveryTimeoutSeconds -gt 0) { $ScriptParams['DiscoveryTimeoutSeconds'] = $ParamDiscoveryTimeoutSeconds }
    if ($ParamConfigFile)                { $ScriptParams['ConfigFile'] = $ParamConfigFile }

    Push-Location $RemoteRunDir
    try {
        & ".\Get-WorkstationDiscovery.ps1" @ScriptParams
    }
    catch {
        Pop-Location
        return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Success = $false; ErrorMessage = $_.Exception.Message }
    }
    Pop-Location

    if ($UseSmbForResults) {
        return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Success = $true }
    }

    $jsonPath = Join-Path $RemoteOutputRoot ("{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date).ToString('MM-dd-yyyy'))
    if (-not (Test-Path -LiteralPath $jsonPath)) {
        return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Success = $false; ErrorMessage = "Discovery ran but JSON file not found: $jsonPath" }
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
        Success      = $true
    }
}

if ($AttemptWinRmHeal) {
    Write-Host "Note: AttemptWinRmHeal is not applied in PS7 parallel mode (single fan-out)." -ForegroundColor Yellow
}

Write-Host "`nStarting discovery on $($servers.Count) server(s) (ThrottleLimit=$ThrottleLimit)..." -ForegroundColor Cyan

# --- Phase: Session creation (bulk New-PSSession in main runspace) ---
$sessionOption = New-PSSessionOption -OperationTimeout 300000
$sessionParams = @{
    ComputerName  = $servers
    SessionOption = $sessionOption
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'sessionCreateErrors'
}
if ($Credential) { $sessionParams['Credential'] = $Credential }
$sessions = @(New-PSSession @sessionParams)
$connectedComputers = @($sessions | ForEach-Object { $_.ComputerName })

foreach ($err in $sessionCreateErrors) {
    $targetName = $null
    if ($err.TargetObject -is [string]) { $targetName = $err.TargetObject }
    elseif ($err.CategoryInfo -and $err.CategoryInfo.TargetName) { $targetName = $err.CategoryInfo.TargetName }
    if (-not $targetName -and $err.Exception.Message -match '(?:computer name[:\s]+|Connecting to remote server\s+)(\S+)') { $targetName = $Matches[1] }
    if (-not $targetName) { $targetName = 'UNKNOWN' }
    $null = $script:SessionCreateFailed.Add($targetName)
    $script:SessionCreateErrorByServer[$targetName] = $err
    $resolved = Resolve-RemoteGatheringFailure -ErrorRecord $err -Stage SessionCreate -ComputerName $targetName
    Write-Warning "[$targetName] $($resolved.FailureReasonSummary)"
    Write-ErrorLog -ServerName $targetName -ErrorMessage "$($resolved.FailureReasonSummary) | $($resolved.TechnicalDetail)" -ErrorType "CONNECTION_ERROR"
}

# --- Phase: Invoke (discovery on all sessions) ---
$allResults = @()
if ($sessions.Count -gt 0) {
    try {
        $allResults = Invoke-Command -Session $sessions -ScriptBlock $remoteDiscoveryScriptBlock -ArgumentList @(
            $helperModuleContent,
            $remoteRunDir,
            $scriptContent,
            $RemoteOutputRoot,          # ParamOutputRoot (same as scriptParams.OutputRoot)
            $RemoteLogRoot,             # ParamLogRoot (same as scriptParams.LogRoot)
            $OldDomainFqdn,             # ParamOldDomainFqdn
            $NewDomainFqdn,             # ParamNewDomainFqdn
            $(if ($OldDomainNetBIOS) { $OldDomainNetBIOS } else { '' }),  # ParamOldDomainNetBIOS
            $(if ($PlantId) { $PlantId } else { '' }),                     # ParamPlantId
            [bool]$EmitStdOut.IsPresent,           # ParamEmitStdOut
            [bool]$ExcludeConfigFiles.IsPresent,   # ParamExcludeConfigFiles
            [bool]$LogTimeMetrics.IsPresent,       # ParamLogTimeMetrics
            [bool]$NoDiscoveryTimeouts.IsPresent,  # ParamNoDiscoveryTimeouts
            $DiscoveryTimeoutSeconds,              # ParamDiscoveryTimeoutSeconds
            $(if ($remoteConfigPath) { $remoteConfigPath } else { '' }),  # ParamConfigFile
            $RemoteOutputRoot,          # RemoteOutputRoot (for JSON path construction)
            $RemoteLogRoot,             # RemoteLogRoot (for log collection)
            $(if ($configFileContent) { $configFileContent } else { '' }),  # ConfigContent
            [bool]$UseSmbForResults.IsPresent      # UseSmbForResults
        ) -ThrottleLimit $ThrottleLimit -ErrorAction Continue
    }
    catch {
        Write-Warning "Invoke-Command reported an error (see error log)"
    }
    finally {
        Remove-PSSession -Session $sessions -Force -ErrorAction SilentlyContinue
    }
}

if ($allResults -and -not ($allResults -is [array])) { $allResults = @($allResults) }

# --- Phase: Collection (Truth Map: same method as PS5.1) ---
$localOutputRoot = Join-Path $scriptDir "results\$localOutputSubdir"
if (-not (Test-Path -Path $localOutputRoot)) { New-Item -Path $localOutputRoot -ItemType Directory -Force | Out-Null }

if (-not $UseSmbForResults) {
    foreach ($r in $allResults) {
        if (-not $r) { continue }
        $listKey = Get-InvokeResultListKey -R $r
        if (-not $r.Success) {
            $ex = [System.Exception]::new([string]$r.ErrorMessage)
            $er = [System.Management.Automation.ErrorRecord]::new($ex, 'RemoteDiscovery', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
            $ir = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage RemoteInvoke -ComputerName $listKey
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $r.ComputerName; ErrorMessage = $ir.TechnicalDetail; FailureReasonCode = $ir.FailureReasonCode; FailureReasonSummary = $ir.FailureReasonSummary })
            Write-Warning "[$listKey] $($ir.FailureReasonSummary)"
            Write-ErrorLog -ServerName $listKey -ErrorMessage "$($ir.FailureReasonSummary) | $($ir.TechnicalDetail)" -ErrorType "SCRIPT_EXECUTION_ERROR"
            continue
        }
        if (-not $r.Payload) {
            $npEx = [System.Exception]::new("Discovery ran but no JSON payload returned from $listKey")
            $npEr = [System.Management.Automation.ErrorRecord]::new($npEx, 'NoJsonPayload', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
            $npRes = Resolve-RemoteGatheringFailure -ErrorRecord $npEr -Stage PayloadDecode -ComputerName $listKey
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $r.ComputerName; ErrorMessage = $npRes.TechnicalDetail; FailureReasonCode = $npRes.FailureReasonCode; FailureReasonSummary = $npRes.FailureReasonSummary })
            Write-Warning "[$listKey] $($npRes.FailureReasonSummary)"
            Write-ErrorLog -ServerName $listKey -ErrorMessage "$($npRes.FailureReasonSummary) | $($npRes.TechnicalDetail)" -ErrorType "FILE_COLLECTION_ERROR"
            continue
        }
        try {
            $compressed = [Convert]::FromBase64String($r.Payload)
            $in = New-Object System.IO.MemoryStream(,$compressed)
            $gzip = New-Object System.IO.Compression.GzipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            $out = New-Object System.IO.MemoryStream
            $gzip.CopyTo($out)
            $gzip.Close()
            $decodedBytes = $out.ToArray()
            $localPath = Join-Path $localOutputRoot $r.JsonFileName
            [System.IO.File]::WriteAllBytes($localPath, $decodedBytes)
            $null = $script:SuccessHosts.Add($listKey)
            $script:SuccessJsonByListEntry[$listKey] = $r.JsonFileName
            Write-Host "[$listKey] Wrote $localPath" -ForegroundColor Green
            if ($r.LogFileName -and $r.LogPayload) {
                try {
                    $logCompressed = [Convert]::FromBase64String($r.LogPayload)
                    $logIn = New-Object System.IO.MemoryStream(,$logCompressed)
                    $logGzip = New-Object System.IO.Compression.GzipStream($logIn, [System.IO.Compression.CompressionMode]::Decompress)
                    $logOut = New-Object System.IO.MemoryStream
                    $logGzip.CopyTo($logOut)
                    $logGzip.Close()
                    $logDecodedBytes = $logOut.ToArray()
                    $logDir = Join-Path $scriptDir "results\log"
                    if (-not (Test-Path -Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
                    $localLogPath = Join-Path $logDir $r.LogFileName
                    [System.IO.File]::WriteAllBytes($localLogPath, $logDecodedBytes)
                    Write-Host "[$listKey] Discovery log saved to $localLogPath" -ForegroundColor Green
                }
                catch {
                    Write-Warning "[$listKey] Failed to save discovery log: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $decRes = Resolve-RemoteGatheringFailure -ErrorRecord $_ -Stage PayloadDecode -ComputerName $listKey
            $null = $script:CollectFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $r.ComputerName; ErrorMessage = $decRes.TechnicalDetail; FailureReasonCode = $decRes.FailureReasonCode; FailureReasonSummary = $decRes.FailureReasonSummary })
            Write-Warning "[$listKey] $($decRes.FailureReasonSummary)"
            Write-ErrorLog -ServerName $listKey -ErrorMessage "$($decRes.FailureReasonSummary) | $($decRes.TechnicalDetail)" -ErrorType "FILE_COLLECTION_ERROR"
        }
    }
}

if ($UseSmbForResults -and $allResults) {
    $successful = @($allResults | Where-Object { $_.Success -and $_.ComputerName })
    $todayStr = (Get-Date).ToString('MM-dd-yyyy')

    foreach ($r in $allResults) {
        if (-not $r -or -not $r.ComputerName) { continue }
        $listKey = Get-InvokeResultListKey -R $r
        if (-not $r.Success) {
            $invErr = if ($r.ErrorMessage) { $r.ErrorMessage } else { "Invoke failed" }
            $ex = [System.Exception]::new([string]$invErr)
            $er = [System.Management.Automation.ErrorRecord]::new($ex, 'RemoteDiscovery', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
            $ir = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage RemoteInvoke -ComputerName $listKey
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $r.ComputerName; ErrorMessage = $ir.TechnicalDetail; FailureReasonCode = $ir.FailureReasonCode; FailureReasonSummary = $ir.FailureReasonSummary })
            Write-ErrorLog -ServerName $listKey -ErrorMessage "$($ir.FailureReasonSummary) | $($ir.TechnicalDetail)" -ErrorType "SCRIPT_EXECUTION_ERROR"
            continue
        }
    }

    foreach ($r in $successful) {
        $listKey = Get-InvokeResultListKey -R $r
        $remoteNetbios = [string]$r.ComputerName
        $pattern = "${remoteNetbios}_${todayStr}.json"
        $remotePath = Join-Path $RemoteOutputRoot $pattern

        if ($CollectorShare) {
            if (-not (Test-Path -Path $CollectorShare)) { New-Item -Path $CollectorShare -ItemType Directory -Force | Out-Null }
            $destPath = Join-Path $CollectorShare $pattern
            try {
                $sessionParams = @{ ComputerName = $listKey }
                if ($Credential) { $sessionParams['Credential'] = $Credential }
                $session = New-PSSession @sessionParams
                try {
                    Copy-Item -Path $remotePath -Destination $destPath -FromSession $session -Force -ErrorAction Stop
                    $null = $script:SuccessHosts.Add($listKey)
                    $script:SuccessJsonByListEntry[$listKey] = $pattern
                    Write-Host "[$listKey] Copied to $destPath" -ForegroundColor Green
                    if ($RemoteLogRoot) {
                        try {
                            $getLogPathBlock = { param($LogRoot) $p = "discovery_$env:COMPUTERNAME_*.log"; $f = Get-ChildItem -Path $LogRoot -Filter $p -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { $f.FullName } }
                            $remoteLogPath = @(Invoke-Command -Session $session -ScriptBlock $getLogPathBlock -ArgumentList $RemoteLogRoot -ErrorAction SilentlyContinue)[0]
                            if ($remoteLogPath) {
                                $logDir = Join-Path $scriptDir "results\log"
                                if (-not (Test-Path -Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
                                $logFileName = [System.IO.Path]::GetFileName($remoteLogPath)
                                $localLogPath = Join-Path $logDir $logFileName
                                Copy-Item -Path $remoteLogPath -Destination $localLogPath -FromSession $session -Force -ErrorAction Stop
                                Write-Host "[$computerName] Discovery log saved to $localLogPath" -ForegroundColor Green
                            }
                        }
                        catch { Write-Warning "[$listKey] Failed to copy discovery log: $($_.Exception.Message)" }
                    }
                }
                finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
            }
            catch {
                $fcRes = Resolve-RemoteGatheringFailure -ErrorRecord $_ -Stage FileCollection -ComputerName $listKey
                $null = $script:CollectFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $remoteNetbios; ErrorMessage = $fcRes.TechnicalDetail; FailureReasonCode = $fcRes.FailureReasonCode; FailureReasonSummary = $fcRes.FailureReasonSummary })
                Write-Warning "[$listKey] $($fcRes.FailureReasonSummary)"
                Write-ErrorLog -ServerName $listKey -ErrorMessage "$($fcRes.FailureReasonSummary) | $($fcRes.TechnicalDetail)" -ErrorType "FILE_COLLECTION_ERROR"
            }
        }
        else {
            $localDestPath = Join-Path $localOutputRoot $pattern
            if ($RemoteOutputRoot -match '^([A-Z]):\\(.*)$') {
                $driveLetter = $matches[1].ToLower()
                $relativePath = $matches[2]
                $remoteUncPath = "\\$listKey\${driveLetter}$\$relativePath"
            }
            else { $remoteUncPath = $RemoteOutputRoot -replace '^C:', "\\$listKey\c$" }
            $remoteUncFile = Join-Path $remoteUncPath $pattern
            try {
                if ($Credential) {
                    $driveName = "TempDrive_$($listKey -replace '[^a-zA-Z0-9]', '')"
                    $driveLetter = if ($RemoteOutputRoot -match '^([A-Z]):') { $matches[1].ToLower() } else { 'c' }
                    $relativePath = if ($RemoteOutputRoot -match '^[A-Z]:\\(.*)$') { $matches[1] } else { $RemoteOutputRoot -replace '^C:\\', '' }
                    $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$listKey\$driveLetter`$" -Credential $Credential -Scope Script -ErrorAction Stop
                    try {
                        $mappedRemoteFile = "${driveName}:\$relativePath\$pattern"
                        Copy-Item -Path $mappedRemoteFile -Destination $localDestPath -Force -ErrorAction Stop
                    }
                    finally { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
                }
                else {
                    Copy-Item -Path $remoteUncFile -Destination $localDestPath -Force -ErrorAction Stop
                }
                $null = $script:SuccessHosts.Add($listKey)
                $script:SuccessJsonByListEntry[$listKey] = $pattern
                Write-Host "[$listKey] Copied $remoteUncFile -> $localDestPath" -ForegroundColor Green
                if ($RemoteLogRoot) {
                    try {
                        $sessionParams = @{ ComputerName = $listKey }
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
                                Write-Host "[$listKey] Discovery log saved to $localLogPath" -ForegroundColor Green
                            }
                        }
                        finally { Remove-PSSession $logSession -ErrorAction SilentlyContinue }
                    }
                    catch { Write-Warning "[$listKey] Failed to copy discovery log: $($_.Exception.Message)" }
                }
            }
            catch {
                $fcRes = Resolve-RemoteGatheringFailure -ErrorRecord $_ -Stage FileCollection -ComputerName $listKey
                $null = $script:CollectFailed.Add([pscustomobject]@{ ServerListEntry = $listKey; ComputerName = $remoteNetbios; ErrorMessage = $fcRes.TechnicalDetail; FailureReasonCode = $fcRes.FailureReasonCode; FailureReasonSummary = $fcRes.FailureReasonSummary })
                Write-Warning "[$listKey] $($fcRes.FailureReasonSummary)"
                Write-ErrorLog -ServerName $listKey -ErrorMessage "$($fcRes.FailureReasonSummary) | $($fcRes.TechnicalDetail)" -ErrorType "FILE_COLLECTION_ERROR"
            }
        }
    }
}

# Invoke ran but no result returned (e.g. session died during Invoke-Command)
$returnedComputers = @(
    $allResults | Where-Object { $_ } | ForEach-Object {
        Get-InvokeResultListKey -R $_
    }
)
foreach ($m in $servers) {
    if ($m -in $connectedComputers -and $m -notin $returnedComputers) {
        $nrEx = [System.Exception]::new("No result object returned from Invoke-Command for this host.")
        $nrEr = [System.Management.Automation.ErrorRecord]::new($nrEx, 'NoInvokeResult', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
        $nrRes = Resolve-RemoteGatheringFailure -ErrorRecord $nrEr -Stage ConnectivityTest -ComputerName $m
        $null = $script:InvokeFailed.Add([pscustomobject]@{ ServerListEntry = $m; ComputerName = $m; ErrorMessage = $nrRes.TechnicalDetail; FailureReasonCode = $nrRes.FailureReasonCode; FailureReasonSummary = $nrRes.FailureReasonSummary })
        Write-Warning "[$m] $($nrRes.FailureReasonSummary)"
        Write-ErrorLog -ServerName $m -ErrorMessage "$($nrRes.FailureReasonSummary) | $($nrRes.TechnicalDetail)" -ErrorType "CONNECTION_ERROR"
    }
}

function Build-ScanRowFromDiscoveryJsonPath {
    param([string]$JsonPath, [string]$ListEntry, [string]$JsonFileName)
    $row = [ordered]@{
        ServerListEntry             = $ListEntry
        ResolvedComputerName        = $null
        Outcome                     = 'Fully successful'
        ConnectionErrorCategory     = $null
        FailureReasonCode           = $null
        FailureReasonSummary        = $null
        TechnicalDetail             = $null
        JsonFileName                = $JsonFileName
        PowerShellVersion           = $null
        CompatibilityMode           = $null
        UnavailableSectionsSummary  = $null
        ConfigFileIssue             = $false
        DetailMessage               = $null
    }
    if (-not (Test-Path -LiteralPath $JsonPath)) {
        $row['Outcome'] = 'JSON file missing after reported success'
        $row['DetailMessage'] = $JsonPath
        return [pscustomobject]$row
    }
    try {
        $jtxt = Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8 -ErrorAction Stop
        $j = $jtxt | ConvertFrom-Json
        $meta = $j.Metadata
        if ($meta) {
            $row['ResolvedComputerName'] = $meta.ComputerName
            $row['PowerShellVersion'] = [string]$meta.PowerShellVersion
            $row['CompatibilityMode'] = [string]$meta.CompatibilityMode
            $us = $meta.UnavailableSections
            if ($null -ne $us) {
                if ($us -is [System.Array] -and $us.Count -gt 0) {
                    $row['UnavailableSectionsSummary'] = ($us | ForEach-Object { [string]$_ }) -join '; '
                }
                elseif ($us -is [string] -and $us.Trim() -ne '') {
                    $row['UnavailableSectionsSummary'] = $us
                }
            }
            $compat = [string]$meta.CompatibilityMode
            if ($compat -eq 'Legacy3to4') {
                $row['Outcome'] = 'Partial success (PowerShell 3/4 — limited sections)'
            }
            elseif ($row['UnavailableSectionsSummary']) {
                $row['Outcome'] = 'Partial success (some sections not collected)'
            }
            else {
                $row['Outcome'] = 'Fully successful'
            }
        }
    }
    catch {
        $row['Outcome'] = 'Fully successful'
        $row['DetailMessage'] = "Could not parse discovery JSON metadata: $($_.Exception.Message)"
    }
    return [pscustomobject]$row
}

$builtScanRows = [System.Collections.ArrayList]::new()
foreach ($s in $servers) {
    if ($s -in $script:SessionCreateFailed) {
        $erSession = $script:SessionCreateErrorByServer[$s]
        $sr = Resolve-RemoteGatheringFailure -ErrorRecord $erSession -Stage SessionCreate -ComputerName $s
        $null = $builtScanRows.Add([pscustomobject]@{
                ServerListEntry             = $s
                ResolvedComputerName        = $null
                Outcome                     = 'Could not connect (WinRM)'
                ConnectionErrorCategory     = $sr.FailureReasonCode
                FailureReasonCode           = $sr.FailureReasonCode
                FailureReasonSummary        = $sr.FailureReasonSummary
                TechnicalDetail             = $sr.TechnicalDetail
                JsonFileName                = $null
                PowerShellVersion           = $null
                CompatibilityMode           = $null
                UnavailableSectionsSummary  = $null
                ConfigFileIssue             = $false
                DetailMessage               = $sr.TechnicalDetail
            })
        continue
    }
    $inv = @($script:InvokeFailed | Where-Object { $_.ServerListEntry -eq $s -or ((-not $_.ServerListEntry) -and $_.ComputerName -eq $s) } | Select-Object -First 1)
    if ($inv.Count -gt 0) {
        $e = $inv[0].ErrorMessage
        $fc = $inv[0].FailureReasonCode
        $fs = $inv[0].FailureReasonSummary
        if (-not $fc -or -not $fs) {
            $ex = [System.Exception]::new([string]$e)
            $er = [System.Management.Automation.ErrorRecord]::new($ex, 'RemoteDiscovery', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
            $ir = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage RemoteInvoke -ComputerName $s
            $fc = $ir.FailureReasonCode
            $fs = $ir.FailureReasonSummary
            $e = $ir.TechnicalDetail
        }
        $null = $builtScanRows.Add([pscustomobject]@{
                ServerListEntry             = $s
                ResolvedComputerName        = $inv[0].ComputerName
                Outcome                     = 'Discovery or payload failed'
                ConnectionErrorCategory     = $fc
                FailureReasonCode           = $fc
                FailureReasonSummary        = $fs
                TechnicalDetail             = $e
                JsonFileName                = $null
                PowerShellVersion           = $null
                CompatibilityMode           = $null
                UnavailableSectionsSummary  = $null
                ConfigFileIssue             = $false
                DetailMessage               = $e
            })
        continue
    }
    $cf = @($script:CollectFailed | Where-Object { $_.ServerListEntry -eq $s -or ((-not $_.ServerListEntry) -and $_.ComputerName -eq $s) } | Select-Object -First 1)
    if ($cf.Count -gt 0) {
        $ce = $cf[0].ErrorMessage
        $cfc = $cf[0].FailureReasonCode
        $cfs = $cf[0].FailureReasonSummary
        if (-not $cfc -or -not $cfs) {
            $ex = [System.Exception]::new([string]$ce)
            $er = [System.Management.Automation.ErrorRecord]::new($ex, 'FileCollection', [System.Management.Automation.ErrorCategory]::InvalidResult, $null)
            $fr = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage FileCollection -ComputerName $s
            $cfc = $fr.FailureReasonCode
            $cfs = $fr.FailureReasonSummary
            $ce = $fr.TechnicalDetail
        }
        $null = $builtScanRows.Add([pscustomobject]@{
                ServerListEntry             = $s
                ResolvedComputerName        = $cf[0].ComputerName
                Outcome                     = 'JSON collection failed'
                ConnectionErrorCategory     = $cfc
                FailureReasonCode           = $cfc
                FailureReasonSummary        = $cfs
                TechnicalDetail             = $ce
                JsonFileName                = $null
                PowerShellVersion           = $null
                CompatibilityMode           = $null
                UnavailableSectionsSummary  = $null
                ConfigFileIssue             = $false
                DetailMessage               = $ce
            })
        continue
    }
    if ($s -in $script:SuccessHosts) {
        $jf = $script:SuccessJsonByListEntry[$s]
        if (-not $jf) {
            $null = $builtScanRows.Add([pscustomobject]@{
                    ServerListEntry             = $s
                    ResolvedComputerName        = $null
                    Outcome                     = 'Fully successful (JSON file name not recorded)'
                    ConnectionErrorCategory     = $null
                    FailureReasonCode           = $null
                    FailureReasonSummary        = $null
                    TechnicalDetail             = $null
                    JsonFileName                = $null
                    PowerShellVersion           = $null
                    CompatibilityMode           = $null
                    UnavailableSectionsSummary  = $null
                    ConfigFileIssue             = $false
                    DetailMessage               = $null
                })
            continue
        }
        $jp = Join-Path $localOutputRoot $jf
        $null = $builtScanRows.Add((Build-ScanRowFromDiscoveryJsonPath -JsonPath $jp -ListEntry $s -JsonFileName $jf))
        continue
    }
    $null = $builtScanRows.Add([pscustomobject]@{
            ServerListEntry             = $s
            ResolvedComputerName        = $null
            Outcome                     = 'Unknown (no terminal state recorded)'
            ConnectionErrorCategory     = $null
            FailureReasonCode           = $null
            FailureReasonSummary        = $null
            TechnicalDetail             = $null
            JsonFileName                = $null
            PowerShellVersion           = $null
            CompatibilityMode           = $null
            UnavailableSectionsSummary  = $null
            ConfigFileIssue             = $false
            DetailMessage               = $null
        })
}

$listPathResolved = $ServerListPath
try { $listPathResolved = (Resolve-Path -LiteralPath $ServerListPath -ErrorAction Stop).Path } catch { }
Write-DiscoveryScanResultsFile `
    -OutputDirectory $localOutputRoot `
    -HostScanRows @($builtScanRows.ToArray()) `
    -ServerListPath $listPathResolved `
    -PlantId $PlantId

# --- PS7 orchestrator summary report (new file; does not alter error.log) ---
$summaryPath = Join-Path $resultsDir "PS7-orchestrator-summary.txt"
$summaryLines = [System.Collections.ArrayList]::new()
$null = $summaryLines.Add("PS7 Orchestrator Summary")
$null = $summaryLines.Add("Generated: $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))")
$null = $summaryLines.Add("ServerListPath: $ServerListPath")
$null = $summaryLines.Add("ThrottleLimit: $ThrottleLimit")
$null = $summaryLines.Add("Total servers: $($servers.Count)")
$null = $summaryLines.Add("")
$null = $summaryLines.Add("SessionCreate failed: $($script:SessionCreateFailed.Count)")
if ($script:SessionCreateFailed.Count -gt 0) { foreach ($h in $script:SessionCreateFailed) { $null = $summaryLines.Add("  - $h") } } else { $null = $summaryLines.Add("  (none)") }
$null = $summaryLines.Add("")
$null = $summaryLines.Add("Invoke failed: $($script:InvokeFailed.Count)")
if ($script:InvokeFailed.Count -gt 0) { foreach ($x in $script:InvokeFailed) { $lk = if ($x.ServerListEntry) { $x.ServerListEntry } else { $x.ComputerName }; $null = $summaryLines.Add("  - ${lk}: $($x.ErrorMessage)") } } else { $null = $summaryLines.Add("  (none)") }
$null = $summaryLines.Add("")
$null = $summaryLines.Add("Collect failed: $($script:CollectFailed.Count)")
if ($script:CollectFailed.Count -gt 0) { foreach ($x in $script:CollectFailed) { $lk = if ($x.ServerListEntry) { $x.ServerListEntry } else { $x.ComputerName }; $null = $summaryLines.Add("  - ${lk}: $($x.ErrorMessage)") } } else { $null = $summaryLines.Add("  (none)") }
$null = $summaryLines.Add("")
$null = $summaryLines.Add("Succeeded: $($script:SuccessHosts.Count)")
if ($script:SuccessHosts.Count -gt 0) { foreach ($h in $script:SuccessHosts) { $null = $summaryLines.Add("  - $h") } } else { $null = $summaryLines.Add("  (none)") }
$null = $summaryLines.Add("")
$null = $summaryLines.Add("Error log (unchanged): $script:ErrorLogPath")
$summaryLines | Out-File -FilePath $summaryPath -Encoding utf8 -Force
Write-Host "PS7 summary report: $summaryPath" -ForegroundColor Cyan

# --- Summary (same as PS5.1) ---
Write-Host "`n" + ("="*70) -ForegroundColor Cyan
Write-Host "Discovery execution completed." -ForegroundColor Green
if ($script:ErrorLogPath -and (Test-Path -LiteralPath $script:ErrorLogPath)) {
    $lineCount = Get-Content -LiteralPath $script:ErrorLogPath -ErrorAction SilentlyContinue | Measure-Object -Line
    $errorCount = if ($lineCount.Lines) { $lineCount.Lines } else { 0 }
    if ($errorCount -gt 0) {
        Write-Host "Errors were encountered during execution. Check error log:" -ForegroundColor Yellow
        Write-Host "  $script:ErrorLogPath" -ForegroundColor Yellow
        Write-Host "  Total error entries: $errorCount" -ForegroundColor Yellow
    }
    else {
        Write-Host "No errors encountered. Error log: $script:ErrorLogPath" -ForegroundColor Green
    }
}
Write-Host ("="*70) -ForegroundColor Cyan
