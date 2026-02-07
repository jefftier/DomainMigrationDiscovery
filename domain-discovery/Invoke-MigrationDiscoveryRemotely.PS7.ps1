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
$script:InvokeFailed        = [System.Collections.ArrayList]::new()
$script:CollectFailed      = [System.Collections.ArrayList]::new()
$script:SuccessHosts       = [System.Collections.ArrayList]::new()

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

if (-not (Test-Path -LiteralPath $ServerListPath)) {
    $errorMsg = "Server list file not found: $ServerListPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

$servers = @(Get-Content -Path $ServerListPath |
    Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } |
    ForEach-Object { $_.Trim() } |
    Sort-Object -Unique)

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

# Remote scriptblock: staging + discovery + return payload or success (Truth Map exact)
$remoteDiscoveryScriptBlock = {
    param(
        [string]$HelperModuleContent,
        [string]$RemoteRunDir,
        [string]$ScriptContent,
        [hashtable]$ScriptParams,
        [string]$RemoteOutputRoot,
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
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        JsonFileName = [System.IO.Path]::GetFileName($jsonPath)
        JsonPath     = $jsonPath
        Encoding     = 'gzip+base64'
        Payload      = $b64
        Success      = $true
    }
}

if ($AttemptWinRmHeal) {
    Write-Host "Note: AttemptWinRmHeal is not applied in PS7 parallel mode (single fan-out)." -ForegroundColor Yellow
}

Write-Host "`nStarting discovery on $($servers.Count) server(s) (ThrottleLimit=$ThrottleLimit)..." -ForegroundColor Cyan

# --- Phase: Session creation (fan-out, ThrottleLimit) ---
$sessionOption = New-PSSessionOption -OperationTimeout 300000
$sessionParams = @{
    ComputerName  = $servers
    ThrottleLimit = $ThrottleLimit
    SessionOption = $sessionOption
    ErrorAction   = 'Continue'
}
if ($Credential) { $sessionParams['Credential'] = $Credential }

$sessions = @()
try {
    $sessions = @(New-PSSession @sessionParams)
}
catch {
    Write-Warning "New-PSSession reported: $($_.Exception.Message)"
}

$connectedComputers = @($sessions | ForEach-Object { $_.ComputerName })
foreach ($s in $servers) {
    if ($s -notin $connectedComputers) {
        $null = $script:SessionCreateFailed.Add($s)
        $err = "No session created for $s (WinRM connection failed)."
        Write-Warning $err
        Write-ErrorLog -ServerName $s -ErrorMessage $err -ErrorType "CONNECTION_ERROR"
    }
}

# --- Phase: Invoke (discovery on all sessions) ---
$allResults = @()
if ($sessions.Count -gt 0) {
    try {
        $allResults = Invoke-Command -Session $sessions -ScriptBlock $remoteDiscoveryScriptBlock -ArgumentList @($helperModuleContent, $remoteRunDir, $scriptContent, $scriptParams, $RemoteOutputRoot, $configFileContent, [bool]$UseSmbForResults.IsPresent) -ErrorAction Continue
    }
    catch {
        Write-Warning "Invoke-Command reported: $($_.Exception.Message)"
    }
    finally {
        Remove-PSSession -Session $sessions -Force -ErrorAction SilentlyContinue
    }
}

if ($allResults -and -not ($allResults -is [array])) { $allResults = @($allResults) }

# --- Phase: Collection (Truth Map: same method as PS5.1) ---
$localOutputRoot = Join-Path $scriptDir "results\out"
if (-not (Test-Path -Path $localOutputRoot)) { New-Item -Path $localOutputRoot -ItemType Directory -Force | Out-Null }

if (-not $UseSmbForResults) {
    foreach ($r in $allResults) {
        if (-not $r) { continue }
        if (-not $r.Success) {
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ComputerName = $r.ComputerName; ErrorMessage = $r.ErrorMessage })
            Write-Warning "[$($r.ComputerName)] $($r.ErrorMessage)"
            Write-ErrorLog -ServerName $r.ComputerName -ErrorMessage $r.ErrorMessage -ErrorType "SCRIPT_EXECUTION_ERROR"
            continue
        }
        if (-not $r.Payload) {
            $err = "Discovery ran but no JSON payload returned from $($r.ComputerName)"
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ComputerName = $r.ComputerName; ErrorMessage = $err })
            Write-Warning "[$($r.ComputerName)] $err"
            Write-ErrorLog -ServerName $r.ComputerName -ErrorMessage $err -ErrorType "FILE_COLLECTION_ERROR"
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
            $null = $script:SuccessHosts.Add($r.ComputerName)
            Write-Host "[$($r.ComputerName)] Wrote $localPath" -ForegroundColor Green
        }
        catch {
            $err = "Failed to decode JSON payload from $($r.ComputerName): $($_.Exception.Message)"
            $null = $script:CollectFailed.Add([pscustomobject]@{ ComputerName = $r.ComputerName; ErrorMessage = $err })
            Write-Warning "[$($r.ComputerName)] $err"
            Write-ErrorLog -ServerName $r.ComputerName -ErrorMessage $err -ErrorType "FILE_COLLECTION_ERROR"
        }
    }
}

if ($UseSmbForResults -and $allResults) {
    $successful = @($allResults | Where-Object { $_.Success -and $_.ComputerName })
    $todayStr = (Get-Date).ToString('MM-dd-yyyy')

    foreach ($r in $allResults) {
        if (-not $r -or -not $r.ComputerName) { continue }
        if (-not $r.Success) {
            $invErr = if ($r.ErrorMessage) { $r.ErrorMessage } else { "Invoke failed" }
            $null = $script:InvokeFailed.Add([pscustomobject]@{ ComputerName = $r.ComputerName; ErrorMessage = $invErr })
            Write-ErrorLog -ServerName $r.ComputerName -ErrorMessage $invErr -ErrorType "SCRIPT_EXECUTION_ERROR"
            continue
        }
    }

    foreach ($r in $successful) {
        $computerName = $r.ComputerName
        $pattern = "${computerName}_${todayStr}.json"
        $remotePath = Join-Path $RemoteOutputRoot $pattern

        if ($CollectorShare) {
            if (-not (Test-Path -Path $CollectorShare)) { New-Item -Path $CollectorShare -ItemType Directory -Force | Out-Null }
            $destPath = Join-Path $CollectorShare $pattern
            try {
                $sessionParams = @{ ComputerName = $computerName }
                if ($Credential) { $sessionParams['Credential'] = $Credential }
                $session = New-PSSession @sessionParams
                try {
                    Copy-Item -Path $remotePath -Destination $destPath -FromSession $session -Force -ErrorAction Stop
                    $null = $script:SuccessHosts.Add($computerName)
                    Write-Host "[$computerName] Copied to $destPath" -ForegroundColor Green
                }
                finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
            }
            catch {
                $err = "Failed to collect JSON from CollectorShare: $($_.Exception.Message)"
                $null = $script:CollectFailed.Add([pscustomobject]@{ ComputerName = $computerName; ErrorMessage = $err })
                Write-Warning "[$computerName] $err"
                Write-ErrorLog -ServerName $computerName -ErrorMessage $err -ErrorType "FILE_COLLECTION_ERROR"
            }
        }
        else {
            $localDestPath = Join-Path $localOutputRoot $pattern
            if ($RemoteOutputRoot -match '^([A-Z]):\\(.*)$') {
                $driveLetter = $matches[1].ToLower()
                $relativePath = $matches[2]
                $remoteUncPath = "\\$computerName\${driveLetter}$\$relativePath"
            }
            else { $remoteUncPath = $RemoteOutputRoot -replace '^C:', "\\$computerName\c$" }
            $remoteUncFile = Join-Path $remoteUncPath $pattern
            try {
                if ($Credential) {
                    $driveName = "TempDrive_$($computerName -replace '[^a-zA-Z0-9]', '')"
                    $driveLetter = if ($RemoteOutputRoot -match '^([A-Z]):') { $matches[1].ToLower() } else { 'c' }
                    $relativePath = if ($RemoteOutputRoot -match '^[A-Z]:\\(.*)$') { $matches[1] } else { $RemoteOutputRoot -replace '^C:\\', '' }
                    $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$computerName\$driveLetter`$" -Credential $Credential -Scope Script -ErrorAction Stop
                    try {
                        $mappedRemoteFile = "${driveName}:\$relativePath\$pattern"
                        Copy-Item -Path $mappedRemoteFile -Destination $localDestPath -Force -ErrorAction Stop
                    }
                    finally { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
                }
                else {
                    Copy-Item -Path $remoteUncFile -Destination $localDestPath -Force -ErrorAction Stop
                }
                $null = $script:SuccessHosts.Add($computerName)
                Write-Host "[$computerName] Copied $remoteUncFile -> $localDestPath" -ForegroundColor Green
            }
            catch {
                $err = "Failed to collect JSON from C$ share: $($_.Exception.Message)"
                $null = $script:CollectFailed.Add([pscustomobject]@{ ComputerName = $computerName; ErrorMessage = $err })
                Write-Warning "[$computerName] $err"
                Write-ErrorLog -ServerName $computerName -ErrorMessage $err -ErrorType "FILE_COLLECTION_ERROR"
            }
        }
    }
}

# Invoke ran but no result returned (e.g. session died during Invoke-Command)
$returnedComputers = @($allResults | Where-Object { $_ -and $_.ComputerName } | ForEach-Object { $_.ComputerName })
foreach ($m in $servers) {
    if ($m -in $connectedComputers -and $m -notin $returnedComputers) {
        $null = $script:InvokeFailed.Add([pscustomobject]@{ ComputerName = $m; ErrorMessage = "No result returned (Invoke-Command may have failed)." })
        $err = "No result returned from $m (WinRM connection or execution may have failed)."
        Write-Warning $err
        Write-ErrorLog -ServerName $m -ErrorMessage $err -ErrorType "CONNECTION_ERROR"
    }
}

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
if ($script:InvokeFailed.Count -gt 0) { foreach ($x in $script:InvokeFailed) { $null = $summaryLines.Add("  - $($x.ComputerName): $($x.ErrorMessage)") } } else { $null = $summaryLines.Add("  (none)") }
$null = $summaryLines.Add("")
$null = $summaryLines.Add("Collect failed: $($script:CollectFailed.Count)")
if ($script:CollectFailed.Count -gt 0) { foreach ($x in $script:CollectFailed) { $null = $summaryLines.Add("  - $($x.ComputerName): $($x.ErrorMessage)") } } else { $null = $summaryLines.Add("  (none)") }
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
