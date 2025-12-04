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
    [Parameter(Mandatory = $true)]
    [string]$OldDomainFqdn,

    [Parameter(Mandatory = $true)]
    [string]$NewDomainFqdn,

    [string]$OldDomainNetBIOS,
    [string]$NewDomainNetBIOS,

    [string]$PlantId,
    
    [switch]$EmitStdOut,      # bubble up the summary object from each server
    [switch]$UseParallel,     # simple fan-out option
    [System.Management.Automation.PSCredential]$Credential  # Optional: if not provided, will prompt or use current user
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ServerListPath)) {
    throw "Server list file not found: $ServerListPath"
}

# Read and de-duplicate server names (ignore blank/ commented lines)
$servers = @(Get-Content -Path $ServerListPath |
    Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } |
    ForEach-Object { $_.Trim() } |
    Sort-Object -Unique)

if ($servers.Count -eq 0) {
    throw "No servers found in list file: $ServerListPath"
}

Write-Host "Targets:" -ForegroundColor Cyan
$servers | ForEach-Object { Write-Host "  $_" }

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Discovery script not found: $ScriptPath"
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

# Build a hashtable of parameters for the discovery script
$scriptParams = @{
    OutputRoot    = $RemoteOutputRoot
    LogRoot       = $RemoteLogRoot
    OldDomainFqdn = $OldDomainFqdn
    NewDomainFqdn = $NewDomainFqdn
}

if ($OldDomainNetBIOS) { $scriptParams['OldDomainNetBIOS'] = $OldDomainNetBIOS }
if ($NewDomainNetBIOS) { $scriptParams['NewDomainNetBIOS'] = $NewDomainNetBIOS }
if ($PlantId)          { $scriptParams['PlantId'] = $PlantId }
if ($EmitStdOut)       { $scriptParams['EmitStdOut'] = $true }

# Helper: run discovery on a single server
function Invoke-DiscoveryOnServer {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ScriptContent,
        [hashtable]$ScriptParams,
        [string]$CollectorShare,
        [string]$RemoteOutputRoot
    )

    Write-Host "[$ComputerName] Testing WinRM connectivity and authentication..." -ForegroundColor Yellow
    try {
        # Test connectivity and authentication with a simple Invoke-Command
        # This is more reliable than Test-WSMan when credentials are involved
        $testParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = { $env:COMPUTERNAME }
            ErrorAction  = 'Stop'
        }
        if ($Credential) {
            $testParams['Credential'] = $Credential
        }
        $testResult = Invoke-Command @testParams
        Write-Host "[$ComputerName] Successfully connected (remote computer: $testResult)" -ForegroundColor Green
    }
    catch {
        Write-Warning "[$ComputerName] WinRM connection failed: $($_.Exception.Message)"
        return
    }

    Write-Host "[$ComputerName] Starting discovery..." -ForegroundColor Cyan

    try {
        # Build parameters for Invoke-Command using ScriptBlock with proper parameter passing
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = {
                param($ScriptContent, $Params)
                # Execute the script with the provided parameters using splatting
                & ([scriptblock]::Create($ScriptContent)) @Params
            }
            ArgumentList = @($ScriptContent, $ScriptParams)
            ErrorAction  = 'Stop'
        }
        
        # Add credentials only if provided
        if ($Credential) {
            $invokeParams['Credential'] = $Credential
        }
        
        # Invoke your existing script remotely using ScriptBlock for proper parameter handling
        $summary = Invoke-Command @invokeParams

        if ($summary -and $EmitStdOut) {
            # $summary is the small summary object your script writes when -EmitStdOut is set
            # You can write it or collect it into an array for reporting.
            Write-Host "[$ComputerName] Summary:" -ForegroundColor Green
            $summary | ConvertTo-Json -Depth 4
        }

        # Collect JSON file from remote server
        $today = Get-Date
        $pattern = "{0}_{1}.json" -f $ComputerName.ToUpper(), $today.ToString('MM-dd-yyyy')
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
            }
            catch {
                Write-Warning "[$ComputerName] Failed to collect JSON: $($_.Exception.Message)"
            }
            finally {
                if ($session) { Remove-PSSession $session }
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

                # Create local directory structure: {ScriptDir}\temp\MigrationDiscovery\out
                $localOutputRoot = Join-Path $scriptDir "temp\MigrationDiscovery\out"
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
                            Root = "\\$ComputerName\${driveLetter}$"
                            Credential = $Credential
                            Scope = "Script"
                        }
                        $null = New-PSDrive @psDriveParams -ErrorAction Stop
                        
                        try {
                            # Map the remote path using the temporary drive
                            $mappedRemotePath = "${driveName}:\$relativePath"
                            $mappedRemoteFile = Join-Path $mappedRemotePath $pattern
                            Copy-Item -Path $mappedRemoteFile -Destination $localDestPath -Force -ErrorAction Stop
                        }
                        finally {
                            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        throw "Failed to access remote ${driveLetter}$ share: $($_.Exception.Message)"
                    }
                }
                else {
                    # No credentials - try direct UNC copy (uses current user context)
                    Copy-Item -Path $remoteUncFile -Destination $localDestPath -Force -ErrorAction Stop
                }

                Write-Host "[$ComputerName] Copied $remoteUncFile -> $localDestPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "[$ComputerName] Failed to collect JSON from C$ share: $($_.Exception.Message)"
                Write-Host "[$ComputerName] JSON file is available on the remote server at: $remotePath" -ForegroundColor Cyan
            }
        }
        
        Write-Host "[$ComputerName] Discovery completed." -ForegroundColor Green
    }
    catch {
        Write-Warning "[$ComputerName] Discovery FAILED: $($_.Exception.Message)"
    }
}

if ($UseParallel) {
    # PowerShell 7+ ForEach-Object -Parallel
    $servers | ForEach-Object -Parallel {
        Invoke-DiscoveryOnServer -ComputerName $_ `
                                 -Credential $using:Credential `
                                 -ScriptContent $using:scriptContent `
                                 -ScriptParams $using:scriptParams `
                                 -CollectorShare $using:CollectorShare `
                                 -RemoteOutputRoot $using:RemoteOutputRoot
    } -ThrottleLimit 10
}
else {
    foreach ($server in $servers) {
        Invoke-DiscoveryOnServer -ComputerName $server `
                                 -Credential $Credential `
                                 -ScriptContent $scriptContent `
                                 -ScriptParams $scriptParams `
                                 -CollectorShare $CollectorShare `
                                 -RemoteOutputRoot $RemoteOutputRoot
    }
}
