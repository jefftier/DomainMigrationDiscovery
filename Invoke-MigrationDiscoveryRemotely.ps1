param(
    [Parameter(Mandatory = $true)]
    [string]$ServerListPath,          # e.g. .\servers.txt

    [string]$ScriptPath = ".\Get-WorkstationDiscovery.ps1",

    # Where the *remote* script writes its local JSON/logs
    [string]$RemoteOutputRoot = "C:\temp\MigrationDiscovery\out",
    [string]$RemoteLogRoot    = "C:\temp\MigrationDiscovery\logs",

    # Optional central share where **you** (the jump host) will collect results
    [string]$CollectorShare   = "\\fileserver\MigrationDiscovery\workstations",

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

# Build common argument list for the discovery script
$commonArgs = @(
    '-OutputRoot', $RemoteOutputRoot,
    '-LogRoot',    $RemoteLogRoot,
    '-OldDomainFqdn', $OldDomainFqdn,
    '-NewDomainFqdn', $NewDomainFqdn
)

if ($OldDomainNetBIOS) { $commonArgs += @('-OldDomainNetBIOS', $OldDomainNetBIOS) }
if ($NewDomainNetBIOS) { $commonArgs += @('-NewDomainNetBIOS', $NewDomainNetBIOS) }
if ($PlantId)          { $commonArgs += @('-PlantId', $PlantId) }

# Your script defaults SlimOutputOnly = $true already, so we don't *need* to pass it.
if ($EmitStdOut)       { $commonArgs += '-EmitStdOut' }

# Helper: run discovery on a single server
function Invoke-DiscoveryOnServer {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Host "[$ComputerName] Testing WinRM connectivity and authentication..." -ForegroundColor Yellow
    try {
        # Test connectivity and authentication with a simple Invoke-Command
        # This is more reliable than Test-WSMan when credentials are involved
        $testParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = { $env:COMPUTERNAME }
            ErrorAction  = 'Stop'
            SessionOption = New-PSSessionOption -EnableNetworkAccess
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
        # Create session options to enable network access (for double-hop scenarios)
        $sessionOption = New-PSSessionOption -EnableNetworkAccess
        
        # Build parameters for Invoke-Command
        $invokeParams = @{
            ComputerName = $ComputerName
            FilePath     = $ScriptPath
            ArgumentList = $commonArgs
            ErrorAction  = 'Stop'
            SessionOption = $sessionOption
        }
        
        # Add credentials only if provided
        if ($Credential) {
            $invokeParams['Credential'] = $Credential
        }
        
        # Invoke your existing script remotely.
        # -FilePath sends the local script content to the remote box and executes it there.
        $summary = Invoke-Command @invokeParams

        if ($summary -and $EmitStdOut) {
            # $summary is the small summary object your script writes when -EmitStdOut is set
            # You can write it or collect it into an array for reporting.
            Write-Host "[$ComputerName] Summary:" -ForegroundColor Green
            $summary | ConvertTo-Json -Depth 4
        }

        # Optional: pull the JSON file back from the remote's OutputRoot
        if ($CollectorShare) {
            Write-Host "[$ComputerName] Collecting JSON from remote OutputRoot..." -ForegroundColor Yellow

            # Create a session so we can copy files
            $sessionParams = @{
                ComputerName = $ComputerName
                SessionOption = New-PSSessionOption -EnableNetworkAccess
            }
            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }
            $session = New-PSSession @sessionParams

            try {
                # The file name pattern in your script: COMPUTERNAME_MM-dd-yyyy.json
                $today = Get-Date
                $pattern = "{0}_{1}.json" -f $ComputerName.ToUpper(), $today.ToString('MM-dd-yyyy')
                $remotePath = Join-Path $RemoteOutputRoot $pattern

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

        Write-Host "[$ComputerName] Discovery completed." -ForegroundColor Green
    }
    catch {
        Write-Warning "[$ComputerName] Discovery FAILED: $($_.Exception.Message)"
    }
}

if ($UseParallel) {
    # PowerShell 7+ ForEach-Object -Parallel
    $servers | ForEach-Object -Parallel {
        Invoke-DiscoveryOnServer -ComputerName $_ -Credential $using:Credential
    } -ThrottleLimit 10
}
else {
    foreach ($server in $servers) {
        Invoke-DiscoveryOnServer -ComputerName $server -Credential $Credential
    }
}
