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
    [switch]$UseParallel      # simple fan-out option
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

# Optional: credentials if you're not already running as an account
# that has admin rights on all the target servers.
$cred = Get-Credential -Message "Enter the account that has local admin rights on all servers"

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

    Write-Host "[$ComputerName] Testing WinRM connectivity..." -ForegroundColor Yellow
    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "[$ComputerName] WinRM not reachable: $($_.Exception.Message)"
        return
    }

    Write-Host "[$ComputerName] Starting discovery..." -ForegroundColor Cyan

    try {
        # Invoke your existing script remotely.
        # -FilePath sends the local script content to the remote box and executes it there.
        $summary = Invoke-Command -ComputerName $ComputerName `
                                  -Credential   $Credential `
                                  -FilePath     $ScriptPath `
                                  -ArgumentList $commonArgs `
                                  -ErrorAction  Stop

        if ($summary -and $EmitStdOut) {
            # $summary is the small summary object your script writes when -EmitStdOut is set
            # You can write it or collect it into an array for reporting.
            Write-Host "[$ComputerName] Summary:" -ForegroundColor Green
            $summary | ConvertTo-Json -Depth 4
        }

        # Optional: pull the JSON file back from the remote’s OutputRoot
        if ($CollectorShare) {
            Write-Host "[$ComputerName] Collecting JSON from remote OutputRoot..." -ForegroundColor Yellow

            # Create a session so we can copy files
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

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
        Invoke-DiscoveryOnServer -ComputerName $_ -Credential $using:cred
    } -ThrottleLimit 10
}
else {
    foreach ($server in $servers) {
        Invoke-DiscoveryOnServer -ComputerName $server -Credential $cred
    }
}
