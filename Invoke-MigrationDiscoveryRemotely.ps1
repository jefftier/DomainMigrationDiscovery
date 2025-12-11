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
    [switch]$UseParallel,     # simple fan-out option
    [switch]$AttemptWinRmHeal, # Optional: attempt to start WinRM service if connection fails (default: false)
    [System.Management.Automation.PSCredential]$Credential  # Optional: if not provided, will prompt or use current user
)

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
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$ServerName] [$ErrorType] $ErrorMessage"
    
    try {
        Add-Content -Path $script:ErrorLogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # If we can't write to the log file, at least try to write to console
        Write-Warning "Failed to write to error log: $($_.Exception.Message)"
        Write-Warning $logEntry
    }
}

if (-not (Test-Path -LiteralPath $ServerListPath)) {
    $errorMsg = "Server list file not found: $ServerListPath"
    Write-ErrorLog -ServerName "SCRIPT_INIT" -ErrorMessage $errorMsg -ErrorType "FATAL"
    throw $errorMsg
}

# Read and de-duplicate server names (ignore blank/ commented lines)
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
# Note: NewDomainNetBIOS is not a parameter in Get-WorkstationDiscovery.ps1, so we explicitly do NOT pass it
# This prevents PowerShell parameter binding errors on remote systems
if ($PlantId)          { $scriptParams['PlantId'] = $PlantId }
if ($EmitStdOut)       { $scriptParams['EmitStdOut'] = $true }

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
#   attempts to start the WinRM service on the remote system using: Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running
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
        
        [hashtable]$RemoteScriptArguments = @{},
        
        [switch]$AttemptWinRmHeal,
        
        [System.Management.Automation.PSCredential]$Credential,
        
        [scriptblock]$WriteErrorLogFunction
    )
    
    # Result object to return
    $result = @{
        Success = $false
        ErrorCategory = $null
        ErrorMessage = $null
        Output = $null
        ActualComputerName = $null
    }
    
    # Step 1: Initial WinRM connectivity check
    Write-Host "[$ComputerName] Testing WinRM connectivity..." -ForegroundColor Yellow
    $connectivityTestPassed = $false
    $actualComputerName = $null
    
    try {
        $testParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = { $env:COMPUTERNAME }
            ErrorAction  = 'Stop'
        }
        if ($Credential) {
            $testParams['Credential'] = $Credential
        }
        
        # Add connection timeout to prevent hangs (PowerShell 5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30
        }
        
        $testResult = Invoke-Command @testParams
        $actualComputerName = $testResult
        $connectivityTestPassed = $true
        Write-Host "[$ComputerName] WinRM connectivity successful (remote computer: $testResult)" -ForegroundColor Green
    }
    catch {
        $initialError = $_.Exception.Message
        $errorRecord = $_
        Write-Warning "[$ComputerName] WinRM connectivity failed: $initialError"
        
        # Step 2: Classify the error
        $failureCategory = Get-WinRmFailureCategory -ErrorMessage $initialError -ErrorRecord $errorRecord
        
        # Log the categorized error
        $errorMsg = "WinRM connectivity failed - categorized as $failureCategory. Error: $initialError"
        Write-Warning "[$ComputerName] $errorMsg"
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
                Write-Warning "[$ComputerName] $errorMsg"
                if ($WriteErrorLogFunction) {
                    & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
                }
                $result.ErrorCategory = $failureCategory
                $result.ErrorMessage = $errorMsg
                return $result
            }
            
            # Step 4: Attempt to start WinRM service
            Write-Host "[$ComputerName] Attempting to start WinRM service via Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running..." -ForegroundColor Yellow
            $serviceStarted = $false
            
            try {
                # Use the exact command that works manually
                # Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running
                $service = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                
                if ($service.Status -eq 'Running') {
                    Write-Host "[$ComputerName] WinRM service is already running." -ForegroundColor Green
                    $serviceStarted = $true
                }
                else {
                    # Execute the exact pipeline command
                    Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running -ErrorAction Stop
                    
                    # Wait a short period for the service to start
                    Start-Sleep -Seconds 5
                    
                    # Re-check the service status
                    $serviceCheck = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                    if ($serviceCheck.Status -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service successfully started; retrying WinRM connectivity..." -ForegroundColor Green
                        $serviceStarted = $true
                    }
                    else {
                        $errorMsg = "WinRM heal failed; service not running after attempt. Status: $($serviceCheck.Status)"
                        Write-Warning "[$ComputerName] $errorMsg"
                        if ($WriteErrorLogFunction) {
                            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "WINRM_HEAL_ERROR"
                        }
                        $result.ErrorCategory = $failureCategory
                        $result.ErrorMessage = $errorMsg
                        return $result
                    }
                }
            }
            catch {
                $serviceError = $_.Exception.Message
                $errorMsg = "Failed to start WinRM service: $serviceError"
                Write-Warning "[$ComputerName] $errorMsg"
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
                        $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30
                    }
                    
                    $testResult = Invoke-Command @testParams
                    $actualComputerName = $testResult
                    $connectivityTestPassed = $true
                    Write-Host "[$ComputerName] WinRM connectivity successful after heal (remote computer: $testResult)" -ForegroundColor Green
                }
                catch {
                    $retryError = $_.Exception.Message
                    $errorMsg = "WinRM connection failed after attempting to start service. Initial error: $initialError. Retry error: $retryError"
                    Write-Warning "[$ComputerName] $errorMsg"
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
    
    # Step 6: If connectivity test passed, run the main remote script
    if (-not $connectivityTestPassed) {
        $errorMsg = "WinRM connectivity failed: Unable to establish connection"
        Write-Warning "[$ComputerName] $errorMsg"
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
        
        # Add connection timeout (PowerShell 5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout 300
        }
        
        # Add arguments if provided
        if ($RemoteScriptArguments -and $RemoteScriptArguments.Count -gt 0) {
            $invokeParams['ArgumentList'] = @($RemoteScriptArguments)
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
        Write-Warning "[$ComputerName] $errorMsg"
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
        [scriptblock]$WriteErrorLogFunction,
        [scriptblock]$EnsureWinRmAndConnectFunction,
        [string]$ConfigFile,
        [string]$RemoteConfigPath,
        [string]$CompatibilityMode,
        [switch]$AttemptWinRmHeal
    )

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
        -RemoteScriptArguments @{} `
        -AttemptWinRmHeal:$AttemptWinRmHeal `
        -Credential $Credential `
        -WriteErrorLogFunction $WriteErrorLogFunction
    
    # Check if WinRM connectivity succeeded
    if (-not $testResult.Success) {
        # Error already logged by Ensure-WinRmAndConnect
        return
    }
    
    $actualComputerName = $testResult.ActualComputerName

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
                Write-Warning "[$ComputerName] $errorMsg"
                & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONFIG_FILE_ERROR"
                # Continue execution - the discovery script will run without config file
                $ScriptParams.Remove('ConfigFile')
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
            Write-Warning "[$ComputerName] $errorMsg"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONFIG_FILE_ERROR"
            # Continue execution - the discovery script will run without config file
            $ScriptParams.Remove('ConfigFile')
        }
    }

    # Step 3: Run the discovery script using the centralized helper
    # WinRM connectivity is already established, so this should succeed
    Write-Host "[$ComputerName] Starting discovery..." -ForegroundColor Cyan

    $remoteScriptBlock = {
        param($ScriptContent, $Params)
        # Execute the script with the provided parameters using splatting
        & ([scriptblock]::Create($ScriptContent)) @Params
    }
    
    $remoteScriptArguments = @{
        ScriptContent = $ScriptContent
        Params = $ScriptParams
    }
    
    $discoveryResult = & $EnsureWinRmAndConnectFunction `
        -ComputerName $ComputerName `
        -RemoteScriptBlock $remoteScriptBlock `
        -RemoteScriptArguments $remoteScriptArguments `
        -AttemptWinRmHeal:$false `
        -Credential $Credential `
        -WriteErrorLogFunction $WriteErrorLogFunction
    
    # Check if discovery script execution succeeded
    if (-not $discoveryResult.Success) {
        # Error already logged by Ensure-WinRmAndConnect
        return
    }
    
    $summary = $discoveryResult.Output

    # Note: $EmitStdOut is passed via $ScriptParams, so we check it from there for parallel execution compatibility
    $shouldEmitStdOut = $ScriptParams.ContainsKey('EmitStdOut') -and $ScriptParams['EmitStdOut'] -eq $true
    if ($summary -and $shouldEmitStdOut) {
        # $summary is the small summary object your script writes when -EmitStdOut is set
        # You can write it or collect it into an array for reporting.
        Write-Host "[$ComputerName] Summary:" -ForegroundColor Green
        $summary | ConvertTo-Json -Depth 4
    }

    # Collect JSON file from remote server
    # Use the exact computer name from the remote system to match the filename pattern
    # The discovery script uses $env:COMPUTERNAME which we captured as $actualComputerName
    # This ensures exact matching regardless of case, since we use the actual value from the remote system
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
        }
        catch {
            $errorMsg = "Failed to collect JSON from CollectorShare: $($_.Exception.Message)"
            Write-Warning "[$ComputerName] $errorMsg"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
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

            # Create local directory structure: {ScriptDir}\results\out
            $localOutputRoot = Join-Path $scriptDir "results\out"
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
        }
        catch {
            $errorMsg = "Failed to collect JSON from C$ share: $($_.Exception.Message)"
            Write-Warning "[$ComputerName] $errorMsg"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "FILE_COLLECTION_ERROR"
            Write-Host "[$ComputerName] JSON file is available on the remote server at: $remotePath" -ForegroundColor Cyan
        }
    }
    
    Write-Host "[$ComputerName] Discovery completed." -ForegroundColor Green
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

# Full (PS 5.1+) path
if ($script:CompatibilityMode -eq 'Full' -and $UseParallel) {
    # PowerShell 7+ ForEach-Object -Parallel (only available in PS 7+)
    # Check if -Parallel parameter is available
    $parallelAvailable = $false
    try {
        $null = Get-Command ForEach-Object -ParameterName Parallel -ErrorAction Stop
        $parallelAvailable = $true
    }
    catch {
        $parallelAvailable = $false
    }
    
    if ($parallelAvailable) {
        # ScriptParams already contains EmitStdOut if it was set, so it's available via $using:scriptParams
        $servers | ForEach-Object -Parallel {
            & $using:InvokeDiscoveryOnServerScriptBlock `
                -ComputerName $_ `
                -Credential $using:Credential `
                -ScriptContent $using:scriptContent `
                -ScriptParams $using:scriptParams `
                -CollectorShare $using:CollectorShare `
                -RemoteOutputRoot $using:RemoteOutputRoot `
                -WriteErrorLogFunction $using:writeErrorLogScriptBlock `
                -EnsureWinRmAndConnectFunction $using:ensureWinRmAndConnectScriptBlock `
                -ConfigFile $using:ConfigFile `
                -RemoteConfigPath $using:remoteConfigPath `
                -CompatibilityMode $using:script:CompatibilityMode `
                -AttemptWinRmHeal:$using:AttemptWinRmHeal
        } -ThrottleLimit 10
    }
    else {
        # Parallel not available, fall back to sequential
        Write-Host "ForEach-Object -Parallel not available. Using sequential execution." -ForegroundColor Yellow
        foreach ($server in $servers) {
            try {
                & $InvokeDiscoveryOnServerScriptBlock `
                    -ComputerName $server `
                    -Credential $Credential `
                    -ScriptContent $scriptContent `
                    -ScriptParams $scriptParams `
                    -CollectorShare $CollectorShare `
                    -RemoteOutputRoot $RemoteOutputRoot `
                    -WriteErrorLogFunction $writeErrorLogScriptBlock `
                    -EnsureWinRmAndConnectFunction $ensureWinRmAndConnectScriptBlock `
                    -ConfigFile $ConfigFile `
                    -RemoteConfigPath $remoteConfigPath `
                    -CompatibilityMode $script:CompatibilityMode `
                    -AttemptWinRmHeal:$AttemptWinRmHeal
            }
            catch {
                # Log any unexpected errors that escape the function
                $errorMsg = "Unexpected error processing server: $($_.Exception.Message)"
                Write-ErrorLog -ServerName $server -ErrorMessage $errorMsg -ErrorType "FATAL"
                Write-Warning "[$server] $errorMsg"
            }
        }
    }
}
else {
    # Legacy path for PS 3.0–4.0 (sequential execution only)
    if ($UseParallel) {
        Write-Host "Parallel execution is not available in PowerShell versions below 5.1. Using sequential execution." -ForegroundColor Yellow
    }
    foreach ($server in $servers) {
        try {
            & $InvokeDiscoveryOnServerScriptBlock `
                -ComputerName $server `
                -Credential $Credential `
                -ScriptContent $scriptContent `
                -ScriptParams $scriptParams `
                -CollectorShare $CollectorShare `
                -RemoteOutputRoot $RemoteOutputRoot `
                -WriteErrorLogFunction $writeErrorLogScriptBlock `
                -GetWinRmFailureCategoryFunction $getWinRmFailureCategoryScriptBlock `
                -ConfigFile $ConfigFile `
                -RemoteConfigPath $remoteConfigPath `
                -AttemptWinRmHeal:$AttemptWinRmHeal
        }
        catch {
            # Log any unexpected errors that escape the function
            $errorMsg = "Unexpected error processing server: $($_.Exception.Message)"
            Write-ErrorLog -ServerName $server -ErrorMessage $errorMsg -ErrorType "FATAL"
            Write-Warning "[$server] $errorMsg"
        }
    }
}

# Display summary
Write-Host "`n" + ("="*70) -ForegroundColor Cyan
Write-Host "Discovery execution completed." -ForegroundColor Green
if (Test-Path -Path $script:ErrorLogPath) {
    $errorCount = (Get-Content -Path $script:ErrorLogPath -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
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
