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

# Helper: run discovery on a single server
# Converted to scriptblock for parallel execution compatibility
$InvokeDiscoveryOnServerScriptBlock = {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$ScriptContent,
        [hashtable]$ScriptParams,
        [string]$CollectorShare,
        [string]$RemoteOutputRoot,
        [scriptblock]$WriteErrorLogFunction,
        [string]$ConfigFile,
        [string]$RemoteConfigPath,
        [string]$CompatibilityMode
    )

    Write-Host "[$ComputerName] Testing WinRM connectivity and authentication..." -ForegroundColor Yellow
    $connectionSuccessful = $false
    $actualComputerName = $null
    
    # Determine compatibility mode locally (don't rely on script-level variables)
    if (-not $CompatibilityMode) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $CompatibilityMode = 'Full'
        } else {
            $CompatibilityMode = 'Legacy3to4'
        }
    }
    
    # First attempt to connect
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
        
        # Add connection timeout to prevent hangs (PowerShell 5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout (New-TimeSpan -Seconds 30)
        }
        
        $testResult = Invoke-Command @testParams
        Write-Host "[$ComputerName] Successfully connected (remote computer: $testResult)" -ForegroundColor Green
        
        # Store the actual computer name from the remote system for filename matching
        # The discovery script uses $env:COMPUTERNAME which may not match the provided ComputerName case
        $actualComputerName = $testResult
        $connectionSuccessful = $true
    }
    catch {
        $initialError = $_.Exception.Message
        $errorCategory = $_.CategoryInfo.Category
        $fullError = $_.Exception.ToString()
        
        Write-Warning "[$ComputerName] Initial WinRM connection failed: $initialError"
        Write-Warning "[$ComputerName] Error Category: $errorCategory"
        
        # Provide more specific error information
        if ($_.Exception.InnerException) {
            Write-Warning "[$ComputerName] Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        # Check for common error patterns
        if ($initialError -match "Access is denied" -or $initialError -match "authentication") {
            Write-Warning "[$ComputerName] Authentication issue - verify credentials have admin rights on target"
        }
        elseif ($initialError -match "cannot connect" -or $initialError -match "network") {
            Write-Warning "[$ComputerName] Network/connectivity issue - verify WinRM is enabled and firewall allows connections"
        }
        elseif ($initialError -match "timeout") {
            Write-Warning "[$ComputerName] Connection timeout - verify WinRM service is running and network is accessible"
        }
        
        # Attempt to start WinRM service remotely and retry
        Write-Host "[$ComputerName] Attempting to start WinRM service and retry connection..." -ForegroundColor Yellow
        
        # Try to start WinRM service remotely
        # Note: This will likely fail if WinRM isn't working, but we try anyway
        $serviceStarted = $false
        $cimSession = $null
        try {
            if ($CompatibilityMode -eq 'Full') {
                # PowerShell 5.1+ - Use CIM
                # Note: CIM also requires WinRM, so this will likely fail if WinRM isn't working
                # But we try it anyway in case the service just needs to be started
                try {
                    if ($Credential) {
                        # Create a CIM session with credentials
                        $sessionParams = @{
                            ComputerName = $ComputerName
                            Credential   = $Credential
                            ErrorAction = 'Stop'
                            SessionOption = New-CimSessionOption -Protocol Wsman
                        }
                        $cimSession = New-CimSession @sessionParams
                    }
                    
                    # Get the service using session or direct connection
                    $cimParams = @{
                        ClassName    = 'Win32_Service'
                        Filter       = "Name='WinRM'"
                        ErrorAction  = 'Stop'
                    }
                    if ($cimSession) {
                        $cimParams['CimSession'] = $cimSession
                    } else {
                        $cimParams['ComputerName'] = $ComputerName
                    }
                    
                    $service = Get-CimInstance @cimParams
                }
                catch {
                    Write-Warning "[$ComputerName] CIM connection failed (WinRM likely not available): $($_.Exception.Message)"
                    # CIM failed, which means WinRM isn't working - skip service start attempt
                    $service = $null
                }
                
                if ($service) {
                    if ($service.State -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service is already running, retrying connection..." -ForegroundColor Yellow
                        $serviceStarted = $true
                    }
                    else {
                        # Start the service
                        $startParams = @{
                            InputObject = $service
                            ErrorAction = 'Stop'
                        }
                        $result = Invoke-CimMethod @startParams -MethodName StartService
                        
                        if ($result.ReturnValue -eq 0) {
                            Write-Host "[$ComputerName] WinRM service started successfully (ReturnValue: $($result.ReturnValue))" -ForegroundColor Green
                            # Wait a moment for the service to fully start
                            Start-Sleep -Seconds 3
                            $serviceStarted = $true
                        }
                        else {
                            Write-Warning "[$ComputerName] Failed to start WinRM service. ReturnValue: $($result.ReturnValue)"
                        }
                    }
                }
            }
            else {
                # PowerShell 3.0-4.0 - Use WMI
                $wmiParams = @{
                    ComputerName = $ComputerName
                    Class        = 'Win32_Service'
                    Filter       = "Name='WinRM'"
                    ErrorAction  = 'Stop'
                }
                if ($Credential) {
                    $wmiParams['Credential'] = $Credential
                }
                
                $service = Get-WmiObject @wmiParams
                if ($service) {
                    if ($service.State -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service is already running, retrying connection..." -ForegroundColor Yellow
                        $serviceStarted = $true
                    }
                    else {
                        # Start the service
                        $result = $service.StartService()
                        
                        if ($result.ReturnValue -eq 0) {
                            Write-Host "[$ComputerName] WinRM service started successfully (ReturnValue: $($result.ReturnValue))" -ForegroundColor Green
                            # Wait a moment for the service to fully start
                            Start-Sleep -Seconds 3
                            $serviceStarted = $true
                        }
                        else {
                            Write-Warning "[$ComputerName] Failed to start WinRM service. ReturnValue: $($result.ReturnValue)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "[$ComputerName] Failed to start WinRM service remotely: $($_.Exception.Message)"
        }
        finally {
            # Clean up CIM session if created
            if ($cimSession) {
                try {
                    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                }
                catch {
                    # Ignore cleanup errors
                }
            }
        }
        
        # Retry connection if service was started or was already running
        if ($serviceStarted) {
            Write-Host "[$ComputerName] Retrying WinRM connection..." -ForegroundColor Yellow
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
                    $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout (New-TimeSpan -Seconds 30)
                }
                
                $testResult = Invoke-Command @testParams
                Write-Host "[$ComputerName] Successfully connected after starting WinRM service (remote computer: $testResult)" -ForegroundColor Green
                $actualComputerName = $testResult
                $connectionSuccessful = $true
            }
            catch {
                $retryError = $_.Exception.Message
                $errorMsg = "WinRM connection failed after attempting to start service. Initial error: $initialError. Retry error: $retryError"
                Write-Warning "[$ComputerName] $errorMsg"
                & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
                return
            }
        }
        else {
            # Service couldn't be started, log detailed error and return
            $errorMsg = "WinRM connection failed. Initial error: $initialError"
            Write-Warning "[$ComputerName] $errorMsg"
            Write-Warning "[$ComputerName] Troubleshooting tips:"
            Write-Warning "[$ComputerName]   1. Verify WinRM is enabled: Enable-PSRemoting -Force"
            Write-Warning "[$ComputerName]   2. Check WinRM service status: Get-Service WinRM"
            Write-Warning "[$ComputerName]   3. Test connectivity: Test-WSMan -ComputerName $ComputerName"
            Write-Warning "[$ComputerName]   4. Verify firewall rules allow WinRM"
            Write-Warning "[$ComputerName]   5. Check credentials have admin rights on target"
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
            return
        }
    }
    
    # If connection failed for any reason, exit
    if (-not $connectionSuccessful) {
        $errorMsg = "WinRM connection failed: Unable to establish connection"
        Write-Warning "[$ComputerName] $errorMsg"
        & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "CONNECTION_ERROR"
        return
    }

    # Copy config file to remote server if provided
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
        
        # Add connection timeout to prevent hangs (PowerShell 5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout (New-TimeSpan -Seconds 300)
        }
        
        # Invoke your existing script remotely using ScriptBlock for proper parameter handling
        $summary = Invoke-Command @invokeParams

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
    catch {
        $errorMsg = "Discovery FAILED: $($_.Exception.Message)"
        Write-Warning "[$ComputerName] $errorMsg"
        & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage $errorMsg -ErrorType "DISCOVERY_ERROR"
        
        # Log full exception details if available
        if ($_.Exception.InnerException) {
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage "Inner Exception: $($_.Exception.InnerException.Message)" -ErrorType "DISCOVERY_ERROR"
        }
        if ($_.ScriptStackTrace) {
            & $WriteErrorLogFunction -ServerName $ComputerName -ErrorMessage "Stack Trace: $($_.ScriptStackTrace)" -ErrorType "DISCOVERY_ERROR"
        }
    }
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

# Create a scriptblock for Write-ErrorLog to pass to parallel execution
$writeErrorLogScriptBlock = ${function:Write-ErrorLog}

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
                -ConfigFile $using:ConfigFile `
                -RemoteConfigPath $using:remoteConfigPath `
                -CompatibilityMode $using:script:CompatibilityMode
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
                    -ConfigFile $ConfigFile `
                    -RemoteConfigPath $remoteConfigPath `
                    -CompatibilityMode $script:CompatibilityMode
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
                -ConfigFile $ConfigFile `
                -RemoteConfigPath $remoteConfigPath
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
