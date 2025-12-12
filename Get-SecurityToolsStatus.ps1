#Requires -Version 5.1
<#
.SYNOPSIS
    Checks security tools status for one or more servers remotely.

.DESCRIPTION
    This script connects to remote servers via WinRM and checks the status of security tools:
    - CrowdStrike (Falcon Sensor)
    - Qualys
    - SCCM (Configuration Manager)
    - Encase
    
    The results are displayed in a formatted table showing the installation status
    and tenant configuration for each security tool across all servers.

.PARAMETER ComputerName
    The name or IP address of a single remote server to check.
    Mutually exclusive with ServerListPath.

.PARAMETER ServerListPath
    Path to a text file containing a list of servers (one per line).
    Default: ".\servers.txt"
    Mutually exclusive with ComputerName.
    Lines starting with # are treated as comments and ignored.

.PARAMETER OldDomainFqdn
    Fully Qualified Domain Name (FQDN) of the old domain (required for SCCM detection).
    Can be provided as parameter or loaded from ConfigFile.
    Example: 'olddomain.com'

.PARAMETER NewDomainFqdn
    Fully Qualified Domain Name (FQDN) of the new domain (required for SCCM detection).
    Can be provided as parameter or loaded from ConfigFile.
    Example: 'newdomain.com'

.PARAMETER ConfigFile
    Optional path to JSON configuration file for domain settings, tenant mappings, and Encase registry paths.
    If not provided, default mappings will be used.

.PARAMETER UseParallel
    Use parallel execution for multiple servers (PowerShell 7+ only).
    If not available, falls back to sequential execution.

.PARAMETER Credential
    Optional PSCredential object for remote authentication.
    If not provided, will prompt for credentials or use current user context.

.EXAMPLE
    .\Get-SecurityToolsStatus.ps1 -ServerListPath ".\servers.txt" -ConfigFile ".\migration-config.json"
    
    Checks security tools on all servers in servers.txt using settings from the config file.

.EXAMPLE
    .\Get-SecurityToolsStatus.ps1 -ComputerName "SERVER01" -OldDomainFqdn "oldco.com" -NewDomainFqdn "newco.com"
    
    Checks security tools on SERVER01 using default tenant mappings.

.EXAMPLE
    .\Get-SecurityToolsStatus.ps1 -ServerListPath ".\servers.txt" -UseParallel
    
    Checks security tools on all servers in parallel (PowerShell 7+).
#>

param(
    [Parameter(Mandatory = $false, ParameterSetName = 'SingleServer')]
    [string]$ComputerName,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'ServerList')]
    [string]$ServerListPath = ".\servers.txt",
    
    [Parameter(Mandatory = $false)]
    [string]$OldDomainFqdn,
    
    [Parameter(Mandatory = $false)]
    [string]$NewDomainFqdn,
    
    [string]$ConfigFile,
    
    [switch]$UseParallel,
    
    [switch]$AttemptWinRmHeal,
    
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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
#   After starting the service, waits 10 seconds, verifies the service is running, then retries the connectivity test once.
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
        
        [System.Management.Automation.PSCredential]$Credential
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
        
        # Step 2: Classify the error
        $failureCategory = Get-WinRmFailureCategory -ErrorMessage $initialError -ErrorRecord $errorRecord
        
        # Log the categorized error (brief to console)
        $errorMsg = "WinRM connectivity failed - categorized as $failureCategory. Error: $initialError"
        Write-Warning "[$ComputerName] WinRM failed: $failureCategory"
        
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
                $result.ErrorCategory = $failureCategory
                $result.ErrorMessage = $errorMsg
                return $result
            }
            
            # Step 4: Attempt to start WinRM service
            Write-Host "[$ComputerName] Attempting to start WinRM service via Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running..." -ForegroundColor Yellow
            $serviceStarted = $false
            
            try {
                # Use the exact command that works manually
                $service = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                
                if ($service.Status -eq 'Running') {
                    Write-Host "[$ComputerName] WinRM service is already running." -ForegroundColor Green
                    $serviceStarted = $true
                }
                else {
                    # Execute the exact pipeline command
                    Get-Service -Name winrm -ComputerName $ComputerName | Set-Service -Status Running -ErrorAction Stop
                    
                    # Wait a short period for the service to start
                    Start-Sleep -Seconds 10
                    
                    # Re-check the service status
                    $serviceCheck = Get-Service -Name winrm -ComputerName $ComputerName -ErrorAction Stop
                    if ($serviceCheck.Status -eq 'Running') {
                        Write-Host "[$ComputerName] WinRM service successfully started; retrying WinRM connectivity..." -ForegroundColor Green
                        $serviceStarted = $true
                    }
                    else {
                        $errorMsg = "WinRM heal failed; service not running after attempt. Status: $($serviceCheck.Status)"
                        Write-Warning "[$ComputerName] WinRM heal failed"
                        $result.ErrorCategory = $failureCategory
                        $result.ErrorMessage = $errorMsg
                        return $result
                    }
                }
            }
            catch {
                $serviceError = $_.Exception.Message
                $errorMsg = "Failed to start WinRM service: $serviceError"
                Write-Warning "[$ComputerName] WinRM service start failed"
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
                    Write-Warning "[$ComputerName] WinRM retry failed"
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
        Write-Warning "[$ComputerName] WinRM connection failed"
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
        $result.ErrorCategory = 'Unknown'
        $result.ErrorMessage = $errorMsg
        return $result
    }
}

<#
.SYNOPSIS
    Reads a registry value from both 32-bit and 64-bit views.
#>
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
                    $type = $k.GetValueKind($Name)
                    $asString = $null
                    switch ($type) {
                        'Binary' {
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

<#
.SYNOPSIS
    Checks for SCCM installation and tenant information.
#>
function Get-SCCMTenantInfo {
    [CmdletBinding()]
    param(
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn
    )
    
    $sccmRegPath = 'SOFTWARE\Microsoft\CCM'
    $domainReferences = @()
    $foundDomains = @()
    
    $searchDomains = @()
    if (-not [string]::IsNullOrWhiteSpace($OldDomainFqdn)) {
        $searchDomains += $OldDomainFqdn
    }
    if (-not [string]::IsNullOrWhiteSpace($NewDomainFqdn)) {
        $searchDomains += $NewDomainFqdn
    }
    
    # Safely check array count (handles deserialized arrays)
    $searchDomainsArray = @($searchDomains)
    $searchDomainsCount = 0
    try {
        $searchDomainsCount = $searchDomainsArray.Count
    } catch {
        try {
            $searchDomainsCount = ($searchDomainsArray | Measure-Object).Count
        } catch {
            $searchDomainsCount = 0
        }
    }
    
    if ($searchDomainsCount -eq 0) {
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
        $baseKey = [Microsoft.Win32.Registry]::LocalMachine
        $ccmKey = $baseKey.OpenSubKey($sccmRegPath)
        
        if ($null -eq $ccmKey) {
            return [pscustomobject]@{
                RegPath = "HKLM:\$sccmRegPath"
                Found = $false
                DomainReferences = @()
                FoundDomains = @()
                Tenant = 'Unknown'
                HasDomainReference = $false
            }
        }
        
        function Search-RegistryRecursive {
            param(
                [Microsoft.Win32.RegistryKey]$key,
                [string]$basePath,
                [string[]]$domains,
                [System.Collections.ArrayList]$results
            )
            
            try {
                $valueNames = $key.GetValueNames()
                foreach ($valueName in $valueNames) {
                    try {
                        $value = $key.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
                        if ($null -ne $value) {
                            $valuesToCheck = @()
                            if ($value -is [array]) {
                                $valuesToCheck = $value
                            } else {
                                $valuesToCheck = @([string]$value)
                            }
                            
                            foreach ($valueToCheck in $valuesToCheck) {
                                if ($null -ne $valueToCheck) {
                                    $valueStr = [string]$valueToCheck
                                    
                                    foreach ($domain in $domains) {
                                        $pattern = [regex]::new("(?i)" + [regex]::Escape($domain))
                                        if ($pattern.IsMatch($valueStr)) {
                                            $displayValue = if ($value -is [array]) { ($value -join ' | ') } else { $valueStr }
                                            $null = $results.Add([pscustomobject]@{
                                                Path = $basePath
                                                ValueName = $valueName
                                                Value = $displayValue
                                                Domain = $domain
                                            })
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    } catch {}
                }
                
                $subKeyNames = $key.GetSubKeyNames()
                foreach ($subKeyName in $subKeyNames) {
                    try {
                        $subKey = $key.OpenSubKey($subKeyName)
                        if ($null -ne $subKey) {
                            $newPath = if ($basePath) { "$basePath\$subKeyName" } else { $subKeyName }
                            Search-RegistryRecursive -key $subKey -basePath $newPath -domains $domains -results $results
                            $subKey.Close()
                        }
                    } catch {}
                }
            } catch {}
        }
        
        $resultsList = [System.Collections.ArrayList]::new()
        Search-RegistryRecursive -key $ccmKey -basePath $sccmRegPath -domains $searchDomains -results $resultsList
        $domainReferences = $resultsList.ToArray()
        $ccmKey.Close()
        
        $foundDomains = $domainReferences | Select-Object -ExpandProperty Domain -Unique
        # Ensure foundDomains is always an array (Select-Object -ExpandProperty can return a scalar)
        $foundDomains = @($foundDomains)
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
        # Safely check array count
        $foundDomainsCount = 0
        try {
            $foundDomainsCount = $foundDomains.Count
        } catch {
            try {
                $foundDomainsCount = ($foundDomains | Measure-Object).Count
            } catch {
                $foundDomainsCount = 0
            }
        }
        
        if ($foundDomainsCount -gt 0) {
            $hasDomainReference = $true
            if ($foundDomains -contains $NewDomainFqdn) {
                $sccmTenant = 'NewDomain'
            } elseif ($foundDomains -contains $OldDomainFqdn) {
                $sccmTenant = 'OldDomain'
            } else {
                # Safe array access - we know foundDomains is an array and has at least one element
                $sccmTenant = if ($foundDomainsCount -gt 0) { $foundDomains[0] } else { 'Unknown' }
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
#>
function Get-EncaseTenantInfo {
    [CmdletBinding()]
    param(
        [string[]]$EncaseRegistryPaths = @()
    )
    
    $serviceName = 'enstart64'
    $installed = $false
    $tenantKey = $null
    $tenant = 'Unknown'
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $installed = $true
        }
    } catch {}
    
    # Safely check if array has items (handles deserialized arrays that might not have .Count)
    $encasePathsArray = @($EncaseRegistryPaths)
    $hasItems = $false
    try {
        $hasItems = $null -ne $encasePathsArray -and $encasePathsArray.Count -gt 0
    } catch {
        # If .Count fails, try to enumerate to check if it has items
        try {
            $hasItems = ($encasePathsArray | Measure-Object).Count -gt 0
        } catch {
            $hasItems = $false
        }
    }
    if ($hasItems) {
        try {
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine
            $tenantKeys = @()
            
            foreach ($keyName in $encasePathsArray) {
                if (-not [string]::IsNullOrWhiteSpace($keyName)) {
                    $testPath = "SOFTWARE\Microsoft\$keyName"
                    try {
                        $testKey = $baseKey.OpenSubKey($testPath)
                        if ($null -ne $testKey) {
                            $tenantKeys += $keyName
                            $testKey.Close()
                        }
                    } catch {}
                }
            }
            
            # Safely check array count
            $tenantKeysCount = 0
            try {
                $tenantKeysCount = $tenantKeys.Count
            } catch {
                try {
                    $tenantKeysCount = ($tenantKeys | Measure-Object).Count
                } catch {
                    $tenantKeysCount = 0
                }
            }
            
            if ($tenantKeysCount -gt 0) {
                $tenantKey = $tenantKeys[0]
                $tenant = $tenantKey
            }
        } catch {}
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
#>
function Get-SecurityAgentsTenantInfo {
    [CmdletBinding()]
    param(
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn,
        [string[]]$EncaseRegistryPaths = @(),
        [hashtable]$CrowdStrikeTenantMap,
        [hashtable]$QualysTenantMap
    )

    # CrowdStrike (Falcon Sensor)
    $csRegPath = 'System\\CurrentControlSet\\Services\\CSAgent\\Sim'
    $csValName = 'CU'
    $cs = Get-RegistryValueMultiView -Hive LocalMachine -Path $csRegPath -Name $csValName
    $csHex = if ($cs) { $cs.String } else { $null }
    
    # Determine tenant name using user-configurable mapping (matches original script logic)
    if ($null -eq $csHex) {
        if ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey('UNKNOWN')) {
            $csTenant = $CrowdStrikeTenantMap['UNKNOWN']
        }
    } elseif ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey($csHex)) {
        $csTenant = $CrowdStrikeTenantMap[$csHex]
    } else {
        if ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey('DEFAULT')) {
            $csTenant = $CrowdStrikeTenantMap['DEFAULT']
        }
    }

    # Qualys
    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
    # Determine tenant name using user-configurable mapping (matches original script logic)
    if ($null -eq $qStr) {
        if ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey('UNKNOWN')) {
            $qTenant = $QualysTenantMap['UNKNOWN']
        }
    } elseif ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey($qStr)) {
        $qTenant = $QualysTenantMap[$qStr]
    } else {
        if ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey('DEFAULT')) {
            $qTenant = $QualysTenantMap['DEFAULT']
        }
    }

    # SCCM (Configuration Manager)
    $sccmInfo = Get-SCCMTenantInfo -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn

    # Encase
    $encaseInfo = Get-EncaseTenantInfo -EncaseRegistryPaths $EncaseRegistryPaths

    [pscustomobject]@{
        CrowdStrike = [pscustomobject]@{
            Installed = $null -ne $cs
            RegPath   = 'HKLM:\System\CurrentControlSet\Services\CSAgent\Sim'
            ValueName = $csValName
            Value     = $csHex
            Tenant    = $csTenant
        }
        Qualys = [pscustomobject]@{
            Installed = $null -ne $q
            RegPath   = 'HKLM:\Software\Qualys'
            ValueName = $qValName
            Value     = $qStr
            Tenant    = $qTenant
        }
        SCCM = [pscustomobject]@{
            Installed = $sccmInfo.Found
            RegPath   = $sccmInfo.RegPath
            Tenant    = $sccmInfo.Tenant
            HasDomainReference = $sccmInfo.HasDomainReference
            FoundDomains = $sccmInfo.FoundDomains
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

<#
.SYNOPSIS
    Loads configuration from JSON file.
#>
function Import-ConfigurationFile {
    param(
        [string]$ConfigFilePath,
        [hashtable]$CrowdStrikeTenantMap,
        [hashtable]$QualysTenantMap
    )
    
    if (-not (Test-Path -LiteralPath $ConfigFilePath)) {
        return @{
            OldDomainFqdn = $null
            NewDomainFqdn = $null
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
    }
    
    try {
        $configContent = Get-Content -Path $ConfigFilePath -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop
        
        $result = @{
            OldDomainFqdn = $null
            NewDomainFqdn = $null
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
        
        # Load domain settings from config file
        if ($config.PSObject.Properties['OldDomainFqdn']) {
            $result.OldDomainFqdn = $config.OldDomainFqdn
        }
        if ($config.PSObject.Properties['NewDomainFqdn']) {
            $result.NewDomainFqdn = $config.NewDomainFqdn
        }
        
        # Load CrowdStrike tenant map from config (if present, replaces defaults)
        if ($config.PSObject.Properties['CrowdStrikeTenantMap']) {
            $csMap = @{}
            $config.CrowdStrikeTenantMap.PSObject.Properties | ForEach-Object {
                $csMap[$_.Name] = $_.Value
            }
            $result.CrowdStrikeTenantMap = $csMap
        }
        
        # Load Qualys tenant map from config (if present, replaces defaults)
        if ($config.PSObject.Properties['QualysTenantMap']) {
            $qMap = @{}
            $config.QualysTenantMap.PSObject.Properties | ForEach-Object {
                $qMap[$_.Name] = $_.Value
            }
            $result.QualysTenantMap = $qMap
        }
        
        # Load Encase registry paths from config (if present, replaces defaults)
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
        Write-Warning "Failed to load configuration file '$ConfigFilePath': $($_.Exception.Message)"
        return @{
            OldDomainFqdn = $null
            NewDomainFqdn = $null
            CrowdStrikeTenantMap = $null
            QualysTenantMap = $null
            EncaseRegistryPaths = $null
        }
    }
}

<#
.SYNOPSIS
    Formats security tools result into a table row.
#>
function Format-SecurityToolsTableRow {
    param(
        [string]$ServerName,
        [object]$SecurityAgents
    )
    
    # Qualys: Tenant or "Not Installed"
    $qualysStatus = if ($SecurityAgents.Qualys.Installed) {
        $SecurityAgents.Qualys.Tenant
    } else {
        "Not Installed"
    }
    
    # CrowdStrike: Tenant or "Not Installed"
    $crowdStrikeStatus = if ($SecurityAgents.CrowdStrike.Installed) {
        $SecurityAgents.CrowdStrike.Tenant
    } else {
        "Not Installed"
    }
    
    # SCCM: Domains (comma-separated) or "Not Installed"
    $sccmStatus = if ($SecurityAgents.SCCM.Installed) {
        $foundDomainsArray = @($SecurityAgents.SCCM.FoundDomains)
        $foundDomainsCount = 0
        try {
            $foundDomainsCount = $foundDomainsArray.Count
        } catch {
            try {
                $foundDomainsCount = ($foundDomainsArray | Measure-Object).Count
            } catch {
                $foundDomainsCount = 0
            }
        }
        if ($SecurityAgents.SCCM.FoundDomains -and $foundDomainsCount -gt 0) {
            $foundDomainsArray -join ', '
        } else {
            "Installed (No Domains Found)"
        }
    } else {
        "Not Installed"
    }
    
    # Encase: "Installed" or "Not Installed"
    $encaseStatus = if ($SecurityAgents.Encase.Installed) {
        "Installed"
    } else {
        "Not Installed"
    }
    
    return [PSCustomObject]@{
        Server = $ServerName
        Qualys = $qualysStatus
        CrowdStrike = $crowdStrikeStatus
        SCCM = $sccmStatus
        Encase = $encaseStatus
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Default tenant maps
$defaultCrowdStrikeTenantMap = @{
    'DEFAULT' = 'Unknown'
    'UNKNOWN' = 'Not Installed'
}

$defaultQualysTenantMap = @{
    'DEFAULT' = 'Unknown'
    'UNKNOWN' = 'Not Installed'
}

$defaultEncaseRegistryPaths = @()

# Load configuration from file if provided (load domain settings early)
if ($ConfigFile) {
    $loadedConfig = Import-ConfigurationFile -ConfigFilePath $ConfigFile -CrowdStrikeTenantMap $defaultCrowdStrikeTenantMap -QualysTenantMap $defaultQualysTenantMap
    
    # Load domain settings from config file if not provided as parameters
    if ([string]::IsNullOrWhiteSpace($OldDomainFqdn) -and $loadedConfig.OldDomainFqdn) {
        $OldDomainFqdn = $loadedConfig.OldDomainFqdn
        Write-Host "Loaded OldDomainFqdn from config file: $OldDomainFqdn" -ForegroundColor Cyan
    }
    
    if ([string]::IsNullOrWhiteSpace($NewDomainFqdn) -and $loadedConfig.NewDomainFqdn) {
        $NewDomainFqdn = $loadedConfig.NewDomainFqdn
        Write-Host "Loaded NewDomainFqdn from config file: $NewDomainFqdn" -ForegroundColor Cyan
    }
    
    # Use config file tenant maps if provided, otherwise use defaults
    # This matches the behavior of Get-WorkstationDiscovery.ps1
    if ($loadedConfig.CrowdStrikeTenantMap) {
        Write-Host "Loaded CrowdStrikeTenantMap from config file" -ForegroundColor Cyan
        $configCrowdStrikeTenantMap = $loadedConfig.CrowdStrikeTenantMap
    } else {
        $configCrowdStrikeTenantMap = $defaultCrowdStrikeTenantMap
    }
    
    if ($loadedConfig.QualysTenantMap) {
        Write-Host "Loaded QualysTenantMap from config file" -ForegroundColor Cyan
        $configQualysTenantMap = $loadedConfig.QualysTenantMap
    } else {
        $configQualysTenantMap = $defaultQualysTenantMap
    }
    
    if ($loadedConfig.EncaseRegistryPaths) {
        Write-Host "Loaded EncaseRegistryPaths from config file" -ForegroundColor Cyan
        $configEncaseRegistryPaths = $loadedConfig.EncaseRegistryPaths
    } else {
        $configEncaseRegistryPaths = $defaultEncaseRegistryPaths
    }
    
    $config = @{
        CrowdStrikeTenantMap = $configCrowdStrikeTenantMap
        QualysTenantMap = $configQualysTenantMap
        EncaseRegistryPaths = $configEncaseRegistryPaths
    }
} else {
    $config = @{
        CrowdStrikeTenantMap = $defaultCrowdStrikeTenantMap
        QualysTenantMap = $defaultQualysTenantMap
        EncaseRegistryPaths = $defaultEncaseRegistryPaths
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

# Determine server list
$servers = @()
if ($PSCmdlet.ParameterSetName -eq 'ServerList') {
    if (-not (Test-Path -LiteralPath $ServerListPath)) {
        $errorMsg = "Server list file not found: $ServerListPath"
        Write-Error $errorMsg
        throw $errorMsg
    }
    
    # Read and de-duplicate server names (ignore blank/commented lines)
    $servers = @(Get-Content -Path $ServerListPath |
        Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique)
    
    if ($servers.Count -eq 0) {
        $errorMsg = "No servers found in list file: $ServerListPath"
        Write-Error $errorMsg
        throw $errorMsg
    }
    
    Write-Host "Found $($servers.Count) server(s) in list file" -ForegroundColor Cyan
} elseif ($ComputerName) {
    $servers = @($ComputerName)
} else {
    $errorMsg = "Either ComputerName or ServerListPath must be provided"
    Write-Error $errorMsg
    throw $errorMsg
}

# Get credentials if not provided
if (-not $Credential) {
    $cred = Get-Credential -Message "Enter credentials for remote servers (or press Cancel to use current user)"
    if ($cred) {
        $Credential = $cred
    }
}


# Build scriptblock with all necessary functions
# We need to define all functions inside the scriptblock for remote execution
$functionDefinitions = @'
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
                    $type = $k.GetValueKind($Name)
                    $asString = $null
                    switch ($type) {
                        'Binary' {
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

function Get-SCCMTenantInfo {
    [CmdletBinding()]
    param(
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn
    )
    
    $sccmRegPath = 'SOFTWARE\Microsoft\CCM'
    $domainReferences = @()
    $foundDomains = @()
    
    $searchDomains = @()
    if (-not [string]::IsNullOrWhiteSpace($OldDomainFqdn)) {
        $searchDomains += $OldDomainFqdn
    }
    if (-not [string]::IsNullOrWhiteSpace($NewDomainFqdn)) {
        $searchDomains += $NewDomainFqdn
    }
    
    # Safely check array count (handles deserialized arrays)
    $searchDomainsArray = @($searchDomains)
    $searchDomainsCount = 0
    try {
        $searchDomainsCount = $searchDomainsArray.Count
    } catch {
        try {
            $searchDomainsCount = ($searchDomainsArray | Measure-Object).Count
        } catch {
            $searchDomainsCount = 0
        }
    }
    
    if ($searchDomainsCount -eq 0) {
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
        $baseKey = [Microsoft.Win32.Registry]::LocalMachine
        $ccmKey = $baseKey.OpenSubKey($sccmRegPath)
        
        if ($null -eq $ccmKey) {
            return [pscustomobject]@{
                RegPath = "HKLM:\$sccmRegPath"
                Found = $false
                DomainReferences = @()
                FoundDomains = @()
                Tenant = 'Unknown'
                HasDomainReference = $false
            }
        }
        
        function Search-RegistryRecursive {
            param(
                [Microsoft.Win32.RegistryKey]$key,
                [string]$basePath,
                [string[]]$domains,
                [System.Collections.ArrayList]$results
            )
            
            try {
                $valueNames = $key.GetValueNames()
                foreach ($valueName in $valueNames) {
                    try {
                        $value = $key.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
                        if ($null -ne $value) {
                            $valuesToCheck = @()
                            if ($value -is [array]) {
                                $valuesToCheck = $value
                            } else {
                                $valuesToCheck = @([string]$value)
                            }
                            
                            foreach ($valueToCheck in $valuesToCheck) {
                                if ($null -ne $valueToCheck) {
                                    $valueStr = [string]$valueToCheck
                                    
                                    foreach ($domain in $domains) {
                                        $pattern = [regex]::new("(?i)" + [regex]::Escape($domain))
                                        if ($pattern.IsMatch($valueStr)) {
                                            $displayValue = if ($value -is [array]) { ($value -join ' | ') } else { $valueStr }
                                            $null = $results.Add([pscustomobject]@{
                                                Path = $basePath
                                                ValueName = $valueName
                                                Value = $displayValue
                                                Domain = $domain
                                            })
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    } catch {}
                }
                
                $subKeyNames = $key.GetSubKeyNames()
                foreach ($subKeyName in $subKeyNames) {
                    try {
                        $subKey = $key.OpenSubKey($subKeyName)
                        if ($null -ne $subKey) {
                            $newPath = if ($basePath) { "$basePath\$subKeyName" } else { $subKeyName }
                            Search-RegistryRecursive -key $subKey -basePath $newPath -domains $domains -results $results
                            $subKey.Close()
                        }
                    } catch {}
                }
            } catch {}
        }
        
        $resultsList = [System.Collections.ArrayList]::new()
        Search-RegistryRecursive -key $ccmKey -basePath $sccmRegPath -domains $searchDomains -results $resultsList
        $domainReferences = $resultsList.ToArray()
        $ccmKey.Close()
        
        $foundDomains = $domainReferences | Select-Object -ExpandProperty Domain -Unique
        # Ensure foundDomains is always an array (Select-Object -ExpandProperty can return a scalar)
        $foundDomains = @($foundDomains)
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
        # Safely check array count
        $foundDomainsCount = 0
        try {
            $foundDomainsCount = $foundDomains.Count
        } catch {
            try {
                $foundDomainsCount = ($foundDomains | Measure-Object).Count
            } catch {
                $foundDomainsCount = 0
            }
        }
        
        if ($foundDomainsCount -gt 0) {
            $hasDomainReference = $true
            if ($foundDomains -contains $NewDomainFqdn) {
                $sccmTenant = 'NewDomain'
            } elseif ($foundDomains -contains $OldDomainFqdn) {
                $sccmTenant = 'OldDomain'
            } else {
                # Safe array access - we know foundDomains is an array and has at least one element
                $sccmTenant = if ($foundDomainsCount -gt 0) { $foundDomains[0] } else { 'Unknown' }
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

function Get-EncaseTenantInfo {
    [CmdletBinding()]
    param(
        [string[]]$EncaseRegistryPaths = @()
    )
    
    $serviceName = 'enstart64'
    $installed = $false
    $tenantKey = $null
    $tenant = 'Unknown'
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $installed = $true
        }
    } catch {}
    
    # Safely check if array has items (handles deserialized arrays that might not have .Count)
    $encasePathsArray = @($EncaseRegistryPaths)
    $hasItems = $false
    try {
        $hasItems = $null -ne $encasePathsArray -and $encasePathsArray.Count -gt 0
    } catch {
        # If .Count fails, try to enumerate to check if it has items
        try {
            $hasItems = ($encasePathsArray | Measure-Object).Count -gt 0
        } catch {
            $hasItems = $false
        }
    }
    if ($hasItems) {
        try {
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine
            $tenantKeys = @()
            
            foreach ($keyName in $encasePathsArray) {
                if (-not [string]::IsNullOrWhiteSpace($keyName)) {
                    $testPath = "SOFTWARE\Microsoft\$keyName"
                    try {
                        $testKey = $baseKey.OpenSubKey($testPath)
                        if ($null -ne $testKey) {
                            $tenantKeys += $keyName
                            $testKey.Close()
                        }
                    } catch {}
                }
            }
            
            # Safely check array count
            $tenantKeysCount = 0
            try {
                $tenantKeysCount = $tenantKeys.Count
            } catch {
                try {
                    $tenantKeysCount = ($tenantKeys | Measure-Object).Count
                } catch {
                    $tenantKeysCount = 0
                }
            }
            
            if ($tenantKeysCount -gt 0) {
                $tenantKey = $tenantKeys[0]
                $tenant = $tenantKey
            }
        } catch {}
    }
    
    return [pscustomobject]@{
        Installed = $installed
        ServiceName = $serviceName
        RegPath = if ($tenantKey) { "HKLM:\SOFTWARE\Microsoft\$tenantKey" } else { $null }
        TenantKey = $tenantKey
        Tenant = $tenant
    }
}

function Get-SecurityAgentsTenantInfo {
    [CmdletBinding()]
    param(
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn,
        [string[]]$EncaseRegistryPaths = @(),
        [hashtable]$CrowdStrikeTenantMap,
        [hashtable]$QualysTenantMap
    )

    # CrowdStrike (Falcon Sensor)
    $csRegPath = 'System\\CurrentControlSet\\Services\\CSAgent\\Sim'
    $csValName = 'CU'
    $cs = Get-RegistryValueMultiView -Hive LocalMachine -Path $csRegPath -Name $csValName
    $csHex = if ($cs) { $cs.String } else { $null }
    
    # Determine tenant name using user-configurable mapping (matches original script logic)
    if ($null -eq $csHex) {
        if ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey('UNKNOWN')) {
            $csTenant = $CrowdStrikeTenantMap['UNKNOWN']
        }
    } elseif ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey($csHex)) {
        $csTenant = $CrowdStrikeTenantMap[$csHex]
    } else {
        if ($null -ne $CrowdStrikeTenantMap -and $CrowdStrikeTenantMap.ContainsKey('DEFAULT')) {
            $csTenant = $CrowdStrikeTenantMap['DEFAULT']
        }
    }

    # Qualys
    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
    # Determine tenant name using user-configurable mapping (matches original script logic)
    if ($null -eq $qStr) {
        if ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey('UNKNOWN')) {
            $qTenant = $QualysTenantMap['UNKNOWN']
        }
    } elseif ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey($qStr)) {
        $qTenant = $QualysTenantMap[$qStr]
    } else {
        if ($null -ne $QualysTenantMap -and $QualysTenantMap.ContainsKey('DEFAULT')) {
            $qTenant = $QualysTenantMap['DEFAULT']
        }
    }

    # SCCM (Configuration Manager)
    $sccmInfo = Get-SCCMTenantInfo -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn

    # Encase
    $encaseInfo = Get-EncaseTenantInfo -EncaseRegistryPaths $EncaseRegistryPaths

    [pscustomobject]@{
        CrowdStrike = [pscustomobject]@{
            Installed = $null -ne $cs
            RegPath   = 'HKLM:\System\CurrentControlSet\Services\CSAgent\Sim'
            ValueName = $csValName
            Value     = $csHex
            Tenant    = $csTenant
        }
        Qualys = [pscustomobject]@{
            Installed = $null -ne $q
            RegPath   = 'HKLM:\Software\Qualys'
            ValueName = $qValName
            Value     = $qStr
            Tenant    = $qTenant
        }
        SCCM = [pscustomobject]@{
            Installed = $sccmInfo.Found
            RegPath   = $sccmInfo.RegPath
            Tenant    = $sccmInfo.Tenant
            HasDomainReference = $sccmInfo.HasDomainReference
            FoundDomains = $sccmInfo.FoundDomains
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
'@

$securityCheckScriptBlock = [scriptblock]::Create(@"
$functionDefinitions

# Access arguments via $args array
`$OldDomainFqdn = `$args[0]
`$NewDomainFqdn = `$args[1]
`$EncaseRegistryPaths = `$args[2]
`$CrowdStrikeTenantMap = `$args[3]
`$QualysTenantMap = `$args[4]

# Ensure EncaseRegistryPaths is properly converted to array (Invoke-Command may deserialize it incorrectly)
# Use @() to force array conversion - this handles null, single values, PSCustomObjects, and nested arrays
`$EncaseRegistryPaths = @(`$EncaseRegistryPaths)

# Ensure hashtables are properly converted (Invoke-Command may deserialize them as PSCustomObjects)
if (`$null -eq `$CrowdStrikeTenantMap) {
    `$CrowdStrikeTenantMap = @{}
} elseif (`$CrowdStrikeTenantMap -isnot [hashtable]) {
    `$temp = @{}
    `$CrowdStrikeTenantMap.PSObject.Properties | ForEach-Object { `$temp[`$_.Name] = `$_.Value }
    `$CrowdStrikeTenantMap = `$temp
}
if (`$null -eq `$QualysTenantMap) {
    `$QualysTenantMap = @{}
} elseif (`$QualysTenantMap -isnot [hashtable]) {
    `$temp = @{}
    `$QualysTenantMap.PSObject.Properties | ForEach-Object { `$temp[`$_.Name] = `$_.Value }
    `$QualysTenantMap = `$temp
}

# Execute security check
Get-SecurityAgentsTenantInfo -OldDomainFqdn `$OldDomainFqdn -NewDomainFqdn `$NewDomainFqdn -EncaseRegistryPaths `$EncaseRegistryPaths -CrowdStrikeTenantMap `$CrowdStrikeTenantMap -QualysTenantMap `$QualysTenantMap
"@)

# Function to check security tools on a single server
function Invoke-SecurityCheckOnServer {
    param(
        [string]$ServerName,
        [string]$OldDomainFqdn,
        [string]$NewDomainFqdn,
        [string[]]$EncaseRegistryPaths,
        [hashtable]$CrowdStrikeTenantMap,
        [hashtable]$QualysTenantMap,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$SecurityCheckScriptBlock,
        [switch]$AttemptWinRmHeal
    )
    
    $result = [PSCustomObject]@{
        Server = $ServerName
        Qualys = "Error"
        CrowdStrike = "Error"
        SCCM = "Error"
        Encase = "Error"
        Success = $false
    }
    
    # Use the centralized WinRM helper to establish connectivity and run the security check
    $remoteScriptArguments = @(
        $OldDomainFqdn,
        $NewDomainFqdn,
        $EncaseRegistryPaths,
        $CrowdStrikeTenantMap,
        $QualysTenantMap
    )
    
    $winRmResult = Ensure-WinRmAndConnect `
        -ComputerName $ServerName `
        -RemoteScriptBlock $SecurityCheckScriptBlock `
        -RemoteScriptArguments $remoteScriptArguments `
        -AttemptWinRmHeal:$AttemptWinRmHeal `
        -Credential $Credential
    
    # Check if WinRM connection and script execution succeeded
    if (-not $winRmResult.Success) {
        $result.Qualys = "Connection Failed"
        $result.CrowdStrike = "Connection Failed"
        $result.SCCM = "Connection Failed"
        $result.Encase = "Connection Failed"
        return $result
    }
    
    # Format result
    $securityAgents = $winRmResult.Output
    $formatted = Format-SecurityToolsTableRow -ServerName $ServerName -SecurityAgents $securityAgents
    $result.Server = $formatted.Server
    $result.Qualys = $formatted.Qualys
    $result.CrowdStrike = $formatted.CrowdStrike
    $result.SCCM = $formatted.SCCM
    $result.Encase = $formatted.Encase
    $result.Success = $true
    Write-Host "Security check completed successfully for $ServerName" -ForegroundColor Green
    
    return $result
}

# Process servers
$results = @()

if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
    # PowerShell 7+ parallel execution
    try {
        $null = Get-Command ForEach-Object -ParameterName Parallel -ErrorAction Stop
        $results = $servers | ForEach-Object -Parallel {
            # Recreate helper functions in the parallel context
            function Get-WinRmFailureCategory {
                param(
                    [Parameter(Mandatory)]
                    [string]$ErrorMessage,
                    [Parameter(Mandatory)]
                    [System.Management.Automation.ErrorRecord]$ErrorRecord
                )
                if ($ErrorMessage -match 'access is denied' -or $ErrorMessage -match '401' -or $ErrorMessage -match '403' -or
                    $ErrorMessage -match 'unauthorized' -or $ErrorMessage -match 'authentication failed' -or
                    $ErrorMessage -match 'Kerberos' -or $ErrorMessage -match 'NTLM' -or $ErrorMessage -match 'credential' -or
                    $ErrorRecord.CategoryInfo.Category -eq 'AuthenticationError' -or $ErrorRecord.CategoryInfo.Category -eq 'SecurityError') {
                    return 'AuthError'
                }
                if ($ErrorMessage -match 'WinRM cannot complete the operation' -or $ErrorMessage -match 'The network path was not found' -or
                    $ErrorMessage -match 'No connection could be made' -or $ErrorMessage -match 'cannot resolve' -or
                    $ErrorMessage -match 'host.*not found' -or $ErrorMessage -match 'RPC server is unavailable' -or
                    $ErrorMessage -match 'network is unreachable' -or ($ErrorRecord.CategoryInfo.Category -eq 'InvalidOperation' -and $ErrorMessage -match 'network')) {
                    return 'NetworkError'
                }
                if ($ErrorMessage -match 'WinRM service' -or $ErrorMessage -match 'The WinRM client cannot process the request' -or
                    $ErrorMessage -match 'WS-Management service' -or $ErrorMessage -match 'service.*not running' -or
                    ($ErrorMessage -match 'cannot connect' -and $ErrorMessage -match 'WinRM') -or
                    $ErrorRecord.Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException] -or
                    $ErrorRecord.FullyQualifiedErrorId -match 'WinRM') {
                    return 'WinRmServiceError'
                }
                return 'Unknown'
            }
            
            function Ensure-WinRmAndConnect {
                param(
                    [Parameter(Mandatory)][string]$ComputerName,
                    [Parameter(Mandatory)][scriptblock]$RemoteScriptBlock,
                    [array]$RemoteScriptArguments = @(),
                    [switch]$AttemptWinRmHeal,
                    [System.Management.Automation.PSCredential]$Credential
                )
                $result = @{ Success = $false; ErrorCategory = $null; ErrorMessage = $null; Output = $null; ActualComputerName = $null }
                Write-Host "[$ComputerName] Testing WinRM connectivity..." -ForegroundColor Yellow
                $connectivityTestPassed = $false
                $actualComputerName = $null
                try {
                    $testParams = @{ ComputerName = $ComputerName; ScriptBlock = { $env:COMPUTERNAME }; ErrorAction = 'Stop' }
                    if ($Credential) { $testParams['Credential'] = $Credential }
                    if ($PSVersionTable.PSVersion.Major -ge 5) { $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30 }
                    $testResult = Invoke-Command @testParams
                    $actualComputerName = $testResult
                    $connectivityTestPassed = $true
                    Write-Host "[$ComputerName] WinRM connectivity successful (remote computer: $testResult)" -ForegroundColor Green
                }
                catch {
                    $initialError = $_.Exception.Message
                    $errorRecord = $_
                    $failureCategory = Get-WinRmFailureCategory -ErrorMessage $initialError -ErrorRecord $errorRecord
                    $errorMsg = "WinRM connectivity failed - categorized as $failureCategory. Error: $initialError"
                    Write-Warning "[$ComputerName] WinRM failed: $failureCategory"
                    if ($failureCategory -eq 'AuthError' -or $failureCategory -eq 'NetworkError') {
                        $result.ErrorCategory = $failureCategory
                        $result.ErrorMessage = $errorMsg
                        return $result
                    }
                    if ($failureCategory -eq 'WinRmServiceError' -or $failureCategory -eq 'Unknown') {
                        if (-not $AttemptWinRmHeal) {
                            $errorMsg = "WinRM is not available and healing is disabled. Category: $failureCategory. Error: $initialError"
                            Write-Warning "[$ComputerName] WinRM unavailable (healing disabled)"
                            $result.ErrorCategory = $failureCategory
                            $result.ErrorMessage = $errorMsg
                            return $result
                        }
                        Write-Host "[$ComputerName] Attempting to start WinRM service..." -ForegroundColor Yellow
                        $serviceStarted = $false
                        try {
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
                                    $result.ErrorCategory = $failureCategory
                                    $result.ErrorMessage = $errorMsg
                                    return $result
                                }
                            }
                        }
                        catch {
                            $serviceError = $_.Exception.Message
                            $errorMsg = "Failed to start WinRM service: $serviceError"
                            Write-Warning "[$ComputerName] WinRM service start failed"
                            $result.ErrorCategory = $failureCategory
                            $result.ErrorMessage = $errorMsg
                            return $result
                        }
                        if ($serviceStarted) {
                            Write-Host "[$ComputerName] Retrying WinRM connectivity test..." -ForegroundColor Yellow
                            try {
                                $testParams = @{ ComputerName = $ComputerName; ScriptBlock = { $env:COMPUTERNAME }; ErrorAction = 'Stop' }
                                if ($Credential) { $testParams['Credential'] = $Credential }
                                if ($PSVersionTable.PSVersion.Major -ge 5) { $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30 }
                                $testResult = Invoke-Command @testParams
                                $actualComputerName = $testResult
                                $connectivityTestPassed = $true
                                Write-Host "[$ComputerName] WinRM connectivity successful after heal (remote computer: $testResult)" -ForegroundColor Green
                            }
                            catch {
                                $retryError = $_.Exception.Message
                                $errorMsg = "WinRM connection failed after attempting to start service. Initial error: $initialError. Retry error: $retryError"
                                Write-Warning "[$ComputerName] WinRM retry failed"
                                $result.ErrorCategory = $failureCategory
                                $result.ErrorMessage = $errorMsg
                                return $result
                            }
                        }
                    }
                }
                if (-not $connectivityTestPassed) {
                    $errorMsg = "WinRM connectivity failed: Unable to establish connection"
                    Write-Warning "[$ComputerName] WinRM connection failed"
                    $result.ErrorCategory = 'Unknown'
                    $result.ErrorMessage = $errorMsg
                    return $result
                }
                try {
                    $invokeParams = @{ ComputerName = $ComputerName; ScriptBlock = $RemoteScriptBlock; ErrorAction = 'Stop' }
                    if ($Credential) { $invokeParams['Credential'] = $Credential }
                    if ($PSVersionTable.PSVersion.Major -ge 5) { $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout 300 }
                    if ($RemoteScriptArguments -and $RemoteScriptArguments.Count -gt 0) { $invokeParams['ArgumentList'] = $RemoteScriptArguments }
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
                    $result.ErrorCategory = 'Unknown'
                    $result.ErrorMessage = $errorMsg
                    return $result
                }
            }
            
            function Invoke-SecurityCheckOnServer {
                param(
                    [string]$ServerName,
                    [string]$OldDomainFqdn,
                    [string]$NewDomainFqdn,
                    [string[]]$EncaseRegistryPaths,
                    [hashtable]$CrowdStrikeTenantMap,
                    [hashtable]$QualysTenantMap,
                    [System.Management.Automation.PSCredential]$Credential,
                    [scriptblock]$SecurityCheckScriptBlock,
                    [switch]$AttemptWinRmHeal
                )
                
                $result = [PSCustomObject]@{
                    Server = $ServerName
                    Qualys = "Error"
                    CrowdStrike = "Error"
                    SCCM = "Error"
                    Encase = "Error"
                    Success = $false
                }
                
                $remoteScriptArguments = @($OldDomainFqdn, $NewDomainFqdn, $EncaseRegistryPaths, $CrowdStrikeTenantMap, $QualysTenantMap)
                $winRmResult = Ensure-WinRmAndConnect -ComputerName $ServerName -RemoteScriptBlock $SecurityCheckScriptBlock -RemoteScriptArguments $remoteScriptArguments -AttemptWinRmHeal:$AttemptWinRmHeal -Credential $Credential
                
                if (-not $winRmResult.Success) {
                    $result.Qualys = "Connection Failed"
                    $result.CrowdStrike = "Connection Failed"
                    $result.SCCM = "Connection Failed"
                    $result.Encase = "Connection Failed"
                    return $result
                }
                
                    $securityAgents = $winRmResult.Output
                    
                    # Format result inline (can't use external function in parallel)
                    $qualysStatus = if ($securityAgents.Qualys.Installed) { $securityAgents.Qualys.Tenant } else { "Not Installed" }
                    $crowdStrikeStatus = if ($securityAgents.CrowdStrike.Installed) { $securityAgents.CrowdStrike.Tenant } else { "Not Installed" }
                    $sccmStatus = if ($securityAgents.SCCM.Installed) {
                        $foundDomainsArray = @($securityAgents.SCCM.FoundDomains)
                        $foundDomainsCount = 0
                        try {
                            $foundDomainsCount = $foundDomainsArray.Count
                        } catch {
                            try {
                                $foundDomainsCount = ($foundDomainsArray | Measure-Object).Count
                            } catch {
                                $foundDomainsCount = 0
                            }
                        }
                        if ($securityAgents.SCCM.FoundDomains -and $foundDomainsCount -gt 0) {
                            $foundDomainsArray -join ', '
                        } else {
                            "Installed (No Domains Found)"
                        }
                    } else {
                        "Not Installed"
                    }
                    $encaseStatus = if ($securityAgents.Encase.Installed) { "Installed" } else { "Not Installed" }
                    
                    $result.Server = $ServerName
                    $result.Qualys = $qualysStatus
                    $result.CrowdStrike = $crowdStrikeStatus
                    $result.SCCM = $sccmStatus
                    $result.Encase = $encaseStatus
                    $result.Success = $true
                    Write-Host "Security check completed successfully for $ServerName" -ForegroundColor Green
                
                return $result
            }
            
            Invoke-SecurityCheckOnServer `
                -ServerName $_ `
                -OldDomainFqdn $using:OldDomainFqdn `
                -NewDomainFqdn $using:NewDomainFqdn `
                -EncaseRegistryPaths $using:config.EncaseRegistryPaths `
                -CrowdStrikeTenantMap $using:config.CrowdStrikeTenantMap `
                -QualysTenantMap $using:config.QualysTenantMap `
                -Credential $using:Credential `
                -SecurityCheckScriptBlock $using:securityCheckScriptBlock `
                -AttemptWinRmHeal:$using:AttemptWinRmHeal
        } -ThrottleLimit 10
    }
    catch {
        Write-Warning "Parallel execution not available. Using sequential execution."
        $UseParallel = $false
    }
}

if (-not $UseParallel -or $PSVersionTable.PSVersion.Major -lt 7) {
    # Sequential execution
    foreach ($server in $servers) {
        Write-Host "Checking $server..." -ForegroundColor Yellow
        $result = Invoke-SecurityCheckOnServer `
            -ServerName $server `
            -OldDomainFqdn $OldDomainFqdn `
            -NewDomainFqdn $NewDomainFqdn `
            -EncaseRegistryPaths $config.EncaseRegistryPaths `
            -CrowdStrikeTenantMap $config.CrowdStrikeTenantMap `
            -QualysTenantMap $config.QualysTenantMap `
            -Credential $Credential `
            -SecurityCheckScriptBlock $securityCheckScriptBlock `
            -AttemptWinRmHeal:$AttemptWinRmHeal
        $results += $result
    }
}

# Display results table
Write-Host "`n" + ("="*100) -ForegroundColor Cyan
Write-Host "Security Tools Status Summary" -ForegroundColor Cyan
Write-Host ("="*100) -ForegroundColor Cyan
$results | Format-Table -AutoSize -Property Server, Qualys, CrowdStrike, SCCM, Encase
Write-Host ("="*100) -ForegroundColor Cyan

