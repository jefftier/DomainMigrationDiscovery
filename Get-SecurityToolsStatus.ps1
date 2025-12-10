#Requires -Version 5.1
<#
.SYNOPSIS
    Checks security tools status for a specific server remotely.

.DESCRIPTION
    This script connects to a remote server via WinRM and checks the status of security tools:
    - CrowdStrike (Falcon Sensor)
    - Qualys
    - SCCM (Configuration Manager)
    - Encase
    
    The results are displayed in a formatted console output showing the installation status
    and tenant configuration for each security tool.

.PARAMETER ComputerName
    The name or IP address of the remote server to check.

.PARAMETER OldDomainFqdn
    Fully Qualified Domain Name (FQDN) of the old domain (required for SCCM detection).
    Example: 'olddomain.com'

.PARAMETER NewDomainFqdn
    Fully Qualified Domain Name (FQDN) of the new domain (required for SCCM detection).
    Example: 'newdomain.com'

.PARAMETER ConfigFile
    Optional path to JSON configuration file for tenant mappings and Encase registry paths.
    If not provided, default mappings will be used.

.PARAMETER Credential
    Optional PSCredential object for remote authentication.
    If not provided, will prompt for credentials or use current user context.

.EXAMPLE
    .\Get-SecurityToolsStatus.ps1 -ComputerName "SERVER01" -OldDomainFqdn "oldco.com" -NewDomainFqdn "newco.com"
    
    Checks security tools on SERVER01 using default tenant mappings.

.EXAMPLE
    .\Get-SecurityToolsStatus.ps1 -ComputerName "SERVER01" -OldDomainFqdn "oldco.com" -NewDomainFqdn "newco.com" -ConfigFile ".\migration-config.json"
    
    Checks security tools on SERVER01 using tenant mappings from the config file.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,
    
    [Parameter(Mandatory = $true)]
    [string]$OldDomainFqdn,
    
    [Parameter(Mandatory = $true)]
    [string]$NewDomainFqdn,
    
    [string]$ConfigFile,
    
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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
    
    if ($searchDomains.Count -eq 0) {
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
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
        if ($foundDomains.Count -gt 0) {
            $hasDomainReference = $true
            if ($foundDomains -contains $NewDomainFqdn) {
                $sccmTenant = 'NewDomain'
            } elseif ($foundDomains -contains $OldDomainFqdn) {
                $sccmTenant = 'OldDomain'
            } else {
                $sccmTenant = $foundDomains[0]
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
    
    if ($EncaseRegistryPaths.Count -gt 0) {
        try {
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine
            $tenantKeys = @()
            
            foreach ($keyName in $EncaseRegistryPaths) {
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
            
            if ($tenantKeys.Count -gt 0) {
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
    
    $csTenant = 'Unknown'
    if ($null -eq $csHex) {
        if ($CrowdStrikeTenantMap.ContainsKey('UNKNOWN')) {
            $csTenant = $CrowdStrikeTenantMap['UNKNOWN']
        }
    } elseif ($CrowdStrikeTenantMap.ContainsKey($csHex)) {
        $csTenant = $CrowdStrikeTenantMap[$csHex]
    } else {
        if ($CrowdStrikeTenantMap.ContainsKey('DEFAULT')) {
            $csTenant = $CrowdStrikeTenantMap['DEFAULT']
        }
    }

    # Qualys
    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
    $qTenant = 'Unknown'
    if ($null -eq $qStr) {
        if ($QualysTenantMap.ContainsKey('UNKNOWN')) {
            $qTenant = $QualysTenantMap['UNKNOWN']
        }
    } elseif ($QualysTenantMap.ContainsKey($qStr)) {
        $qTenant = $QualysTenantMap[$qStr]
    } else {
        if ($QualysTenantMap.ContainsKey('DEFAULT')) {
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
            CrowdStrikeTenantMap = $CrowdStrikeTenantMap
            QualysTenantMap = $QualysTenantMap
            EncaseRegistryPaths = @()
        }
    }
    
    try {
        $configContent = Get-Content -Path $ConfigFilePath -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop
        
        $result = @{
            CrowdStrikeTenantMap = $CrowdStrikeTenantMap
            QualysTenantMap = $QualysTenantMap
            EncaseRegistryPaths = @()
        }
        
        if ($config.PSObject.Properties['CrowdStrikeTenantMap']) {
            $csMap = @{}
            $config.CrowdStrikeTenantMap.PSObject.Properties | ForEach-Object {
                $csMap[$_.Name] = $_.Value
            }
            $result.CrowdStrikeTenantMap = $csMap
        }
        
        if ($config.PSObject.Properties['QualysTenantMap']) {
            $qMap = @{}
            $config.QualysTenantMap.PSObject.Properties | ForEach-Object {
                $qMap[$_.Name] = $_.Value
            }
            $result.QualysTenantMap = $qMap
        }
        
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
            CrowdStrikeTenantMap = $CrowdStrikeTenantMap
            QualysTenantMap = $QualysTenantMap
            EncaseRegistryPaths = @()
        }
    }
}

<#
.SYNOPSIS
    Formats and displays security tools status to console.
#>
function Format-SecurityToolsOutput {
    param(
        [string]$ComputerName,
        [object]$SecurityAgents
    )
    
    Write-Host "`n" + ("="*80) -ForegroundColor Cyan
    Write-Host "Security Tools Status for: $ComputerName" -ForegroundColor Cyan
    Write-Host ("="*80) -ForegroundColor Cyan
    Write-Host ""
    
    # CrowdStrike
    Write-Host "CrowdStrike (Falcon Sensor):" -ForegroundColor Yellow
    if ($SecurityAgents.CrowdStrike.Installed) {
        Write-Host "  Status:      " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        Write-Host "  Registry:    $($SecurityAgents.CrowdStrike.RegPath)" -ForegroundColor Gray
        Write-Host "  Value Name:  $($SecurityAgents.CrowdStrike.ValueName)" -ForegroundColor Gray
        Write-Host "  Value:       $($SecurityAgents.CrowdStrike.Value)" -ForegroundColor Gray
        Write-Host "  Tenant:      " -NoNewline
        Write-Host "$($SecurityAgents.CrowdStrike.Tenant)" -ForegroundColor Cyan
    } else {
        Write-Host "  Status:      " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    Write-Host ""
    
    # Qualys
    Write-Host "Qualys:" -ForegroundColor Yellow
    if ($SecurityAgents.Qualys.Installed) {
        Write-Host "  Status:      " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        Write-Host "  Registry:    $($SecurityAgents.Qualys.RegPath)" -ForegroundColor Gray
        Write-Host "  Value Name:  $($SecurityAgents.Qualys.ValueName)" -ForegroundColor Gray
        Write-Host "  Value:       $($SecurityAgents.Qualys.Value)" -ForegroundColor Gray
        Write-Host "  Tenant:      " -NoNewline
        Write-Host "$($SecurityAgents.Qualys.Tenant)" -ForegroundColor Cyan
    } else {
        Write-Host "  Status:      " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    Write-Host ""
    
    # SCCM
    Write-Host "SCCM (Configuration Manager):" -ForegroundColor Yellow
    if ($SecurityAgents.SCCM.Installed) {
        Write-Host "  Status:      " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        Write-Host "  Registry:    $($SecurityAgents.SCCM.RegPath)" -ForegroundColor Gray
        Write-Host "  Tenant:      " -NoNewline
        Write-Host "$($SecurityAgents.SCCM.Tenant)" -ForegroundColor Cyan
        if ($SecurityAgents.SCCM.HasDomainReference) {
            Write-Host "  Domains:     " -NoNewline
            Write-Host "$($SecurityAgents.SCCM.FoundDomains -join ', ')" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Status:      " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    Write-Host ""
    
    # Encase
    Write-Host "Encase:" -ForegroundColor Yellow
    if ($SecurityAgents.Encase.Installed) {
        Write-Host "  Status:      " -NoNewline
        Write-Host "INSTALLED" -ForegroundColor Green
        Write-Host "  Service:     $($SecurityAgents.Encase.ServiceName)" -ForegroundColor Gray
        if ($SecurityAgents.Encase.RegPath) {
            Write-Host "  Registry:    $($SecurityAgents.Encase.RegPath)" -ForegroundColor Gray
        }
        Write-Host "  Tenant Key:  $($SecurityAgents.Encase.TenantKey)" -ForegroundColor Gray
        Write-Host "  Tenant:      " -NoNewline
        Write-Host "$($SecurityAgents.Encase.Tenant)" -ForegroundColor Cyan
    } else {
        Write-Host "  Status:      " -NoNewline
        Write-Host "NOT INSTALLED" -ForegroundColor Red
    }
    Write-Host ""
    
    Write-Host ("="*80) -ForegroundColor Cyan
    Write-Host ""
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

# Load configuration from file if provided
$config = @{
    CrowdStrikeTenantMap = $defaultCrowdStrikeTenantMap
    QualysTenantMap = $defaultQualysTenantMap
    EncaseRegistryPaths = $defaultEncaseRegistryPaths
}

if ($ConfigFile) {
    $loadedConfig = Import-ConfigurationFile -ConfigFilePath $ConfigFile -CrowdStrikeTenantMap $defaultCrowdStrikeTenantMap -QualysTenantMap $defaultQualysTenantMap
    $config = $loadedConfig
}

# Get credentials if not provided
if (-not $Credential) {
    $cred = Get-Credential -Message "Enter credentials for $ComputerName (or press Cancel to use current user)"
    if ($cred) {
        $Credential = $cred
    }
}

Write-Host "Connecting to $ComputerName..." -ForegroundColor Yellow

# Test connectivity
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
    
    $actualComputerName = Invoke-Command @testParams
    Write-Host "Successfully connected to: $actualComputerName" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to $ComputerName : $($_.Exception.Message)"
    exit 1
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
    
    if ($searchDomains.Count -eq 0) {
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
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
        if ($foundDomains.Count -gt 0) {
            $hasDomainReference = $true
            if ($foundDomains -contains $NewDomainFqdn) {
                $sccmTenant = 'NewDomain'
            } elseif ($foundDomains -contains $OldDomainFqdn) {
                $sccmTenant = 'OldDomain'
            } else {
                $sccmTenant = $foundDomains[0]
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
    
    if ($EncaseRegistryPaths.Count -gt 0) {
        try {
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine
            $tenantKeys = @()
            
            foreach ($keyName in $EncaseRegistryPaths) {
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
            
            if ($tenantKeys.Count -gt 0) {
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
    
    $csTenant = 'Unknown'
    if ($null -eq $csHex) {
        if ($CrowdStrikeTenantMap.ContainsKey('UNKNOWN')) {
            $csTenant = $CrowdStrikeTenantMap['UNKNOWN']
        }
    } elseif ($CrowdStrikeTenantMap.ContainsKey($csHex)) {
        $csTenant = $CrowdStrikeTenantMap[$csHex]
    } else {
        if ($CrowdStrikeTenantMap.ContainsKey('DEFAULT')) {
            $csTenant = $CrowdStrikeTenantMap['DEFAULT']
        }
    }

    # Qualys
    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
    $qTenant = 'Unknown'
    if ($null -eq $qStr) {
        if ($QualysTenantMap.ContainsKey('UNKNOWN')) {
            $qTenant = $QualysTenantMap['UNKNOWN']
        }
    } elseif ($QualysTenantMap.ContainsKey($qStr)) {
        $qTenant = $QualysTenantMap[$qStr]
    } else {
        if ($QualysTenantMap.ContainsKey('DEFAULT')) {
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

param(
    [string]`$OldDomainFqdn,
    [string]`$NewDomainFqdn,
    [string[]]`$EncaseRegistryPaths,
    [hashtable]`$CrowdStrikeTenantMap,
    [hashtable]`$QualysTenantMap
)

# Execute security check
Get-SecurityAgentsTenantInfo `
    -OldDomainFqdn `$OldDomainFqdn `
    -NewDomainFqdn `$NewDomainFqdn `
    -EncaseRegistryPaths `$EncaseRegistryPaths `
    -CrowdStrikeTenantMap `$CrowdStrikeTenantMap `
    -QualysTenantMap `$QualysTenantMap
"@)

# Execute remote security check
try {
    Write-Host "Checking security tools..." -ForegroundColor Yellow
    
    $invokeParams = @{
        ComputerName = $ComputerName
        ScriptBlock  = $securityCheckScriptBlock
        ArgumentList = @(
            $OldDomainFqdn,
            $NewDomainFqdn,
            ,$config.EncaseRegistryPaths,
            $config.CrowdStrikeTenantMap,
            $config.QualysTenantMap
        )
        ErrorAction  = 'Stop'
    }
    
    if ($Credential) {
        $invokeParams['Credential'] = $Credential
    }
    
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout 300
    }
    
    $securityAgents = Invoke-Command @invokeParams
    
    # Display results
    Format-SecurityToolsOutput -ComputerName $ComputerName -SecurityAgents $securityAgents
}
catch {
    Write-Error "Failed to check security tools on $ComputerName : $($_.Exception.Message)"
    exit 1
}

