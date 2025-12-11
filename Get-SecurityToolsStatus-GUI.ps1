#Requires -Version 5.1
<#
.SYNOPSIS
    GUI version of Get-SecurityToolsStatus - Checks security tools status for one or more servers remotely.

.DESCRIPTION
    This script provides a graphical user interface for checking security tools on remote servers:
    - CrowdStrike (Falcon Sensor)
    - Qualys
    - SCCM (Configuration Manager)
    - Encase
    
    Features:
    - Credential prompt at startup
    - Server list input via text area
    - Real-time results display in a table
    - Background processing to keep UI responsive
    - Progress indication

.EXAMPLE
    .\Get-SecurityToolsStatus-GUI.ps1
    
    Launches the GUI application for checking security tools status.
#>

# Add WPF and Windows Forms assemblies
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# ============================================================================
# HELPER FUNCTIONS (from original script)
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
                    return [pscustomobject]@{
                        Raw=$raw
                        Kind=$type
                        String=$asString
                    }
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
        $foundDomains = @($foundDomains)
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
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
    
    $encasePathsArray = @($EncaseRegistryPaths)
    $hasItems = $false
    try {
        $hasItems = $null -ne $encasePathsArray -and $encasePathsArray.Count -gt 0
    } catch {
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
        
        if ($config.PSObject.Properties['OldDomainFqdn']) {
            $result.OldDomainFqdn = $config.OldDomainFqdn
        }
        if ($config.PSObject.Properties['NewDomainFqdn']) {
            $result.NewDomainFqdn = $config.NewDomainFqdn
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
    
    $qualysStatus = if ($SecurityAgents.Qualys.Installed) {
        $SecurityAgents.Qualys.Tenant
    } else {
        "Not Installed"
    }
    
    $crowdStrikeStatus = if ($SecurityAgents.CrowdStrike.Installed) {
        $SecurityAgents.CrowdStrike.Tenant
    } else {
        "Not Installed"
    }
    
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
# GUI FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Updates UI controls from a background thread (thread-safe).
#>
function Update-UIElement {
    param(
        [System.Windows.Controls.Control]$Control,
        [scriptblock]$ScriptBlock
    )
    
    if ($Control.Dispatcher.CheckAccess()) {
        & $ScriptBlock
    } else {
        $Control.Dispatcher.Invoke([action]$ScriptBlock)
    }
}

<#
.SYNOPSIS
    Prompts for credentials at startup.
#>
function Get-CredentialDialog {
    $cred = Get-Credential -Message "Enter credentials for remote servers (or press Cancel to use current user)"
    return $cred
}

<#
.SYNOPSIS
    Creates and shows the main GUI window.
#>
function Show-SecurityToolsGUI {
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
    
    # Create main window
    $window = New-Object System.Windows.Window
    $window.Title = "Security Tools Status Checker"
    $window.Width = 1200
    $window.Height = 800
    $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
    $window.ResizeMode = [System.Windows.ResizeMode]::CanResize
    
    # Create main grid
    $mainGrid = New-Object System.Windows.Controls.Grid
    $mainGrid.Margin = New-Object System.Windows.Thickness(10)
    
    # Define rows
    $rowDef1 = New-Object System.Windows.Controls.RowDefinition
    $rowDef1.Height = [System.Windows.GridLength]::Auto
    $rowDef2 = New-Object System.Windows.Controls.RowDefinition
    $rowDef2.Height = [System.Windows.GridLength]::Auto
    $rowDef3 = New-Object System.Windows.Controls.RowDefinition
    $rowDef3.Height = [System.Windows.GridLength]::Auto
    $rowDef4 = New-Object System.Windows.Controls.RowDefinition
    $rowDef4.Height = [System.Windows.GridLength]::Auto
    $rowDef5 = New-Object System.Windows.Controls.RowDefinition
    $rowDef5.Height = [System.Windows.GridLength]::Auto
    $rowDef6 = New-Object System.Windows.Controls.RowDefinition
    $rowDef6.Height = "*"
    $rowDef7 = New-Object System.Windows.Controls.RowDefinition
    $rowDef7.Height = [System.Windows.GridLength]::Auto
    
    $mainGrid.RowDefinitions.Add($rowDef1)
    $mainGrid.RowDefinitions.Add($rowDef2)
    $mainGrid.RowDefinitions.Add($rowDef3)
    $mainGrid.RowDefinitions.Add($rowDef4)
    $mainGrid.RowDefinitions.Add($rowDef5)
    $mainGrid.RowDefinitions.Add($rowDef6)
    $mainGrid.RowDefinitions.Add($rowDef7)
    
    # Domain FQDN inputs
    $domainGrid = New-Object System.Windows.Controls.Grid
    $domainGrid.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    
    $colDef1 = New-Object System.Windows.Controls.ColumnDefinition
    $colDef1.Width = [System.Windows.GridLength]::Auto
    $colDef2 = New-Object System.Windows.Controls.ColumnDefinition
    $colDef2.Width = "*"
    $colDef3 = New-Object System.Windows.Controls.ColumnDefinition
    $colDef3.Width = [System.Windows.GridLength]::Auto
    $colDef4 = New-Object System.Windows.Controls.ColumnDefinition
    $colDef4.Width = "*"
    
    $domainGrid.ColumnDefinitions.Add($colDef1)
    $domainGrid.ColumnDefinitions.Add($colDef2)
    $domainGrid.ColumnDefinitions.Add($colDef3)
    $domainGrid.ColumnDefinitions.Add($colDef4)
    
    $oldDomainLabel = New-Object System.Windows.Controls.Label
    $oldDomainLabel.Content = "Old Domain FQDN:"
    $oldDomainLabel.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
    $oldDomainLabel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    [System.Windows.Controls.Grid]::SetColumn($oldDomainLabel, 0)
    $domainGrid.Children.Add($oldDomainLabel) | Out-Null
    
    $oldDomainTextBox = New-Object System.Windows.Controls.TextBox
    $oldDomainTextBox.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    [System.Windows.Controls.Grid]::SetColumn($oldDomainTextBox, 1)
    $domainGrid.Children.Add($oldDomainTextBox) | Out-Null
    
    $newDomainLabel = New-Object System.Windows.Controls.Label
    $newDomainLabel.Content = "New Domain FQDN:"
    $newDomainLabel.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
    $newDomainLabel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    [System.Windows.Controls.Grid]::SetColumn($newDomainLabel, 2)
    $domainGrid.Children.Add($newDomainLabel) | Out-Null
    
    $newDomainTextBox = New-Object System.Windows.Controls.TextBox
    $newDomainTextBox.Margin = New-Object System.Windows.Thickness(0, 0, 0, 0)
    [System.Windows.Controls.Grid]::SetColumn($newDomainTextBox, 3)
    $domainGrid.Children.Add($newDomainTextBox) | Out-Null
    
    [System.Windows.Controls.Grid]::SetRow($domainGrid, 0)
    $mainGrid.Children.Add($domainGrid) | Out-Null
    
    # Config file input
    $configGrid = New-Object System.Windows.Controls.Grid
    $configGrid.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    
    $configColDef1 = New-Object System.Windows.Controls.ColumnDefinition
    $configColDef1.Width = [System.Windows.GridLength]::Auto
    $configColDef2 = New-Object System.Windows.Controls.ColumnDefinition
    $configColDef2.Width = "*"
    $configColDef3 = New-Object System.Windows.Controls.ColumnDefinition
    $configColDef3.Width = [System.Windows.GridLength]::Auto
    
    $configGrid.ColumnDefinitions.Add($configColDef1)
    $configGrid.ColumnDefinitions.Add($configColDef2)
    $configGrid.ColumnDefinitions.Add($configColDef3)
    
    $configLabel = New-Object System.Windows.Controls.Label
    $configLabel.Content = "Config File (Optional):"
    $configLabel.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
    $configLabel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    [System.Windows.Controls.Grid]::SetColumn($configLabel, 0)
    $configGrid.Children.Add($configLabel) | Out-Null
    
    $configTextBox = New-Object System.Windows.Controls.TextBox
    $configTextBox.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
    [System.Windows.Controls.Grid]::SetColumn($configTextBox, 1)
    $configGrid.Children.Add($configTextBox) | Out-Null
    
    $browseButton = New-Object System.Windows.Controls.Button
    $browseButton.Content = "Browse..."
    $browseButton.Width = 80
    $browseButton.Height = 25
    [System.Windows.Controls.Grid]::SetColumn($browseButton, 2)
    $browseButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        $dialog.Title = "Select Configuration File"
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $configTextBox.Text = $dialog.FileName
        }
    })
    $configGrid.Children.Add($browseButton) | Out-Null
    
    [System.Windows.Controls.Grid]::SetRow($configGrid, 1)
    $mainGrid.Children.Add($configGrid) | Out-Null
    
    # Server list input
    $serverListLabel = New-Object System.Windows.Controls.Label
    $serverListLabel.Content = "Server List (one per line):"
    $serverListLabel.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
    [System.Windows.Controls.Grid]::SetRow($serverListLabel, 2)
    $mainGrid.Children.Add($serverListLabel) | Out-Null
    
    $serverListTextBox = New-Object System.Windows.Controls.TextBox
    $serverListTextBox.AcceptsReturn = $true
    $serverListTextBox.AcceptsTab = $false
    $serverListTextBox.VerticalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
    $serverListTextBox.HorizontalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
    $serverListTextBox.TextWrapping = [System.Windows.TextWrapping]::NoWrap
    $serverListTextBox.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
    $serverListTextBox.FontSize = 12
    $serverListTextBox.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    [System.Windows.Controls.Grid]::SetRow($serverListTextBox, 3)
    $mainGrid.Children.Add($serverListTextBox) | Out-Null
    
    # Run button
    $runButton = New-Object System.Windows.Controls.Button
    $runButton.Content = "Run Check"
    $runButton.Height = 35
    $runButton.FontSize = 14
    $runButton.FontWeight = [System.Windows.FontWeights]::Bold
    $runButton.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    [System.Windows.Controls.Grid]::SetRow($runButton, 4)
    $mainGrid.Children.Add($runButton) | Out-Null
    
    # Results DataGrid
    $resultsLabel = New-Object System.Windows.Controls.Label
    $resultsLabel.Content = "Results:"
    $resultsLabel.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
    [System.Windows.Controls.Grid]::SetRow($resultsLabel, 5)
    $mainGrid.Children.Add($resultsLabel) | Out-Null
    
    $resultsDataGrid = New-Object System.Windows.Controls.DataGrid
    $resultsDataGrid.AutoGenerateColumns = $true
    $resultsDataGrid.IsReadOnly = $true
    $resultsDataGrid.CanUserAddRows = $false
    $resultsDataGrid.CanUserDeleteRows = $false
    $resultsDataGrid.SelectionMode = [System.Windows.Controls.DataGridSelectionMode]::Extended
    $resultsDataGrid.GridLinesVisibility = [System.Windows.Controls.DataGridGridLinesVisibility]::All
    $resultsDataGrid.HeadersVisibility = [System.Windows.Controls.DataGridHeadersVisibility]::All
    $resultsDataGrid.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    [System.Windows.Controls.Grid]::SetRow($resultsDataGrid, 6)
    $mainGrid.Children.Add($resultsDataGrid) | Out-Null
    
    # Status bar
    $statusBar = New-Object System.Windows.Controls.TextBlock
    $statusBar.Text = "Ready"
    $statusBar.Margin = New-Object System.Windows.Thickness(0, 5, 0, 0)
    $statusBar.FontSize = 11
    [System.Windows.Controls.Grid]::SetRow($statusBar, 7)
    $mainGrid.Children.Add($statusBar) | Out-Null
    
    $window.Content = $mainGrid
    
    # Run button click handler
    $runButton.Add_Click({
        # Validate inputs
        if ([string]::IsNullOrWhiteSpace($oldDomainTextBox.Text)) {
            [System.Windows.MessageBox]::Show("Please enter the Old Domain FQDN.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        
        if ([string]::IsNullOrWhiteSpace($newDomainTextBox.Text)) {
            [System.Windows.MessageBox]::Show("Please enter the New Domain FQDN.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        
        $serverList = $serverListTextBox.Text -split "`n" | Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") } | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        
        if ($serverList.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please enter at least one server name.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        
        # Disable run button
        $runButton.IsEnabled = $false
        $runButton.Content = "Running..."
        $resultsDataGrid.ItemsSource = $null
        
        # Load configuration
        $configFile = $configTextBox.Text.Trim()
        $oldDomainFqdn = $oldDomainTextBox.Text.Trim()
        $newDomainFqdn = $newDomainTextBox.Text.Trim()
        
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
        
        $config = @{
            CrowdStrikeTenantMap = $defaultCrowdStrikeTenantMap
            QualysTenantMap = $defaultQualysTenantMap
            EncaseRegistryPaths = $defaultEncaseRegistryPaths
        }
        
        if ($configFile -and (Test-Path -LiteralPath $configFile)) {
            $loadedConfig = Import-ConfigurationFile -ConfigFilePath $configFile -CrowdStrikeTenantMap $defaultCrowdStrikeTenantMap -QualysTenantMap $defaultQualysTenantMap
            
            if ([string]::IsNullOrWhiteSpace($oldDomainFqdn) -and $loadedConfig.OldDomainFqdn) {
                $oldDomainFqdn = $loadedConfig.OldDomainFqdn
                Update-UIElement -Control $oldDomainTextBox -ScriptBlock { $oldDomainTextBox.Text = $oldDomainFqdn }
            }
            
            if ([string]::IsNullOrWhiteSpace($newDomainFqdn) -and $loadedConfig.NewDomainFqdn) {
                $newDomainFqdn = $loadedConfig.NewDomainFqdn
                Update-UIElement -Control $newDomainTextBox -ScriptBlock { $newDomainTextBox.Text = $newDomainFqdn }
            }
            
            if ($loadedConfig.CrowdStrikeTenantMap) {
                $config.CrowdStrikeTenantMap = $loadedConfig.CrowdStrikeTenantMap
            }
            
            if ($loadedConfig.QualysTenantMap) {
                $config.QualysTenantMap = $loadedConfig.QualysTenantMap
            }
            
            if ($loadedConfig.EncaseRegistryPaths) {
                $config.EncaseRegistryPaths = $loadedConfig.EncaseRegistryPaths
            }
        }
        
        # Build scriptblock for remote execution
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
        $foundDomains = @($foundDomains)
        
        $sccmTenant = 'Unknown'
        $hasDomainReference = $false
        
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
    
    $encasePathsArray = @($EncaseRegistryPaths)
    $hasItems = $false
    try {
        $hasItems = $null -ne $encasePathsArray -and $encasePathsArray.Count -gt 0
    } catch {
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

    $csRegPath = 'System\\CurrentControlSet\\Services\\CSAgent\\Sim'
    $csValName = 'CU'
    $cs = Get-RegistryValueMultiView -Hive LocalMachine -Path $csRegPath -Name $csValName
    $csHex = if ($cs) { $cs.String } else { $null }
    
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

    $qRegPath = 'Software\\Qualys'
    $qValName = 'ActivationID'
    $q = Get-RegistryValueMultiView -Hive LocalMachine -Path $qRegPath -Name $qValName
    $qStr = if ($q) { $q.String } else { $null }
    
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

    $sccmInfo = Get-SCCMTenantInfo -OldDomainFqdn $OldDomainFqdn -NewDomainFqdn $NewDomainFqdn
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

`$OldDomainFqdn = `$args[0]
`$NewDomainFqdn = `$args[1]
`$EncaseRegistryPaths = `$args[2]
`$CrowdStrikeTenantMap = `$args[3]
`$QualysTenantMap = `$args[4]

`$EncaseRegistryPaths = @(`$EncaseRegistryPaths)

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

Get-SecurityAgentsTenantInfo -OldDomainFqdn `$OldDomainFqdn -NewDomainFqdn `$NewDomainFqdn -EncaseRegistryPaths `$EncaseRegistryPaths -CrowdStrikeTenantMap `$CrowdStrikeTenantMap -QualysTenantMap `$QualysTenantMap
"@)
        
        # Process servers in background runspace
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.ApartmentState = [System.Threading.ApartmentState]::STA
        $runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $runspace.Open()
        
        $ps = [PowerShell]::Create()
        $ps.Runspace = $runspace
        
        # Add variables to runspace
        $runspace.SessionStateProxy.SetVariable('serverList', $serverList)
        $runspace.SessionStateProxy.SetVariable('oldDomainFqdn', $oldDomainFqdn)
        $runspace.SessionStateProxy.SetVariable('newDomainFqdn', $newDomainFqdn)
        $runspace.SessionStateProxy.SetVariable('config', $config)
        $runspace.SessionStateProxy.SetVariable('credential', $Credential)
        $runspace.SessionStateProxy.SetVariable('securityCheckScriptBlock', $securityCheckScriptBlock)
        $runspace.SessionStateProxy.SetVariable('resultsDataGrid', $resultsDataGrid)
        $runspace.SessionStateProxy.SetVariable('statusBar', $statusBar)
        
        $ps.AddScript({
            $results = @()
            $total = $serverList.Count
            $current = 0
            
            foreach ($server in $serverList) {
                $current++
                $result = [PSCustomObject]@{
                    Server = $server
                    Qualys = "Checking..."
                    CrowdStrike = "Checking..."
                    SCCM = "Checking..."
                    Encase = "Checking..."
                    Success = $false
                }
                
                # Update UI immediately with "Checking..." status
                $resultsDataGrid.Dispatcher.Invoke([action]{
                    $results += $result
                    $resultsDataGrid.ItemsSource = $null
                    $resultsDataGrid.ItemsSource = $results
                    $statusBar.Text = "Checking $server ($current of $total)..."
                }, [System.Windows.Threading.DispatcherPriority]::Normal)
                
                try {
                    # Test connectivity
                    $testParams = @{
                        ComputerName = $server
                        ScriptBlock  = { $env:COMPUTERNAME }
                        ErrorAction  = 'Stop'
                    }
                    if ($credential) {
                        $testParams['Credential'] = $credential
                    }
                    
                    try {
                        if ($PSVersionTable.PSVersion.Major -ge 5) {
                            $testParams['SessionOption'] = New-PSSessionOption -OperationTimeout 30 -ErrorAction Stop
                        }
                    } catch {}
                    
                    $actualComputerName = Invoke-Command @testParams
                    
                    # Execute security check
                    $invokeParams = @{
                        ComputerName = $server
                        ScriptBlock  = $securityCheckScriptBlock
                        ArgumentList = @(
                            $oldDomainFqdn,
                            $newDomainFqdn,
                            $config.EncaseRegistryPaths,
                            $config.CrowdStrikeTenantMap,
                            $config.QualysTenantMap
                        )
                        ErrorAction  = 'Stop'
                    }
                    
                    if ($credential) {
                        $invokeParams['Credential'] = $credential
                    }
                    
                    try {
                        if ($PSVersionTable.PSVersion.Major -ge 5) {
                            $invokeParams['SessionOption'] = New-PSSessionOption -OperationTimeout 300 -ErrorAction Stop
                        }
                    } catch {}
                    
                    $securityAgents = Invoke-Command @invokeParams
                    
                    # Format result
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
                    
                    $result.Server = $server
                    $result.Qualys = $qualysStatus
                    $result.CrowdStrike = $crowdStrikeStatus
                    $result.SCCM = $sccmStatus
                    $result.Encase = $encaseStatus
                    $result.Success = $true
                }
                catch {
                    $result.Qualys = "Connection Failed"
                    $result.CrowdStrike = "Connection Failed"
                    $result.SCCM = "Connection Failed"
                    $result.Encase = "Connection Failed"
                }
                
                # Update results array
                $existingIndex = $results | Where-Object { $_.Server -eq $server } | Select-Object -First 1
                if ($existingIndex) {
                    $index = [array]::IndexOf($results, $existingIndex)
                    $results[$index] = $result
                } else {
                    $results += $result
                }
                
                # Update UI on main thread
                $resultsDataGrid.Dispatcher.Invoke([action]{
                    $resultsDataGrid.ItemsSource = $null
                    $resultsDataGrid.ItemsSource = $results
                    $statusBar.Text = "Processed $current of $total servers..."
                }, [System.Windows.Threading.DispatcherPriority]::Normal)
            }
            
            return $results
        }) | Out-Null
        
        # Start async execution
        $handle = $ps.BeginInvoke()
        
        # Monitor completion
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({
            if ($handle.IsCompleted) {
                $timer.Stop()
                $finalResults = $ps.EndInvoke($handle)
                $ps.Dispose()
                $runspace.Close()
                $runspace.Dispose()
                
                Update-UIElement -Control $resultsDataGrid -ScriptBlock {
                    $resultsDataGrid.ItemsSource = $finalResults
                }
                
                Update-UIElement -Control $runButton -ScriptBlock {
                    $runButton.IsEnabled = $true
                    $runButton.Content = "Run Check"
                }
                
                Update-UIElement -Control $statusBar -ScriptBlock {
                    $statusBar.Text = "Completed. Processed $($finalResults.Count) server(s)."
                }
            }
        })
        $timer.Start()
    })
    
    # Show window
    $window.ShowDialog() | Out-Null
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Prompt for credentials at startup
$credential = Get-CredentialDialog

# Show GUI
Show-SecurityToolsGUI -Credential $credential

