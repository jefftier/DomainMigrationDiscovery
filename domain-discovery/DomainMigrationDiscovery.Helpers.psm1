<#
.SYNOPSIS
  Hides (redacts) sensitive values in text (passwords, tokens, secrets, connection strings).
  Preserves key names; replaces only values with "REDACTED". Used before storing
  config excerpts or event snippets in JSON/Excel. Uses approved verb Hide.
  Lightweight self-test examples: Hide-SensitiveText 'password=secret' -> 'password=REDACTED';
  Hide-SensitiveText 'Token: abc123' -> 'Token: REDACTED'; Hide-SensitiveText '"api_key":"xyz"' -> '"api_key":"REDACTED"'
#>
function Hide-SensitiveText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [string]$InputString
  )
  if ([string]::IsNullOrEmpty($InputString)) { return $InputString }
  $text = $InputString
  $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  # Literal key names (case-insensitive match)
  $sensitiveKeys = @(
    'password', 'pwd', 'passwd', 'pass',
    'token', 'access_token', 'refresh_token', 'id_token',
    'apikey', 'api_key', 'api key',
    'secret', 'client_secret', 'sharedsecret',
    'connectionstring', 'connection string', 'connection_string',
    'datasource', 'data source', 'server', 'uid', 'userid', 'user id',
    'integrated security', 'trusted_connection'
  )
  foreach ($key in $sensitiveKeys) {
    $esc = [regex]::Escape($key)
    # key=value (value: non-quoted, to next space/semicolon/quote/newline)
    $text = [regex]::Replace($text, "($esc)\s*[=:]\s*([^;\s""'<>`r`n]+)", "`${1}=REDACTED", $opt)
    # key="value" or key='value'
    $text = [regex]::Replace($text, "($esc)\s*[=:]\s*[""']([^""']*)[""']", "`${1}=REDACTED", $opt)
    # JSON: "key": "value" ($1 must be literal for regex backreference; escape $ in double-quoted string)
    $text = [regex]::Replace($text, "[""']($esc)[""']\s*:\s*[""']([^""']*)[""']", "`"`$1`":`"REDACTED`"", $opt)
    # XML: <key>value</key> (escape $ so $1 is literal for regex backreference)
    $text = [regex]::Replace($text, "<($esc)>[^<]*</\1>", '<$1>REDACTED</$1>', $opt)
  }
  # Connection string style: Password=xxx; or Pwd=xxx;
  $text = [regex]::Replace($text, '(Password|Pwd)\s*=\s*[^;]+', '${1}=REDACTED', $opt)
  return $text
}

function Get-CredentialManagerDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false)]
    [string]$ProfileSID,
    [Parameter(Mandatory=$false)]
    [string]$ProfilePath,
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  
  # Check registry-based credentials (Windows Vault and Internet Settings)
  $regPaths = @()
  if ($ProfileSID) {
    # For loaded user hives
    $regPaths += "Registry::HKEY_USERS\$ProfileSID\Software\Microsoft\Vault"
    $regPaths += "Registry::HKEY_USERS\$ProfileSID\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Credentials"
  } else {
    # For current user
    $regPaths += "Registry::HKEY_CURRENT_USER\Software\Microsoft\Vault"
    $regPaths += "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Credentials"
  }
  
  foreach ($regPath in $regPaths) {
    if (-not (Test-Path $regPath)) { continue }
    
    try {
      $vaultKeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
      foreach ($vaultKey in $vaultKeys) {
        try {
          $target = $null
          $userName = $null
          
          # Try to read common credential properties
          $props = Get-ItemProperty -Path $vaultKey.PSPath -ErrorAction SilentlyContinue
          if ($props) {
            # Check various property names that might contain target/username
            $target = $vaultKey.PSChildName
            if ($props.Target) { $target = [string]$props.Target }
            elseif ($props.Name) { $target = [string]$props.Name }
            elseif ($props.Resource) { $target = [string]$props.Resource }
            $userName = $null
            if ($props.UserName) { $userName = [string]$props.UserName }
            elseif ($props.User) { $userName = [string]$props.User }
            elseif ($props.Account) { $userName = [string]$props.Account }
          } else {
            $target = $vaultKey.PSChildName
          }
          
          # Only add entry if we have at least one meaningful value (target or username)
          if ($target -or $userName) {
            # Check if target or username contains domain reference
            $hasDomainRef = $false
            if ($target -and $DomainMatchers.Match($target)) { $hasDomainRef = $true }
            if (-not $hasDomainRef -and $userName -and $DomainMatchers.Match($userName)) { $hasDomainRef = $true }
            
            $profileName = $env:USERNAME; if ($ProfileSID) { $profileName = $ProfileSID }
            $results += [pscustomobject]@{
              Profile = $profileName
              Target = $target
              UserName = $userName
              Source = 'Registry'
              HasDomainReference = $hasDomainRef
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error reading vault key $($vaultKey.PSPath): $($_.Exception.Message)", 'WARN') }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error accessing registry path ${regPath}: $($_.Exception.Message)", 'WARN') }
    }
  }
  
  # Check cmdkey.exe for current user (only works for current user context)
  if (-not $ProfileSID) {
    try {
      $cmdkeyPath = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
      if (Test-Path $cmdkeyPath) {
        $cmdkeyOutput = & $cmdkeyPath /list 2>&1
        if ($LASTEXITCODE -eq 0 -and $cmdkeyOutput) {
          $currentTarget = $null
          $currentUser = $null
          $inEntry = $false
          
          foreach ($line in $cmdkeyOutput) {
            $lineStr = [string]$line
            if ($lineStr -match '^Target:\s*(.+)') {
              # If we have a previous entry, save it before starting a new one
              if ($inEntry -and $currentTarget) {
                $hasDomainRef = $false
                if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
                if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
                
                $results += [pscustomobject]@{
                  Profile = $env:USERNAME
                  Target = $currentTarget
                  UserName = $currentUser
                  Source = 'CmdKey'
                  HasDomainReference = $hasDomainRef
                }
              }
              $currentTarget = $Matches[1].Trim()
              $currentUser = $null
              $inEntry = $true
            }
            elseif ($lineStr -match '^Type:\s*(.+)') {
              # Type line, continue
            }
            elseif ($lineStr -match '^User:\s*(.+)') {
              $currentUser = $Matches[1].Trim()
            }
            elseif ([string]::IsNullOrWhiteSpace($lineStr) -and $inEntry) {
              # Empty line indicates end of credential entry
              if ($currentTarget) {
                $hasDomainRef = $false
                if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
                if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
                
                $results += [pscustomobject]@{
                  Profile = $env:USERNAME
                  Target = $currentTarget
                  UserName = $currentUser
                  Source = 'CmdKey'
                  HasDomainReference = $hasDomainRef
                }
              }
              $currentTarget = $null
              $currentUser = $null
              $inEntry = $false
            }
          }
          
          # Handle last entry if output doesn't end with empty line
          if ($inEntry -and $currentTarget) {
            $hasDomainRef = $false
            if ($currentTarget -and $DomainMatchers.Match($currentTarget)) { $hasDomainRef = $true }
            if (-not $hasDomainRef -and $currentUser -and $DomainMatchers.Match($currentUser)) { $hasDomainRef = $true }
            
            $results += [pscustomobject]@{
              Profile = $env:USERNAME
              Target = $currentTarget
              UserName = $currentUser
              Source = 'CmdKey'
              HasDomainReference = $hasDomainRef
            }
          }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error running cmdkey.exe: $($_.Exception.Message)", 'WARN') }
    }
  }
  
  return $results
}

function Get-CertificatesWithDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  $stores = @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')
  
  foreach ($storePath in $stores) {
    try {
      if (-not (Test-Path -LiteralPath $storePath -ErrorAction SilentlyContinue)) { continue }
      
      $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
      foreach ($cert in $certs) {
        try {
          if ($null -eq $cert) { continue }
          
          $subject = [string]$cert.Subject
          $issuer = [string]$cert.Issuer
          $sanText = $null
          $matchedField = $null
          $hasDomainReference = $false
          
          # Extract Subject Alternative Name extension
          try {
            $sanExt = $cert.Extensions | Where-Object { 
              ($_.Oid.FriendlyName -eq 'Subject Alternative Name') -or 
              ($_.Oid.Value -eq '2.5.29.17')
            } | Select-Object -First 1
            
            if ($sanExt) {
              $sanText = $sanExt.Format($false)
            }
          } catch {
            if ($Log) { $Log.Write("Error reading SAN extension for cert $($cert.Thumbprint): $($_.Exception.Message)", 'WARN') }
          }
          
          # Check Subject
          if (-not [string]::IsNullOrWhiteSpace($subject) -and $DomainMatchers.Match($subject)) {
            $hasDomainReference = $true
            $matchedField = 'Subject'
          }
          
          # Check Issuer
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($issuer) -and $DomainMatchers.Match($issuer)) {
            $hasDomainReference = $true
            $matchedField = 'Issuer'
          }
          
          # Check SAN
          if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($sanText) -and $DomainMatchers.Match($sanText)) {
            $hasDomainReference = $true
            $matchedField = 'SAN'
          }
          
          # Return all certificates, but flag those with domain references
          $notAfterVal = $null; if ($cert.NotAfter) { $notAfterVal = $cert.NotAfter.ToString('o') }
          $results += [pscustomobject]@{
            Store = $storePath
            Thumbprint = $cert.Thumbprint
            Subject = $subject
            Issuer = $issuer
            NotAfter = $notAfterVal
            HasDomainReference = $hasDomainReference
            MatchedField = $matchedField
          }
        } catch {
          if ($Log) { $Log.Write("Error processing certificate $($cert.Thumbprint): $($_.Exception.Message)", 'WARN') }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error accessing certificate store $storePath : $($_.Exception.Message)", 'WARN') }
    }
  }
  
  return $results
}

function Get-FirewallRulesWithDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  
  # Check if firewall cmdlets are available (Windows 8/Server 2012+)
  if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
    if ($Log) { $Log.Write('Get-NetFirewallRule cmdlet not available on this OS version', 'WARN') }
    return $results
  }
  
  try {
    $rules = Get-NetFirewallRule -ErrorAction Stop
    
    foreach ($rule in $rules) {
      try {
        if ($null -eq $rule) { continue }
        
        $name = [string]$rule.Name
        $displayName = [string]$rule.DisplayName
        $description = [string]$rule.Description
        $group = [string]$rule.Group
        $direction = [string]$rule.Direction
        $action = [string]$rule.Action
        
        # Get address filter
        $localUser = $null
        $remoteUser = $null
        $applicationPath = $null
        $serviceName = $null
        
        try {
          $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
          if ($addrFilter) {
            $localUser = [string]$addrFilter.LocalUser
            $remoteUser = [string]$addrFilter.RemoteUser
          }
        } catch {
          # Address filter may not be available for all rules
        }
        
        # Get application filter
        try {
          $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
          if ($appFilter) {
            $applicationPath = [string]$appFilter.Program
            $serviceName = [string]$appFilter.Service
          }
        } catch {
          # Application filter may not be available for all rules
        }
        
        # Check all relevant fields for domain references
        $matchedField = $null
        $hasDomainReference = $false
        
        # Check DisplayName
        if (-not [string]::IsNullOrWhiteSpace($displayName) -and $DomainMatchers.Match($displayName)) {
          $hasDomainReference = $true
          $matchedField = 'DisplayName'
        }
        
        # Check Description
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($description) -and $DomainMatchers.Match($description)) {
          $hasDomainReference = $true
          $matchedField = 'Description'
        }
        
        # Check Group
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($group) -and $DomainMatchers.Match($group)) {
          $hasDomainReference = $true
          $matchedField = 'Group'
        }
        
        # Check LocalUser
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($localUser) -and $DomainMatchers.Match($localUser)) {
          $hasDomainReference = $true
          $matchedField = 'LocalUser'
        }
        
        # Check RemoteUser
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($remoteUser) -and $DomainMatchers.Match($remoteUser)) {
          $hasDomainReference = $true
          $matchedField = 'RemoteUser'
        }
        
        # Check ApplicationPath
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($applicationPath) -and $DomainMatchers.Match($applicationPath)) {
          $hasDomainReference = $true
          $matchedField = 'ApplicationPath'
        }
        
        # Check ServiceName
        if (-not $hasDomainReference -and -not [string]::IsNullOrWhiteSpace($serviceName) -and $DomainMatchers.Match($serviceName)) {
          $hasDomainReference = $true
          $matchedField = 'ServiceName'
        }
        
        # Return all rules, but flag those with domain references
        $results += [pscustomobject]@{
          Name = $name
          DisplayName = $displayName
          Direction = $direction
          Action = $action
          ApplicationPath = $applicationPath
          LocalUser = $localUser
          RemoteUser = $remoteUser
          HasDomainReference = $hasDomainReference
          MatchedField = $matchedField
        }
      } catch {
        if ($Log) { $Log.Write("Error processing firewall rule $($rule.Name): $($_.Exception.Message)", 'WARN') }
      }
    }
  } catch {
    if ($Log) { $Log.Write("Error accessing firewall rules: $($_.Exception.Message)", 'WARN') }
  }
  
  return $results
}

function Get-IISDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $result = [pscustomobject]@{
    Sites = @()
    AppPools = @()
  }
  
  # Check if IIS is installed
  $iisInstalled = $false
  
  # Method 1: Check Windows Feature (Server OS)
  try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
      $webServerFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
      if ($webServerFeature -and $webServerFeature.InstallState -eq 'Installed') {
        $iisInstalled = $true
      }
    }
  } catch {
    # Get-WindowsFeature may not be available on client OS
  }
  
  # Method 2: Check if WebAdministration module is available (works on both Server and Client OS)
  if (-not $iisInstalled) {
    try {
      if (Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue) {
        # Try to import and check if IIS is actually running
        Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
        if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
          # Try to access IIS configuration to confirm it's installed
          try {
            $testSite = Get-Website -ErrorAction Stop | Select-Object -First 1
            $iisInstalled = $true
          } catch {
            # IIS module available but IIS not installed or not accessible
          }
        }
      }
    } catch {
      # WebAdministration module not available
    }
  }
  
  # Method 3: Check if IIS service exists
  if (-not $iisInstalled) {
    try {
      $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
      if ($w3svc) {
        $iisInstalled = $true
      }
    } catch {
      # Service check failed
    }
  }
  
  if (-not $iisInstalled) {
    if ($Log) { $Log.Write('IIS (Web-Server role) is not installed on this system', 'INFO') }
    return $null
  }
  
  # IIS is installed, proceed with discovery
  try {
    # Ensure WebAdministration module is loaded
    if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
      Import-Module WebAdministration -ErrorAction Stop | Out-Null
    }
    
    # Get Websites
    try {
      $websites = Get-Website -ErrorAction Stop
      foreach ($site in $websites) {
        try {
          if ($null -eq $site) { continue }
          
          $siteName = [string]$site.Name
          $bindings = @()
          $matchedFields = @()
          $hasDomainReference = $false
          
          # Get bindings for the site
          try {
            $siteBindings = Get-WebBinding -Name $siteName -ErrorAction SilentlyContinue
            foreach ($binding in $siteBindings) {
              if ($null -eq $binding) { continue }
              
              $bindingInfo = [pscustomobject]@{
                Protocol = [string]$binding.Protocol
                BindingInformation = [string]$binding.BindingInformation
                HostHeader = $null
                IPAddress = $null
                Port = $null
              }
              
              # Parse binding information (format: IP:Port:HostHeader)
              $bindingInfoStr = [string]$binding.BindingInformation
              if ($bindingInfoStr -match '^([^:]+):(\d+):(.+)$') {
                $bindingInfo.IPAddress = $Matches[1]
                $bindingInfo.Port = $Matches[2]
                $bindingInfo.HostHeader = $Matches[3]
              } elseif ($bindingInfoStr -match '^([^:]+):(\d+)$') {
                $bindingInfo.IPAddress = $Matches[1]
                $bindingInfo.Port = $Matches[2]
              }
              
              # Check binding for domain references
              $bindingCheckStr = "$($bindingInfo.HostHeader) $($bindingInfo.BindingInformation)"
              if ($DomainMatchers.Match($bindingCheckStr)) {
                $hasDomainReference = $true
                if (-not ($matchedFields -contains 'Binding')) {
                  $matchedFields += 'Binding'
                }
              }
              
              $bindings += $bindingInfo
            }
          } catch {
            if ($Log) { $Log.Write("Error getting bindings for site $siteName : $($_.Exception.Message)", 'WARN') }
          }
          
          # Check site name for domain references
          if ($DomainMatchers.Match($siteName)) {
            $hasDomainReference = $true
            if (-not ($matchedFields -contains 'Name')) {
              $matchedFields += 'Name'
            }
          }
          
          # Get applications and check their paths
          try {
            $applications = Get-WebApplication -Site $siteName -ErrorAction SilentlyContinue
            foreach ($app in $applications) {
              if ($null -eq $app) { continue }
              $appPath = [string]$app.Path
              if ($DomainMatchers.Match($appPath)) {
                $hasDomainReference = $true
                if (-not ($matchedFields -contains 'ApplicationPath')) {
                  $matchedFields += 'ApplicationPath'
                }
              }
            }
          } catch {
            # Applications may not exist or may not be accessible
          }
          
          $result.Sites += [pscustomobject]@{
            Name = $siteName
            State = [string]$site.State
            Bindings = $bindings
            HasDomainReference = $hasDomainReference
            MatchedFields = $matchedFields
          }
        } catch {
          if ($Log) { $Log.Write("Error processing website $($site.Name): $($_.Exception.Message)", 'WARN') }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error getting websites: $($_.Exception.Message)", 'WARN') }
    }
    
    # Get Application Pools
    try {
      # Try to get app pools directly from IIS provider
      $appPoolItems = @()
      try {
        $appPoolItems = Get-ChildItem "IIS:\AppPools" -ErrorAction Stop
      } catch {
        # Fallback to Get-WebAppPoolState if direct access fails
        $appPoolStates = Get-WebAppPoolState -ErrorAction SilentlyContinue
        if ($appPoolStates) {
          foreach ($state in $appPoolStates) {
            try {
              $poolItem = Get-Item "IIS:\AppPools\$($state.Name)" -ErrorAction Stop
              $appPoolItems += $poolItem
            } catch {
              # Skip if we can't access the pool
            }
          }
        }
      }
      
      foreach ($poolItem in $appPoolItems) {
        $poolName = $poolItem.Name
        try {
          if ([string]::IsNullOrWhiteSpace($poolName)) { continue }
          
          $matchedFields = @()
          $hasDomainReference = $false
          $identityType = $null
          $identityUser = $null
          
          # Get application pool configuration
          try {
            # Get process model identity
            $processModel = $poolItem.processModel
            if ($processModel) {
              $identityType = [string]$processModel.identityType
              $identityUser = [string]$processModel.userName
              
              # Check identity user for domain references
              if (-not [string]::IsNullOrWhiteSpace($identityUser)) {
                if ($DomainMatchers.Match($identityUser)) {
                  $hasDomainReference = $true
                  if (-not ($matchedFields -contains 'IdentityUser')) {
                    $matchedFields += 'IdentityUser'
                  }
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error getting app pool details for $poolName : $($_.Exception.Message)", 'WARN') }
          }
          
          # Check pool name for domain references
          if ($DomainMatchers.Match($poolName)) {
            $hasDomainReference = $true
            if (-not ($matchedFields -contains 'Name')) {
              $matchedFields += 'Name'
            }
          }
          
          $result.AppPools += [pscustomobject]@{
            Name = $poolName
            IdentityType = $identityType
            IdentityUser = $identityUser
            HasDomainReference = $hasDomainReference
            MatchedFields = $matchedFields
          }
        } catch {
          if ($Log) { $Log.Write("Error processing app pool $poolName : $($_.Exception.Message)", 'WARN') }
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error getting application pools: $($_.Exception.Message)", 'WARN') }
    }
    
  } catch {
    if ($Log) { $Log.Write("Error accessing IIS configuration: $($_.Exception.Message)", 'WARN') }
    return $null
  }
  
  return $result
}

function Get-SqlServerPresence {
  [CmdletBinding()]
  param([Parameter(Mandatory = $false)] $Log)
  $installed = $false
  $version = $null
  try {
    # Registry: Instance Names\SQL lists instances; value data is instance ID (e.g. MSSQL15.MSSQLSERVER)
    $regPath = 'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
    $key = $base.OpenSubKey($regPath)
    if ($key) {
      $instanceIds = @()
      foreach ($valueName in $key.GetValueNames()) {
        if (-not $valueName) { continue }
        $instanceId = $key.GetValue($valueName)
        if ($instanceId -and $instanceId -notin $instanceIds) { $instanceIds += $instanceId }
      }
      $key.Close()
      if ($instanceIds.Count -gt 0) {
        $installed = $true
        # Read version from first instance: ...\MSSQLServer\CurrentVersion
        $instanceId = $instanceIds[0]
        $verKey = $base.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer\CurrentVersion")
        if ($verKey) {
          $version = $verKey.GetValue('CurrentVersion')
          $verKey.Close()
        }
      }
    }
    # Fallback: check for MSSQLSERVER or MSSQL$* services if registry had nothing
    if (-not $installed) {
      $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'MSSQLSERVER' -or ($_.Name -like 'MSSQL$*' -and $_.Name -notlike '*SQLBrowser*' -and $_.Name -notlike '*SQLWriter*' -and $_.Name -notlike '*SQLSERVERAGENT*') } | Select-Object -First 1
      if ($svc) { $installed = $true }
    }
  } catch {
    if ($Log) { $Log.Write("Get-SqlServerPresence: $($_.Exception.Message)", 'WARN') }
  }
  return [pscustomobject]@{ Installed = $installed; Version = $version }
}

function Get-SqlDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  
  # Step 1: Detect SQL Server instances
  $sqlInstances = @()
  # Known Windows/SQL support services that are NOT connectable instances (do not add to $sqlInstances)
  $nonInstanceServiceSuffixes = @('SQLBrowser', 'SQLSERVERAGENT', 'SQLTELEMETRY', 'SQLWriter', 'SSISTELEMETRY', 'ReportServer')
  
  # Method 1: Check for SQL Server services (MSSQL*)
  try {
    $sqlServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
      $_.Name -like 'MSSQL*' -or 
      $_.Name -eq 'MSSQLSERVER' -or
      $_.DisplayName -like '*SQL Server*'
    }
    
    foreach ($svc in $sqlServices) {
      # Extract instance name from service name
      # MSSQLSERVER = default instance; MSSQL$INSTANCENAME = named instance
      # Skip support services that are not connectable database instances
      $instanceName = $null
      if ($svc.Name -eq 'MSSQLSERVER') {
        $instanceName = $env:COMPUTERNAME
      } elseif ($svc.Name -like 'MSSQL$*') {
        $suffix = $svc.Name -replace 'MSSQL\$', ''
        if ($nonInstanceServiceSuffixes -notcontains $suffix) {
          $instanceName = $suffix
        }
      }
      
      if ($instanceName -and -not ($sqlInstances | Where-Object { $_.InstanceName -eq $instanceName })) {
        $sqlInstances += [pscustomobject]@{
          InstanceName = $instanceName
          ServiceName = $svc.Name
          DisplayName = $svc.DisplayName
          State = $svc.Status
          DetectionMethod = 'Service'
        }
      }
    }
  } catch {
    if ($Log) { $Log.Write("Error detecting SQL services: $($_.Exception.Message)", 'WARN') }
  }
  
  # Method 2: Check registry for SQL Server instances
  try {
    $regPaths = @(
      'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL',
      'SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    )
    
    foreach ($regPath in $regPaths) {
      try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        $key = $base.OpenSubKey($regPath)
        if ($key) {
          foreach ($instanceName in $key.GetValueNames()) {
            if ($instanceName -and -not ($sqlInstances | Where-Object { $_.InstanceName -eq $instanceName })) {
              $sqlInstances += [pscustomobject]@{
                InstanceName = $instanceName
                ServiceName = $null
                DisplayName = $null
                State = $null
                DetectionMethod = 'Registry'
              }
            }
          }
          $key.Close()
        }
      } catch {
        # Registry path may not exist, continue
      }
    }
  } catch {
    if ($Log) { $Log.Write("Error checking registry for SQL instances: $($_.Exception.Message)", 'WARN') }
  }
  
  # If no instances detected, return null
  if ($sqlInstances.Count -eq 0) {
    if ($Log) { $Log.Write('No SQL Server instances detected on this system', 'INFO') }
    return $null
  }
  
  if ($Log) { $Log.Write("Detected $($sqlInstances.Count) SQL Server instance(s)", 'INFO') }
  
  # Step 2: For each instance, attempt to query for domain references
  foreach ($instance in $sqlInstances) {
    $instanceName = $instance.InstanceName
    $domainLogins = @()
    $linkedServersWithDomainRefs = @()
    $configFilesWithDomainRefs = @()
    
    # Build connection string
    $serverName = "$env:COMPUTERNAME\$instanceName"
    if ($instanceName -eq $env:COMPUTERNAME) { $serverName = $env:COMPUTERNAME }
    
    # Try SMO first (SQL Server Management Objects)
    $smoAvailable = $false
    try {
      # Check if SMO type is already loaded
      $smoType = [Microsoft.SqlServer.Management.Smo.Server] -as [Type]
      if ($smoType) {
        $smoAvailable = $true
      } else {
        # Try to load SMO assembly
        try {
          Add-Type -AssemblyName 'Microsoft.SqlServer.Smo' -ErrorAction Stop
          $smoAvailable = $true
        } catch {
          # Try alternative loading method
          try {
            $smoPath = Get-ChildItem -Path "$env:ProgramFiles\Microsoft SQL Server" -Recurse -Filter 'Microsoft.SqlServer.Smo.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($smoPath -and (Test-Path $smoPath.FullName)) {
              Add-Type -Path $smoPath.FullName -ErrorAction Stop
              $smoAvailable = $true
            }
          } catch {
            # SMO not available, will try other methods
          }
        }
      }
    } catch {
      # SMO not available, will try other methods
    }
    
    if ($smoAvailable) {
      try {
        # Use SMO to query SQL Server
        $server = New-Object Microsoft.SqlServer.Management.Smo.Server($serverName)
        
        # Query Windows logins
        try {
          foreach ($login in $server.Logins) {
            if ($login.LoginType -eq 'WindowsUser' -or $login.LoginType -eq 'WindowsGroup') {
              $loginName = $login.Name
              if ($DomainMatchers.Match($loginName)) {
                $domainLogins += [pscustomobject]@{
                  LoginName = $loginName
                  LoginType = $login.LoginType
                  DefaultDatabase = $login.DefaultDatabase
                  IsDisabled = $login.IsDisabled
                }
              }
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error querying logins for instance $instanceName : $($_.Exception.Message)", 'WARN') }
        }
        
        # Query linked servers
        try {
          foreach ($linkedServer in $server.LinkedServers) {
            $linkedServerName = $linkedServer.Name
            $hasDomainRef = $false
            $matchedFields = @()
            
            # Check server name
            if ($DomainMatchers.Match($linkedServerName)) {
              $hasDomainRef = $true
              $matchedFields += 'ServerName'
            }
            
            # Check provider string
            if (-not $hasDomainRef -and $linkedServer.ProviderString -and $DomainMatchers.Match($linkedServer.ProviderString)) {
              $hasDomainRef = $true
              $matchedFields += 'ProviderString'
            }
            
            # Check remote login (if configured)
            if (-not $hasDomainRef -and $linkedServer.RemoteLogin -and $DomainMatchers.Match($linkedServer.RemoteLogin)) {
              $hasDomainRef = $true
              $matchedFields += 'RemoteLogin'
            }
            
            if ($hasDomainRef) {
              $linkedServersWithDomainRefs += [pscustomobject]@{
                LinkedServerName = $linkedServerName
                ProviderName = $linkedServer.ProviderName
                DataSource = $linkedServer.DataSource
                RemoteLogin = $linkedServer.RemoteLogin
                MatchedFields = $matchedFields
              }
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error querying linked servers for instance $instanceName : $($_.Exception.Message)", 'WARN') }
        }
      } catch {
        if ($Log) { $Log.Write("Error connecting to SQL instance $instanceName via SMO: $($_.Exception.Message)", 'WARN') }
        $smoAvailable = $false  # Mark SMO as failed so we try fallback
      }
    }
    
    # Fallback: Try Invoke-Sqlcmd if SMO not available or failed
    if (-not $smoAvailable) {
      try {
        if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
          # Query Windows logins
          try {
            # Get all Windows logins and filter in PowerShell (more flexible than SQL LIKE)
            $loginQuery = @"
SELECT 
  name AS LoginName,
  type_desc AS LoginType,
  default_database_name AS DefaultDatabase,
  is_disabled AS IsDisabled
FROM sys.server_principals
WHERE type IN ('U', 'G')
"@
            $loginResults = Invoke-Sqlcmd -ServerInstance $serverName -Query $loginQuery -ErrorAction SilentlyContinue
            if ($loginResults) {
              foreach ($row in $loginResults) {
                $loginName = $row.LoginName
                if ($DomainMatchers.Match($loginName)) {
                  $domainLogins += [pscustomobject]@{
                    LoginName = $loginName
                    LoginType = $row.LoginType
                    DefaultDatabase = $row.DefaultDatabase
                    IsDisabled = $row.IsDisabled
                  }
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error querying logins via Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
          }
          
          # Query linked servers
          try {
            $linkedServerQuery = @"
SELECT 
  srv.name AS LinkedServerName,
  srv.provider AS ProviderName,
  srv.data_source AS DataSource,
  srv.catalog AS Catalog,
  ls.remote_name AS RemoteLogin
FROM sys.servers srv
LEFT JOIN sys.linked_logins ls ON srv.server_id = ls.server_id
WHERE srv.is_linked = 1
"@
            $linkedServerResults = Invoke-Sqlcmd -ServerInstance $serverName -Query $linkedServerQuery -ErrorAction SilentlyContinue
            if ($linkedServerResults) {
              foreach ($row in $linkedServerResults) {
                $hasDomainRef = $false
                $matchedFields = @()
                
                $linkedServerName = $row.LinkedServerName
                if ($DomainMatchers.Match($linkedServerName)) {
                  $hasDomainRef = $true
                  $matchedFields += 'ServerName'
                }
                
                if (-not $hasDomainRef -and $row.DataSource -and $DomainMatchers.Match($row.DataSource)) {
                  $hasDomainRef = $true
                  $matchedFields += 'DataSource'
                }
                
                if (-not $hasDomainRef -and $row.RemoteLogin -and $DomainMatchers.Match($row.RemoteLogin)) {
                  $hasDomainRef = $true
                  $matchedFields += 'RemoteLogin'
                }
                
                if ($hasDomainRef) {
                  $linkedServersWithDomainRefs += [pscustomobject]@{
                    LinkedServerName = $linkedServerName
                    ProviderName = $row.ProviderName
                    DataSource = $row.DataSource
                    RemoteLogin = $row.RemoteLogin
                    MatchedFields = $matchedFields
                  }
                }
              }
            }
          } catch {
            if ($Log) { $Log.Write("Error querying linked servers via Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
          }
        } else {
          if ($Log) { $Log.Write("SQL tools (SMO or Invoke-Sqlcmd) not available for instance $instanceName", 'WARN') }
        }
      } catch {
        if ($Log) { $Log.Write("Error using Invoke-Sqlcmd for instance $instanceName : $($_.Exception.Message)", 'WARN') }
      }
    }
    
    # Step 3: Scan for configuration files that might contain SQL references
    try {
      $configPaths = @()
      
      # Common SQL Server configuration file locations
      $sqlInstallPaths = @(
        "C:\Program Files\Microsoft SQL Server",
        "C:\Program Files (x86)\Microsoft SQL Server"
      )
      
      foreach ($basePath in $sqlInstallPaths) {
        if (Test-Path $basePath) {
          $configPaths += Get-ChildItem -Path $basePath -Recurse -Include *.config,*.ini,*.conf,*.xml -ErrorAction SilentlyContinue | Select-Object -First 50
        }
      }
      
      # Also check common application config locations
      $appConfigPaths = @(
        "$env:ProgramFiles\*\*.config",
        "$env:ProgramFiles(x86)\*\*.config",
        "$env:ProgramData\*\*.config",
        "$env:APPDATA\*\*.config"
      )
      
      foreach ($pattern in $appConfigPaths) {
        try {
          $configPaths += Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 20
        } catch {
          # Pattern may not match, continue
        }
      }
      
      # Scan files for domain references in connection strings
      foreach ($configFile in $configPaths) {
        try {
          if (-not (Test-Path -LiteralPath $configFile.FullName)) { continue }
          
          $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction SilentlyContinue
          if ($content -and $DomainMatchers.Match($content)) {
            # Extract connection strings or relevant sections
            $matchedLines = @()
            $lines = Get-Content -Path $configFile.FullName -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
              if ($DomainMatchers.Match($line)) {
                $matchedLines += $line.Trim()
              }
            }
            
            if ($matchedLines.Count -gt 0) {
              $linesToStore = @()
              $cap = [Math]::Min(5, $matchedLines.Count - 1)
              for ($i = 0; $i -le $cap; $i++) {
                $linesToStore += Hide-SensitiveText -InputString $matchedLines[$i]
              }
              $configFilesWithDomainRefs += [pscustomobject]@{
                FilePath = $configFile.FullName
                FileName = $configFile.Name
                MatchedLines = $linesToStore
                TotalMatches = $matchedLines.Count
              }
            }
          }
        } catch {
          # Skip files that can't be read
        }
      }
    } catch {
      if ($Log) { $Log.Write("Error scanning configuration files: $($_.Exception.Message)", 'WARN') }
    }
    
    # Build result for this instance
    $results += [pscustomobject]@{
      InstanceName = $instanceName
      ServiceName = $instance.ServiceName
      DetectionMethod = $instance.DetectionMethod
      DomainLogins = $domainLogins
      LinkedServersWithDomainReferences = $linkedServersWithDomainRefs
      ConfigFilesWithDomainReferences = $configFilesWithDomainRefs
    }
  }
  
  return $results
}

<#
.SYNOPSIS
  Parses a connection string (key=value; key=value) into DataSource, InitialCatalog, UserId, IntegratedSecurity, HasPassword.
#>
function Parse-ConnectionStringToHash {
  [CmdletBinding()]
  param([Parameter(Mandatory=$false)][string]$ConnectionString)
  $out = @{ DataSource = ''; InitialCatalog = ''; UserId = ''; IntegratedSecurity = $false; HasPassword = $false }
  if ([string]::IsNullOrWhiteSpace($ConnectionString)) { return $out }
  $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  foreach ($pair in ($ConnectionString -split ';')) {
    if ($pair -match '^\s*([^=]+)=(.*)$') {
      $k = $Matches[1].Trim().ToLowerInvariant() -replace '\s+', ''
      $v = $Matches[2].Trim().Trim('"').Trim("'")
      switch -Regex ($k) {
        '^datasource$|^server$'   { $out.DataSource = $v }
        '^initialcatalog$|^database$' { $out.InitialCatalog = $v }
        '^userid$|^uid$|^user$' { $out.UserId = $v }
        '^integratedsecurity$|^trusted_connection$' { $out.IntegratedSecurity = ($v -match '^(true|yes|sspi|1)$') }
        '^password$|^pwd$'      { $out.HasPassword = $true }
      }
    }
  }
  return $out
}

<#
.SYNOPSIS
  Extracts and parses connection strings from a config file for DatabaseConnections.
  Returns array of { LocationType, Location, ConnectionTarget, Parsed }.
#>
function Get-DatabaseConnectionsFromConfigFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$FilePath,
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  $results = @()
  if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $results }
  try {
    $content = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
    if (-not $content -or $content -notmatch '(?i)(connectionstring|connection\s+string|data\s+source|server)\s*[=:]') { return $results }
    $connectionStrings = @()
    if ($content -match '(?i)connectionString\s*=\s*["'']([^"'']+)["'']') {
      foreach ($m in ([regex]::Matches($content, '(?i)connectionString\s*=\s*["'']([^"'']+)["'']'))) {
        $connectionStrings += $m.Groups[1].Value
      }
    }
    if ($content -match '(?i)connectionstring\s*["'']\s*:\s*["'']([^"'']+)["'']') {
      foreach ($m in ([regex]::Matches($content, '(?i)connectionstring\s*["'']\s*:\s*["'']([^"'']+)["'']'))) {
        $connectionStrings += $m.Groups[1].Value
      }
    }
    $seen = @{}
    foreach ($cs in $connectionStrings) {
      $cs = $cs -replace '&quot;', '"' -replace '&apos;', "'"
      if ($seen[$cs]) { continue }; $seen[$cs] = $true
      $parsed = Parse-ConnectionStringToHash -ConnectionString $cs
      if ([string]::IsNullOrWhiteSpace($parsed.DataSource)) { continue }
      $connTarget = $parsed.DataSource
      if (-not [string]::IsNullOrWhiteSpace($parsed.InitialCatalog)) { $connTarget = "$($parsed.DataSource)\$($parsed.InitialCatalog)" }
      $isOld = $DomainMatchers.Match($parsed.DataSource)
      $results += [pscustomobject]@{
        LocationType = 'Config'
        Location = $FilePath
        ConnectionTarget = $connTarget
        Parsed = [pscustomobject]@{
          DataSource = $parsed.DataSource
          InitialCatalog = $parsed.InitialCatalog
          UserId = $parsed.UserId
          IntegratedSecurity = $parsed.IntegratedSecurity
          HasPassword = $parsed.HasPassword
          IsOldDomainServer = $isOld
        }
      }
    }
  } catch {
    if ($Log) { $Log.Write("Get-DatabaseConnectionsFromConfigFile: $FilePath : $($_.Exception.Message)", 'WARN') }
  }
  return $results
}

function Get-ApplicationConfigDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  $configFilesWithDomainRefs = @()
  $configFilesWithCredentials = @()
  
  try {
    if ($Log) { $Log.Write('Scanning application configuration files for domain references and credentials', 'INFO') }
    
    # Common application configuration file patterns
    $configFilePatterns = @(
      '*.config',
      '*.ini',
      '*.conf',
      '*.xml',
      '*.json',
      '*.properties',
      '*.yaml',
      '*.yml',
      'web.config',
      'app.config',
      'appsettings.json',
      'connectionstrings.config',
      'settings.ini'
    )
    
    # Common application configuration file locations (non-recursive first level)
    $appConfigLocations = @(
      "$env:ProgramFiles",
      "${env:ProgramFiles(x86)}",
      "$env:ProgramData",
      "$env:ALLUSERSPROFILE",
      "$env:APPDATA",
      "$env:LOCALAPPDATA",
      "$env:USERPROFILE"
    )
    
    # Also check common application subdirectories
    $appSubdirs = @(
      '\AppData\Local',
      '\AppData\Roaming',
      '\Documents',
      '\Application Data'
    )
    
    $allConfigPaths = @()
    
    # Scan Program Files and Program Files (x86) - limit depth to avoid performance issues
    foreach ($basePath in @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")) {
      if (Test-Path $basePath) {
        try {
          # Look for common config files in first-level subdirectories (one level deep)
          $directories = $null
          try {
            $directories = Get-ChildItem -Path $basePath -Directory -ErrorAction Stop
          } catch {
            if ($Log) { $Log.Write("Error accessing directories in $basePath : $($_.Exception.Message)", 'WARN') }
            continue
          }
          
          foreach ($dir in $directories) {
            $appDir = $dir.FullName
            foreach ($pattern in $configFilePatterns) {
              try {
                $files = Get-ChildItem -Path $appDir -Filter $pattern -Recurse -Depth 2 -ErrorAction Stop | Select-Object -First 10
                if ($files) {
                  $allConfigPaths += $files
                }
              } catch {
                # Skip directories we can't access (permissions, locked files, etc.)
                # This is expected and not an error
              }
            }
          }
        } catch {
          if ($Log) { $Log.Write("Error scanning $basePath : $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'WARN') }
        }
      }
    }
    
    # Scan ProgramData - common location for application configs
    if (Test-Path $env:ProgramData) {
      try {
        $directories = $null
        try {
          $directories = Get-ChildItem -Path $env:ProgramData -Directory -ErrorAction Stop
        } catch {
          if ($Log) { $Log.Write("Error accessing directories in ProgramData: $($_.Exception.Message)", 'WARN') }
          # Continue to next section instead of failing entirely
        }
        
        if ($directories) {
          foreach ($dir in $directories) {
            $appDir = $dir.FullName
            foreach ($pattern in $configFilePatterns) {
              try {
                $files = Get-ChildItem -Path $appDir -Filter $pattern -Recurse -Depth 2 -ErrorAction Stop | Select-Object -First 10
                if ($files) {
                  $allConfigPaths += $files
                }
              } catch {
                # Skip directories we can't access (permissions, locked files, etc.)
                # This is expected and not an error
              }
            }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error scanning ProgramData: $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'WARN') }
      }
    }
    
    # Scan user profile directories for config files
    $userProfilesPath = "$env:SystemDrive\Users"
    if (Test-Path $userProfilesPath) {
      try {
        $userDirs = $null
        try {
          $userDirs = Get-ChildItem -Path $userProfilesPath -Directory -ErrorAction Stop
        } catch {
          if ($Log) { $Log.Write("Error accessing user profile directories: $($_.Exception.Message)", 'WARN') }
          # Continue - may not have permission to list all user directories
        }
        
        if ($userDirs) {
          foreach ($userDirObj in $userDirs) {
            $userDir = $userDirObj.FullName
            $appDataLocal = Join-Path $userDir 'AppData\Local'
            $appDataRoaming = Join-Path $userDir 'AppData\Roaming'
            
            foreach ($userAppPath in @($appDataLocal, $appDataRoaming)) {
              if (Test-Path $userAppPath) {
                try {
                  foreach ($pattern in $configFilePatterns) {
                    try {
                      $files = Get-ChildItem -Path $userAppPath -Filter $pattern -Recurse -Depth 2 -ErrorAction Stop | Select-Object -First 5
                      if ($files) {
                        $allConfigPaths += $files
                      }
                    } catch {
                      # Skip directories we can't access (permissions, locked files, etc.)
                      # This is expected and not an error
                    }
                  }
                } catch {
                  # Skip this user's app data directory if we can't access it
                }
              }
            }
          }
        }
      } catch {
        if ($Log) { $Log.Write("Error scanning user profiles: $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'WARN') }
      }
    }
    
    # Remove duplicates
    $allConfigPaths = $allConfigPaths | Sort-Object FullName -Unique
    
    if ($Log) { $Log.Write("Found $($allConfigPaths.Count) configuration files to scan", 'INFO') }
    
    # Scan each file for domain references and credentials
    $filesScanned = 0
    $maxFilesToScan = 500  # Limit to avoid performance issues
    
    foreach ($configFile in $allConfigPaths) {
      if ($filesScanned -ge $maxFilesToScan) {
        if ($Log) { $Log.Write("Reached maximum file scan limit ($maxFilesToScan), stopping scan", 'INFO') }
        break
      }
      
      try {
        if (-not (Test-Path -LiteralPath $configFile.FullName)) { continue }
        
        # Skip very large files (> 5MB) to avoid memory issues
        $fileInfo = $null
        try {
          $fileInfo = Get-Item -LiteralPath $configFile.FullName -ErrorAction Stop
        } catch {
          # Can't access file info, skip this file
          continue
        }
        
        if ($fileInfo -and $fileInfo.Length -gt 5MB) { continue }
        # Skip empty or nearly empty files (noise, nothing actionable)
        if ($fileInfo -and $fileInfo.Length -le 32) { continue }
        # Skip common log/trace files (domain refs there are usually transient, not config)
        $ext = [System.IO.Path]::GetExtension($configFile.FullName).ToLowerInvariant()
        $pathUpper = $configFile.FullName.ToUpperInvariant()
        if ($ext -in @('.log', '.trace', '.trc', '.evtx') -or $pathUpper -like '*\LOGS\*' -or $pathUpper -like '*\LOG\*') { continue }
        
        $content = $null
        $matchedLines = @()
        $hasDomainRef = $false
        $hasCredentials = $false
        $credentialPatterns = @()
        
        try {
          # Try to read as text with UTF8 encoding
          $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction Stop -Encoding UTF8
        } catch {
          # Try alternative encoding
          try {
            $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction Stop -Encoding Default
          } catch {
            # Skip files we can't read (may be locked, binary, or permission denied)
            # This is expected and not an error
            continue
          }
        }
        
        if (-not $content) { continue }
        
        $filesScanned++
        
        # Check for domain references
        if ($DomainMatchers.Match($content)) {
          $hasDomainRef = $true
          $lines = $content -split "`r?`n"
          foreach ($line in $lines) {
            if ($DomainMatchers.Match($line)) {
              $matchedLines += $line.Trim()
              if ($matchedLines.Count -ge 10) { break }  # Limit matched lines
            }
          }
        }
        
        # Check for embedded credentials (connection strings, passwords, etc.)
        # Look for common patterns that might indicate credentials
        $credentialIndicators = @(
          'password\s*[=:]\s*["'']?[^"'']+["'']?',  # password=value or password:value
          'pwd\s*[=:]\s*["'']?[^"'']+["'']?',       # pwd=value
          'passwd\s*[=:]\s*["'']?[^"'']+["'']?',    # passwd=value
          'connectionstring\s*[=:]\s*["'']?[^"'']+["'']?',  # connectionstring=value
          'connection\s*string\s*[=:]\s*["'']?[^"'']+["'']?',  # connection string=value
          'user\s*id\s*[=:]\s*["'']?[^"'']+["'']?',  # user id=value
          'userid\s*[=:]\s*["'']?[^"'']+["'']?',     # userid=value
          'uid\s*[=:]\s*["'']?[^"'']+["'']?',        # uid=value
          'integrated\s+security\s*[=:]\s*["'']?true["'']?',  # integrated security=true (Windows auth)
          'trusted_connection\s*[=:]\s*["'']?true["'']?'     # trusted_connection=true
        )
        
        foreach ($pattern in $credentialIndicators) {
          if ($content -match $pattern -and -not $hasCredentials) {
            $hasCredentials = $true
            $credentialPatterns += $pattern
          }
        }
        
        # Also check if connection strings contain domain references (even if no explicit password)
        if ($content -match '(?i)connectionstring|connection\s+string|data\s+source|server\s*=') {
          if ($DomainMatchers.Match($content)) {
            $hasCredentials = $true
            $credentialPatterns += 'ConnectionStringWithDomain'
          }
        }
        
        # Record findings (redact MatchedLines before storing - no secrets in JSON/Excel)
        $linesToStore = @()
        if ($matchedLines.Count -gt 0) {
          $cap = [Math]::Min(10, $matchedLines.Count - 1)
          for ($i = 0; $i -le $cap; $i++) {
            $linesToStore += Hide-SensitiveText -InputString $matchedLines[$i]
          }
        }
        if ($hasDomainRef -or $hasCredentials) {
          $fileSizeVal = $null; if ($fileInfo) { $fileSizeVal = $fileInfo.Length }
          $fileResult = [pscustomobject]@{
            FilePath = $configFile.FullName
            FileName = $configFile.Name
            FileSize = $fileSizeVal
            HasDomainReference = $hasDomainRef
            HasCredentials = $hasCredentials
            MatchedLines = $linesToStore
            TotalDomainMatches = $matchedLines.Count
            CredentialPatterns = $credentialPatterns
          }
          
          if ($hasDomainRef) {
            $configFilesWithDomainRefs += $fileResult
          }
          if ($hasCredentials) {
            $configFilesWithCredentials += $fileResult
          }
        }
      } catch {
        # Skip files that cause errors (locked, corrupted, permission denied, etc.)
        # Log with exception type for debugging
        if ($Log) { $Log.Write("Error scanning file $($configFile.FullName): $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'WARN') }
      }
    }
    
    if ($Log) { 
      $Log.Write("Scanned $filesScanned configuration files", 'INFO')
      $Log.Write("Found $($configFilesWithDomainRefs.Count) files with domain references", 'INFO')
      $Log.Write("Found $($configFilesWithCredentials.Count) files with potential credentials", 'INFO')
    }
    
  } catch {
    # Catch any unexpected errors in the overall scanning process
    if ($Log) { 
      $Log.Write("Error in application config file scanning: $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'ERROR') 
      if ($_.Exception.InnerException) {
        $Log.Write("Inner exception: $($_.Exception.InnerException.Message)", 'ERROR')
      }
    }
    # Return partial results if available rather than failing completely
  }
  
  # Return results
  if ($configFilesWithDomainRefs.Count -eq 0 -and $configFilesWithCredentials.Count -eq 0) {
    return $null
  }
  
  return [pscustomobject]@{
    FilesWithDomainReferences = $configFilesWithDomainRefs
    FilesWithCredentials = $configFilesWithCredentials
    TotalFilesScanned = $filesScanned
    TotalFilesWithDomainRefs = $configFilesWithDomainRefs.Count
    TotalFilesWithCredentials = $configFilesWithCredentials.Count
  }
}
function Get-EventLogDomainReferences {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $DomainMatchers,
    [Parameter(Mandatory)]
    [int]$DaysBack,
    [Parameter(Mandatory=$false)]
    $Log
  )
  
  $results = @()
  $maxEventsPerLog = 100
  $logNames = @('System', 'Security', 'Application')
  $startTime = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
  # Security log event IDs that are purely logon/logoff (domain refs are transient, not config) - exclude to reduce noise
  $securityLogonEventIds = @(4624, 4625, 4634, 4647, 4672, 4648, 4768, 4769, 4770, 4771, 4776, 4778, 4779)
  
  if ($Log) { $Log.Write("Scanning event logs for domain references (last $DaysBack days, max $maxEventsPerLog per log; Security logon events excluded)") }
  
  foreach ($logName in $logNames) {
    try {
      # Check if log exists and is accessible
      $logExists = $null
      try {
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop
      } catch {
        # Log exists check failed - log may not exist, be inaccessible, or require special permissions
        if ($Log) { $Log.Write("Event log '$logName' not accessible: $($_.Exception.Message)", 'WARN') }
        continue
      }
      
      if (-not $logExists) {
        if ($Log) { $Log.Write("Event log '$logName' not found", 'WARN') }
        continue
      }
      
      # Query events within time window (query more events since we'll filter many out)
      # FilterHashtable must include LogName in hashtable on some systems; fallback to unfiltered + Where-Object if it fails
      $events = $null
      try {
        $events = Get-WinEvent -FilterHashtable @{
          LogName = $logName
          StartTime = $startTime
        } -ErrorAction Stop -MaxEvents ($maxEventsPerLog * 5)
      } catch {
        try {
          $events = Get-WinEvent -LogName $logName -MaxEvents ($maxEventsPerLog * 5) -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $startTime } | Select-Object -First ($maxEventsPerLog * 5)
        } catch {
          if ($Log) { $Log.Write("Unable to query events from log '$logName': $($_.Exception.Message)", 'WARN') }
          continue
        }
      }
      
      if (-not $events) { continue }
      
      $matchedCount = 0
      foreach ($event in $events) {
        # Stop if we've reached the limit
        if ($matchedCount -ge $maxEventsPerLog) { break }
        try {
          if ($null -eq $event) { continue }
          
          # Get message text
          $message = $null
          try {
            $message = $event.Message
          } catch {
            # Some events may not have readable messages, try to get formatted message
            try {
              $message = $event | Format-List -Property * | Out-String
            } catch {
              # If we can't get message, skip this event
              continue
            }
          }
          
          if ([string]::IsNullOrWhiteSpace($message)) { continue }
          
          # Skip Security log logon/logoff events (domain\user in message is transient, not config)
          if ($logName -eq 'Security' -and $securityLogonEventIds -contains $event.Id) { continue }
          
          # Check if message contains domain reference
          if ($DomainMatchers.Match($message)) {
            # Extract a snippet (truncate to 200 chars for performance); redact before storing
            $snippet = $message
            if ($snippet.Length -gt 200) {
              $snippet = $message.Substring(0, 200) + '...'
            }
            $snippet = Hide-SensitiveText -InputString $snippet
            
            $timeCreatedVal = $null; if ($event.TimeCreated) { $timeCreatedVal = $event.TimeCreated.ToString('o') }
            $levelDisplayVal = $null; if ($event.LevelDisplayName) { $levelDisplayVal = $event.LevelDisplayName }
            $results += [pscustomobject]@{
              LogName = $logName
              TimeCreated = $timeCreatedVal
              Id = $event.Id
              LevelDisplayName = $levelDisplayVal
              MessageSnippet = $snippet
            }
            
            $matchedCount++
            if ($matchedCount -ge $maxEventsPerLog) { break }
          }
        } catch {
          if ($Log) { $Log.Write("Error processing event $($event.Id) from log $logName : $($_.Exception.Message)", 'WARN') }
        }
      }
      
      if ($Log -and $matchedCount -gt 0) { 
        $Log.Write("Found $matchedCount domain reference(s) in $logName log") 
      }
    } catch {
      # Catch any other errors accessing the event log (permissions, corruption, etc.)
      # Note: Some event logs (especially Security) may require special audit permissions
      # even for local administrators. This is expected behavior and not a script error.
      if ($Log) { 
        $Log.Write("Error accessing event log '$logName': $($_.Exception.Message) (Type: $($_.Exception.GetType().Name))", 'WARN') 
      }
      # Continue to next log instead of failing entirely
      continue
    }
  }
  
  return $results
}

function Get-OracleDiscovery {
  [CmdletBinding()]
  param([Parameter(Mandatory = $false)] $Log)
  $errors = @()
  $oracleServices = @()
  $oracleHomes = @()
  $tnsnamesFiles = @()
  $sqlNetConfigPaths = @()
  $oracleOdbcDrivers = @()
  $isOracleServerLikely = $false
  $oracleClientInstalled = $false

  try {
    # Services: OracleService*, TNSListener, OracleVssWriter*, etc.
    $svcPatterns = @('OracleService*', 'TNSListener', 'OracleVssWriter*', 'Oracle*Service*', 'OracleMTSRecoveryService', 'OracleJobScheduler*')
    try {
      $allSvcs = Get-Service -ErrorAction SilentlyContinue
      foreach ($s in $allSvcs) {
        $match = $false
        foreach ($p in $svcPatterns) {
          if ($s.Name -like $p) { $match = $true; break }
        }
        if ($match) {
          $isOracleServerLikely = $true
          $oracleServices += [pscustomobject]@{
            Name       = $s.Name
            DisplayName = $s.DisplayName
            Status     = $s.Status.ToString()
            StartType = $s.StartType.ToString()
          }
        }
      }
    } catch { $errors += "Services: $($_.Exception.Message)" }

    # Registry: HKLM\SOFTWARE\Oracle and WOW6432Node
    $regPaths = @('SOFTWARE\Oracle', 'SOFTWARE\WOW6432Node\Oracle')
    foreach ($regPath in $regPaths) {
      try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        $key = $base.OpenSubKey($regPath)
        if ($key) {
          $oracleClientInstalled = $true
          foreach ($subName in $key.GetSubKeyNames()) {
            try {
              $sub = $key.OpenSubKey($subName)
              if ($sub) {
                $oh = $sub.GetValue('ORACLE_HOME')
                if ($oh) { $oracleHomes += $oh }
                $sub.Close()
              }
            } catch {}
          }
          $key.Close()
        }
      } catch {}
    }
    $oracleHomes = $oracleHomes | Sort-Object -Unique

    # ODBC drivers (Oracle)
    try {
      $odbcKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default).OpenSubKey('SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers')
      if ($odbcKey) {
        foreach ($name in $odbcKey.GetValueNames()) {
          if ($name -match 'Oracle' -or $name -match 'Oracle in') {
            $oracleOdbcDrivers += $name
            $oracleClientInstalled = $true
          }
        }
        $odbcKey.Close()
      }
    } catch {}
    # 32-bit drivers
    try {
      $odbcKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32).OpenSubKey('SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers')
      if ($odbcKey) {
        foreach ($name in $odbcKey.GetValueNames()) {
          if (($name -match 'Oracle' -or $name -match 'Oracle in') -and $oracleOdbcDrivers -notcontains $name) {
            $oracleOdbcDrivers += $name
            $oracleClientInstalled = $true
          }
        }
        $odbcKey.Close()
      }
    } catch {}

    # Filesystem: tnsnames.ora, sqlnet.ora, listener.ora (paths only)
    $searchDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ORACLE_HOME, $env:TNS_ADMIN)
    foreach ($oh in $oracleHomes) { if ($oh -and (Test-Path -LiteralPath $oh -ErrorAction SilentlyContinue)) { $searchDirs += $oh } }
    $searchDirs = $searchDirs | Where-Object { $_ } | Sort-Object -Unique
    $oraFiles = @('tnsnames.ora', 'sqlnet.ora', 'listener.ora')
    foreach ($dir in $searchDirs) {
      if (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) { continue }
      try {
        $items = Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -Filter 'tnsnames.ora' | Select-Object -First 20
        foreach ($f in $items) { if ($f.FullName -notin $tnsnamesFiles) { $tnsnamesFiles += $f.FullName } }
        $items = Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -Filter 'sqlnet.ora' | Select-Object -First 20
        foreach ($f in $items) { if ($f.FullName -notin $sqlNetConfigPaths) { $sqlNetConfigPaths += $f.FullName } }
        $items = Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -Filter 'listener.ora' | Select-Object -First 20
        foreach ($f in $items) { if ($f.FullName -notin $sqlNetConfigPaths) { $sqlNetConfigPaths += $f.FullName } }
      } catch {}
    }
  } catch {
    $errors += $_.Exception.Message
  }

  $oracleInstalled = $isOracleServerLikely -or $oracleClientInstalled
  $oracleVersion = $null
  try {
    # Try to get version from first Oracle home path (e.g. ...\product\19.0.0\client_1) or registry key name
    foreach ($oh in $oracleHomes) {
      if ($oh -match '\\product\\(\d+\.\d+\.\d+)') {
        $oracleVersion = $Matches[1]
        break
      }
    }
    if (-not $oracleVersion) {
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
      $key = $base.OpenSubKey('SOFTWARE\Oracle')
      if ($key) {
        foreach ($subName in $key.GetSubKeyNames()) {
          if ($subName -match '(\d+\.\d+\.\d+)') { $oracleVersion = $Matches[1]; break }
          if ($subName -match 'KEY_Ora.*?(\d+)c') { $oracleVersion = "$($Matches[1]).0.0"; break }
        }
        $key.Close()
      }
    }
  } catch {}

  $errorsOut = $null; if ($errors.Count -gt 0) { $errorsOut = $errors }
  return [pscustomobject]@{
    OracleInstalled       = $oracleInstalled
    OracleVersion         = $oracleVersion
    IsOracleServerLikely  = $isOracleServerLikely
    OracleServices        = $oracleServices
    OracleHomes           = $oracleHomes
    OracleClientInstalled = $oracleClientInstalled
    OracleODBCDrivers     = $oracleOdbcDrivers
    TnsnamesFiles         = $tnsnamesFiles
    SqlNetConfigPaths     = $sqlNetConfigPaths
    Errors                = $errorsOut
  }
}

function Get-RDSLicensingDiscovery {
  [CmdletBinding()]
  param([Parameter(Mandatory = $false)] $Log)
  $errors = @()
  $evidence = @()
  $isRdsSessionHost = $false
  $rdsRoleInstalled = $null  # Unknown when Get-WindowsFeature not available
  $licensingMode = 'Unknown'
  $licenseServers = @()
  $isLikelyInUse = $false
  $rdsLicensingRoleInstalled = $false  # RDS-Licensing role (license server / CALs)

  try {
    # TermService present indicates RDP/RDS capability
    try {
      $ts = Get-Service -Name TermService -ErrorAction SilentlyContinue
      if ($ts) { $evidence += 'TermService present'; $isRdsSessionHost = $true }
    } catch {}

    # Get-WindowsFeature when available (Server OS)
    try {
      if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $rdServer = Get-WindowsFeature -Name RDS-RD-Server -ErrorAction SilentlyContinue
        if ($rdServer -and $rdServer.Installed) {
          $rdsRoleInstalled = $true
          $evidence += 'RDS-RD-Server feature installed'
        } else {
          $rdsRoleInstalled = $false
        }
        # RDS-Licensing role: license server where CALs can be installed
        $rdLicensing = Get-WindowsFeature -Name RDS-Licensing -ErrorAction SilentlyContinue
        if ($rdLicensing -and $rdLicensing.Installed) {
          $rdsLicensingRoleInstalled = $true
          $evidence += 'RDS-Licensing role installed'
        }
      }
    } catch {}

    # WMI/CIM: Win32_TerminalServiceSetting for licensing mode and license servers
    try {
      $tsSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TerminalServiceSetting -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($tsSetting) {
        # LicensingType: 0=NotConfigured, 1=PerDevice, 2=PerUser (documented for Win32_TerminalServiceSetting)
        $lt = $tsSetting.LicensingType
        if ($null -ne $lt) {
          switch ([int]$lt) {
            0 { $licensingMode = 'NotConfigured' }
            1 { $licensingMode = 'PerDevice'; $evidence += 'LicensingMode=PerDevice' }
            2 { $licensingMode = 'PerUser'; $evidence += 'LicensingMode=PerUser' }
            default { $licensingMode = "Raw$lt" }
          }
        }
        try {
          $list = $tsSetting.GetSpecifiedLicenseServerList()
          if ($list -and $list.Length -gt 0) {
            $licenseServers = @($list)
            $evidence += "LicenseServerConfigured($($list.Length))"
          }
        } catch {}
      }
    } catch { $errors += "WMI TerminalService: $($_.Exception.Message)" }

    # Registry: Terminal Server licensing
    $regPaths = @(
      'SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core',
      'SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing'
    )
    foreach ($regPath in $regPaths) {
      try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        $key = $base.OpenSubKey($regPath)
        if ($key) {
          $ls = $key.GetValue('LicenseServers')
          if ($ls) {
            $evidence += 'Registry LicenseServers'
            if ($ls -is [string] -and $ls -notin $licenseServers) { $licenseServers += $ls }
            elseif ($ls -is [array]) { foreach ($s in $ls) { if ($s -notin $licenseServers) { $licenseServers += $s } } }
          }
          $key.Close()
        }
      } catch {}
    }

    # Small event log probe: TerminalServices licensing, last 14 days, max 30 events
    try {
      $logNames = @('Microsoft-Windows-TerminalServices-Licensing/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational')
      $startTime = (Get-Date).AddDays(-14)
      foreach ($logName in $logNames) {
        try {
          $events = Get-WinEvent -LogName $logName -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $startTime }
          if ($events -and $events.Count -gt 0) {
            $evidence += "Events:$logName($($events.Count))"
          }
        } catch {}
      }
    } catch {}

    $isLikelyInUse = ($licensingMode -notin @('Unknown', 'NotConfigured')) -or ($licenseServers.Count -gt 0) -or ($evidence.Count -gt 1)
  } catch {
    $errors += $_.Exception.Message
  }

  $rdsErrorsOut = $null; if ($errors.Count -gt 0) { $rdsErrorsOut = $errors }
  return [pscustomobject]@{
    IsRDSSessionHost          = $isRdsSessionHost
    RDSRoleInstalled          = $rdsRoleInstalled
    RdsLicensingRoleInstalled  = $rdsLicensingRoleInstalled
    LicensingMode             = $licensingMode
    LicenseServerConfigured   = $licenseServers
    RDSLicensingEvidence      = $evidence
    IsRDSLicensingLikelyInUse = $isLikelyInUse
    Errors                    = $rdsErrorsOut
  }
}

Export-ModuleMember -Function Hide-SensitiveText, Get-SqlServerPresence, Get-CredentialManagerDomainReferences, Get-CertificatesWithDomainReferences, Get-FirewallRulesWithDomainReferences, Get-IISDomainReferences, Get-SqlDomainReferences, Get-EventLogDomainReferences, Get-ApplicationConfigDomainReferences, Get-DatabaseConnectionsFromConfigFile, Get-OracleDiscovery, Get-RDSLicensingDiscovery
