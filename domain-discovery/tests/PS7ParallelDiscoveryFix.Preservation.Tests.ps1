#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Preservation property tests for PS7 parallel discovery fix.
    These tests observe and encode baseline behavior on UNFIXED code.
    All tests should PASS on unfixed code — confirming behavior to preserve.

.DESCRIPTION
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    Property 2: Preservation — Output Format, Error Handling, and Downstream
    Behavior Identical to PS5.1.

    Observation-first methodology: each test observes the current (unfixed) code
    behavior, then encodes that behavior as the expected property.
#>

BeforeAll {
    # ── Source the PS7 script functions without executing the main body ──
    # We extract function definitions from the script and dot-source them.
    $script:PS7ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'Invoke-MigrationDiscoveryRemotely.PS7.ps1'
    $script:PS7ScriptContent = Get-Content -Path $script:PS7ScriptPath -Raw

    # Extract function bodies from the PS7 script and define them in this scope.
    # We pull out: Write-ErrorLog, Write-DiscoveryScanResultsFile,
    #              Merge-ScanRowsWithAllTargets, Build-ScanRowFromDiscoveryJsonPath,
    #              Get-InvokeResultListKey

    $functionNames = @(
        'Write-ErrorLog'
        'Write-DiscoveryScanResultsFile'
        'Merge-ScanRowsWithAllTargets'
        'Build-ScanRowFromDiscoveryJsonPath'
        'Get-InvokeResultListKey'
    )

    foreach ($fname in $functionNames) {
        # Match function definition: function Name { ... } with balanced braces
        $escapedName = [regex]::Escape($fname)
        $pattern = "(?ms)^function\s+${escapedName}\s*\{(.+?)^\}"
        $m = [regex]::Match($script:PS7ScriptContent, $pattern)
        if ($m.Success) {
            $funcBody = $m.Value
            # Replace script-scoped variable references for test isolation
            $funcDef = $funcBody -replace '\$script:ErrorLogPath', '$script:TestErrorLogPath'
            Invoke-Expression $funcDef
        }
    }

    # Import the RemotingFailures module for Resolve-RemoteGatheringFailure
    $script:RemotingFailuresModulePath = Join-Path (Join-Path $PSScriptRoot '..') 'DomainMigrationDiscovery.RemotingFailures.psm1'
    Import-Module $script:RemotingFailuresModulePath -Force

    # Set up a temp directory for test outputs
    $script:TestTempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PS7PreservationTests_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -Path $script:TestTempDir -ItemType Directory -Force | Out-Null
    $script:TestErrorLogPath = Join-Path $script:TestTempDir 'error.log'
}

AfterAll {
    if ($script:TestTempDir -and (Test-Path $script:TestTempDir)) {
        Remove-Item -Path $script:TestTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Module DomainMigrationDiscovery.RemotingFailures -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════
# 1. Write-ErrorLog format preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Write-ErrorLog format' {
    <#
        **Validates: Requirements 3.1**
        Write-ErrorLog must produce lines in the format:
          [timestamp] [ServerName] [ErrorType] ErrorMessage
        where timestamp is yyyy-MM-dd HH:mm:ss
    #>

    BeforeEach {
        $script:TestErrorLogPath = Join-Path $script:TestTempDir "error_$(New-Guid).log"
    }

    Context 'Property-based: various server names and error types produce consistent format' {

        It 'Should produce [timestamp] [<ServerName>] [<ErrorType>] <Message> format' -ForEach @(
            @{ ServerName = 'SERVER01';   ErrorMessage = 'Connection refused';           ErrorType = 'ERROR' }
            @{ ServerName = 'web-srv-02'; ErrorMessage = 'WinRM timeout';                ErrorType = 'CONNECTION_ERROR' }
            @{ ServerName = 'DB_SERVER';  ErrorMessage = 'Access denied to remote host'; ErrorType = 'SCRIPT_EXECUTION_ERROR' }
            @{ ServerName = 'APP.corp.local'; ErrorMessage = 'File not found on remote'; ErrorType = 'FILE_COLLECTION_ERROR' }
            @{ ServerName = 'SINGLE';     ErrorMessage = 'Generic failure message';      ErrorType = 'FATAL' }
            @{ ServerName = 'host-with-special_chars.domain'; ErrorMessage = 'Payload decode failed | extra detail'; ErrorType = 'ERROR' }
            @{ ServerName = '';           ErrorMessage = 'Empty server name test';        ErrorType = 'ERROR' }
            @{ ServerName = 'SRV';        ErrorMessage = '';                              ErrorType = 'WARNING' }
        ) {
            Write-ErrorLog -ServerName $ServerName -ErrorMessage $ErrorMessage -ErrorType $ErrorType

            $logContent = Get-Content -Path $script:TestErrorLogPath -Raw
            $lines = @($logContent -split "`n" | Where-Object { $_.Trim() })
            $lines.Count | Should -BeGreaterOrEqual 1

            $lastLine = $lines[-1].Trim()
            # Format: [yyyy-MM-dd HH:mm:ss] [ServerName] [ErrorType] ErrorMessage
            $expectedPattern = '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[' + [regex]::Escape($ServerName) + '\] \[' + [regex]::Escape($ErrorType) + '\]\s*' + [regex]::Escape($ErrorMessage) + '\s*$'
            $lastLine | Should -Match $expectedPattern
        }

        It 'Should default ErrorType to ERROR when not specified' {
            Write-ErrorLog -ServerName 'TESTHOST' -ErrorMessage 'Default error type test'

            $logContent = Get-Content -Path $script:TestErrorLogPath -Raw
            $lastLine = @($logContent -split "`n" | Where-Object { $_.Trim() })[-1].Trim()
            $lastLine | Should -Match '\[ERROR\]'
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 2. Write-DiscoveryScanResultsFile schema preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Write-DiscoveryScanResultsFile JSON schema' {
    <#
        **Validates: Requirements 3.2**
        scan_results.json must contain:
          Schema = 'DomainMigrationDiscovery.ScanResults/v1'
          Orchestrator, GeneratedAtUtc, ServerListPath, PlantId, Hosts[]
        Each host row must have the full set of per-host fields.
    #>

    $hostFields = @(
        'ServerListEntry', 'ResolvedComputerName', 'Outcome',
        'ConnectionErrorCategory', 'FailureReasonCode', 'FailureReasonSummary',
        'TechnicalDetail', 'JsonFileName', 'PowerShellVersion',
        'CompatibilityMode', 'UnavailableSectionsSummary', 'ConfigFileIssue',
        'DetailMessage'
    )

    Context 'Property-based: various host scan row combinations produce valid schema' {

        It 'Should produce valid schema with <Description>' -ForEach @(
            @{
                Description = 'empty host list'
                Rows = @()
                ServerListPath = 'C:\servers.txt'
                PlantId = 'PLANT01'
            }
            @{
                Description = 'single successful host'
                Rows = @(
                    [pscustomobject]@{
                        ServerListEntry = 'SRV01'; ResolvedComputerName = 'SRV01'
                        Outcome = 'Fully successful'; ConnectionErrorCategory = $null
                        FailureReasonCode = $null; FailureReasonSummary = $null
                        TechnicalDetail = $null; JsonFileName = 'SRV01_01-15-2025.json'
                        PowerShellVersion = '5.1.19041.4291'; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = $null
                    }
                )
                ServerListPath = '.\servers.txt'
                PlantId = 'PLANT01'
            }
            @{
                Description = 'mixed success and failure hosts'
                Rows = @(
                    [pscustomobject]@{
                        ServerListEntry = 'SRV01'; ResolvedComputerName = 'SRV01'
                        Outcome = 'Fully successful'; ConnectionErrorCategory = $null
                        FailureReasonCode = $null; FailureReasonSummary = $null
                        TechnicalDetail = $null; JsonFileName = 'SRV01_01-15-2025.json'
                        PowerShellVersion = '5.1'; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = $null
                    }
                    [pscustomobject]@{
                        ServerListEntry = 'SRV02'; ResolvedComputerName = $null
                        Outcome = 'Could not connect (WinRM)'; ConnectionErrorCategory = 'TcpUnreachable'
                        FailureReasonCode = 'TcpUnreachable'; FailureReasonSummary = 'Connection timed out'
                        TechnicalDetail = 'Timeout detail'; JsonFileName = $null
                        PowerShellVersion = $null; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = 'Timeout detail'
                    }
                    [pscustomobject]@{
                        ServerListEntry = 'SRV03'; ResolvedComputerName = 'SRV03'
                        Outcome = 'Discovery or payload failed'; ConnectionErrorCategory = 'RemoteScriptFailed'
                        FailureReasonCode = 'RemoteScriptFailed'; FailureReasonSummary = 'Script error'
                        TechnicalDetail = 'Script threw exception'; JsonFileName = $null
                        PowerShellVersion = $null; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = 'Script threw exception'
                    }
                )
                ServerListPath = 'C:\data\servers.txt'
                PlantId = $null
            }
            @{
                Description = 'multiple failure hosts with various error categories'
                Rows = @(
                    [pscustomobject]@{
                        ServerListEntry = 'HOST-A'; ResolvedComputerName = $null
                        Outcome = 'Could not connect (WinRM)'; ConnectionErrorCategory = 'AuthenticationFailed'
                        FailureReasonCode = 'AuthenticationFailed'; FailureReasonSummary = 'Auth failed'
                        TechnicalDetail = 'Access denied'; JsonFileName = $null
                        PowerShellVersion = $null; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = 'Access denied'
                    }
                    [pscustomobject]@{
                        ServerListEntry = 'HOST-B'; ResolvedComputerName = $null
                        Outcome = 'Could not connect (WinRM)'; ConnectionErrorCategory = 'DnsNameNotResolved'
                        FailureReasonCode = 'DnsNameNotResolved'; FailureReasonSummary = 'DNS failed'
                        TechnicalDetail = 'No such host'; JsonFileName = $null
                        PowerShellVersion = $null; CompatibilityMode = $null
                        UnavailableSectionsSummary = $null; ConfigFileIssue = $false
                        DetailMessage = 'No such host'
                    }
                )
                ServerListPath = '\\share\servers.txt'
                PlantId = 'PLANT99'
            }
        ) {
            $outDir = Join-Path $script:TestTempDir "scanresults_$(New-Guid)"
            Write-DiscoveryScanResultsFile `
                -OutputDirectory $outDir `
                -HostScanRows $Rows `
                -ServerListPath $ServerListPath `
                -PlantId $PlantId

            $jsonPath = Join-Path $outDir 'scan_results.json'
            Test-Path $jsonPath | Should -BeTrue

            $json = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json

            # Top-level schema fields
            $json.Schema | Should -BeExactly 'DomainMigrationDiscovery.ScanResults/v1'
            $json.PSObject.Properties.Name | Should -Contain 'Orchestrator'
            $json.PSObject.Properties.Name | Should -Contain 'GeneratedAtUtc'
            $json.PSObject.Properties.Name | Should -Contain 'ServerListPath'
            $json.PSObject.Properties.Name | Should -Contain 'PlantId'
            $json.PSObject.Properties.Name | Should -Contain 'Hosts'
            $json.ServerListPath | Should -BeExactly $ServerListPath

            # Orchestrator note
            $json.Orchestrator | Should -Match 'PS7'

            # GeneratedAtUtc should be a parseable ISO 8601 timestamp
            { [DateTime]::Parse($json.GeneratedAtUtc) } | Should -Not -Throw

            # Hosts array length matches input
            @($json.Hosts).Count | Should -Be @($Rows).Count

            # Each host row must have all expected fields
            foreach ($hostItem in @($json.Hosts)) {
                foreach ($field in $hostFields) {
                    $hostItem.PSObject.Properties.Name | Should -Contain $field -Because "Host row must contain field '$field'"
                }
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 3. Resolve-RemoteGatheringFailure classification preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Resolve-RemoteGatheringFailure error classification' {
    <#
        **Validates: Requirements 3.1**
        For various error records with -Stage SessionCreate, the function must
        produce consistent FailureReasonCode, FailureReasonSummary, and TechnicalDetail.
    #>

    Context 'Property-based: various error types with SessionCreate stage produce consistent classification' {

        It 'Should classify "<ErrorMsg>" as <ExpectedCode>' -ForEach @(
            @{
                ErrorMsg = 'WinRM cannot complete the operation'
                ExpectedCode = 'WinRmEndpointUnreachable'
                ComputerName = 'SRV01'
            }
            @{
                ErrorMsg = 'Access is denied'
                ExpectedCode = 'AuthenticationFailed'
                ComputerName = 'SRV02'
            }
            @{
                ErrorMsg = 'The host name could not be resolved via DNS'
                ExpectedCode = 'DnsNameNotResolved'
                ComputerName = 'SRV03'
            }
            @{
                ErrorMsg = 'Connection timed out waiting for remote host'
                ExpectedCode = 'TcpUnreachable'
                ComputerName = 'SRV04'
            }
            @{
                ErrorMsg = 'The connection was actively refused by the target machine'
                ExpectedCode = 'TcpConnectionRefused'
                ComputerName = 'SRV05'
            }
            @{
                ErrorMsg = 'The network path was not found'
                ExpectedCode = 'TcpUnreachable'
                ComputerName = 'SRV06'
            }
            @{
                ErrorMsg = 'SSL certificate validation failed for remote host'
                ExpectedCode = 'TlsCertificateMismatch'
                ComputerName = 'SRV07'
            }
            @{
                ErrorMsg = 'Logon failure: unknown user name or bad password'
                ExpectedCode = 'AuthenticationFailed'
                ComputerName = 'SRV08'
            }
            @{
                ErrorMsg = 'Some completely unknown error that does not match any pattern'
                ExpectedCode = 'UnknownRemotingFailure'
                ComputerName = 'SRV09'
            }
        ) {
            $ex = [System.Exception]::new($ErrorMsg)
            $er = [System.Management.Automation.ErrorRecord]::new(
                $ex, 'TestError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null
            )

            $result = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage SessionCreate -ComputerName $ComputerName

            # Must return all three properties
            $result.PSObject.Properties.Name | Should -Contain 'FailureReasonCode'
            $result.PSObject.Properties.Name | Should -Contain 'FailureReasonSummary'
            $result.PSObject.Properties.Name | Should -Contain 'TechnicalDetail'

            # Classification must match expected code
            $result.FailureReasonCode | Should -BeExactly $ExpectedCode

            # Summary must mention the target computer
            $result.FailureReasonSummary | Should -Match ([regex]::Escape($ComputerName))

            # TechnicalDetail must contain the original error message
            $result.TechnicalDetail | Should -Match ([regex]::Escape($ErrorMsg))
        }

        It 'Should return UnknownRemotingFailure with null ErrorRecord' {
            $result = Resolve-RemoteGatheringFailure -ErrorRecord $null -Stage SessionCreate -ComputerName 'NULLTEST'

            $result.FailureReasonCode | Should -BeExactly 'UnknownRemotingFailure'
            $result.FailureReasonSummary | Should -Not -BeNullOrEmpty
            $result.TechnicalDetail | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Property-based: various stages produce stage-appropriate classification' {

        It 'Should classify generic error at stage <Stage> consistently' -ForEach @(
            @{ Stage = 'SessionCreate';    ExpectedCode = 'UnknownRemotingFailure' }
            @{ Stage = 'ConnectivityTest'; ExpectedCode = 'UnknownRemotingFailure' }
            @{ Stage = 'RemoteInvoke';     ExpectedCode = 'RemoteScriptFailed' }
            @{ Stage = 'Heal';             ExpectedCode = 'WinRmHealFailed' }
            @{ Stage = 'PayloadDecode';    ExpectedCode = 'PayloadOrSerializationFailed' }
            @{ Stage = 'SmbCollect';       ExpectedCode = 'FileCollectionFailed' }
            @{ Stage = 'ConfigCopy';       ExpectedCode = 'ConfigCopyFailed' }
            @{ Stage = 'FileCollection';   ExpectedCode = 'FileCollectionFailed' }
            @{ Stage = 'Orchestrator';     ExpectedCode = 'OrchestratorError' }
        ) {
            # Use a generic error message that won't match any specific pattern
            $ex = [System.Exception]::new('A generic unclassifiable error occurred in testing')
            $er = [System.Management.Automation.ErrorRecord]::new(
                $ex, 'GenericTestError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null
            )

            $result = Resolve-RemoteGatheringFailure -ErrorRecord $er -Stage $Stage -ComputerName 'STAGETEST'

            $result.FailureReasonCode | Should -BeExactly $ExpectedCode
            $result.PSObject.Properties.Name | Should -Contain 'FailureReasonSummary'
            $result.PSObject.Properties.Name | Should -Contain 'TechnicalDetail'
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 4. Merge-ScanRowsWithAllTargets placeholder preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Merge-ScanRowsWithAllTargets placeholder rows' {
    <#
        **Validates: Requirements 3.2**
        Missing hosts must get a placeholder row with:
          Outcome = 'No result recorded (orchestrator did not capture this host)'
        and all other fields set to null/$false.
    #>

    $placeholderOutcome = 'No result recorded (orchestrator did not capture this host)'

    Context 'Property-based: various server lists with missing hosts produce correct placeholders' {

        It 'Should fill all missing hosts with placeholder rows for <Description>' -ForEach @(
            @{
                Description = 'all hosts missing (empty results)'
                Servers = @('SRV01', 'SRV02', 'SRV03')
                ReturnedRows = @()
                ExpectedPlaceholderCount = 3
            }
            @{
                Description = 'one host returned, two missing'
                Servers = @('SRV01', 'SRV02', 'SRV03')
                ReturnedRows = @(
                    [pscustomobject]@{ ServerListEntry = 'SRV02'; Outcome = 'Fully successful'; ResolvedComputerName = 'SRV02'; ConnectionErrorCategory = $null; FailureReasonCode = $null; FailureReasonSummary = $null; TechnicalDetail = $null; JsonFileName = 'SRV02.json'; PowerShellVersion = '5.1'; CompatibilityMode = $null; UnavailableSectionsSummary = $null; ConfigFileIssue = $false; DetailMessage = $null }
                )
                ExpectedPlaceholderCount = 2
            }
            @{
                Description = 'all hosts returned (no placeholders needed)'
                Servers = @('SRV01', 'SRV02')
                ReturnedRows = @(
                    [pscustomobject]@{ ServerListEntry = 'SRV01'; Outcome = 'Fully successful'; ResolvedComputerName = 'SRV01'; ConnectionErrorCategory = $null; FailureReasonCode = $null; FailureReasonSummary = $null; TechnicalDetail = $null; JsonFileName = 'SRV01.json'; PowerShellVersion = '5.1'; CompatibilityMode = $null; UnavailableSectionsSummary = $null; ConfigFileIssue = $false; DetailMessage = $null }
                    [pscustomobject]@{ ServerListEntry = 'SRV02'; Outcome = 'Could not connect'; ResolvedComputerName = $null; ConnectionErrorCategory = 'TcpUnreachable'; FailureReasonCode = 'TcpUnreachable'; FailureReasonSummary = 'Timeout'; TechnicalDetail = 'Detail'; JsonFileName = $null; PowerShellVersion = $null; CompatibilityMode = $null; UnavailableSectionsSummary = $null; ConfigFileIssue = $false; DetailMessage = 'Detail' }
                )
                ExpectedPlaceholderCount = 0
            }
            @{
                Description = 'single server missing'
                Servers = @('LONELY')
                ReturnedRows = @()
                ExpectedPlaceholderCount = 1
            }
            @{
                Description = 'five servers, three missing'
                Servers = @('A', 'B', 'C', 'D', 'E')
                ReturnedRows = @(
                    [pscustomobject]@{ ServerListEntry = 'B'; Outcome = 'OK'; ResolvedComputerName = 'B'; ConnectionErrorCategory = $null; FailureReasonCode = $null; FailureReasonSummary = $null; TechnicalDetail = $null; JsonFileName = 'B.json'; PowerShellVersion = '7.4'; CompatibilityMode = $null; UnavailableSectionsSummary = $null; ConfigFileIssue = $false; DetailMessage = $null }
                    [pscustomobject]@{ ServerListEntry = 'D'; Outcome = 'OK'; ResolvedComputerName = 'D'; ConnectionErrorCategory = $null; FailureReasonCode = $null; FailureReasonSummary = $null; TechnicalDetail = $null; JsonFileName = 'D.json'; PowerShellVersion = '7.4'; CompatibilityMode = $null; UnavailableSectionsSummary = $null; ConfigFileIssue = $false; DetailMessage = $null }
                )
                ExpectedPlaceholderCount = 3
            }
        ) {
            $merged = Merge-ScanRowsWithAllTargets -ServersInOrder $Servers -ReturnedRows $ReturnedRows

            # Total rows must equal total servers
            @($merged).Count | Should -Be $Servers.Count

            # Order must match input server order
            for ($i = 0; $i -lt $Servers.Count; $i++) {
                $merged[$i].ServerListEntry | Should -BeExactly $Servers[$i]
            }

            # Count placeholder rows
            $placeholders = @($merged | Where-Object { $_.Outcome -eq $placeholderOutcome })
            $placeholders.Count | Should -Be $ExpectedPlaceholderCount

            # Verify placeholder row structure
            foreach ($ph in $placeholders) {
                $ph.ResolvedComputerName | Should -BeNullOrEmpty
                $ph.ConnectionErrorCategory | Should -BeNullOrEmpty
                $ph.FailureReasonCode | Should -BeNullOrEmpty
                $ph.FailureReasonSummary | Should -BeNullOrEmpty
                $ph.TechnicalDetail | Should -BeNullOrEmpty
                $ph.JsonFileName | Should -BeNullOrEmpty
                $ph.ConfigFileIssue | Should -BeFalse
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 5. Build-ScanRowFromDiscoveryJsonPath parsing preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Build-ScanRowFromDiscoveryJsonPath scan row parsing' {
    <#
        **Validates: Requirements 3.2**
        Build-ScanRowFromDiscoveryJsonPath must parse discovery JSON metadata
        and produce scan rows with correct fields.
    #>

    $scanRowFields = @(
        'ServerListEntry', 'ResolvedComputerName', 'Outcome',
        'ConnectionErrorCategory', 'FailureReasonCode', 'FailureReasonSummary',
        'TechnicalDetail', 'JsonFileName', 'PowerShellVersion',
        'CompatibilityMode', 'UnavailableSectionsSummary', 'ConfigFileIssue',
        'DetailMessage'
    )

    Context 'Property-based: various discovery JSON files produce correct scan rows' {

        It 'Should parse <Description> correctly' -ForEach @(
            @{
                Description = 'fully successful discovery with metadata'
                JsonContent = @{
                    Metadata = @{
                        ComputerName = 'SRV01'
                        PowerShellVersion = '5.1.19041.4291'
                        CompatibilityMode = $null
                        UnavailableSections = @()
                    }
                    Data = @{ SomeSection = 'value' }
                } | ConvertTo-Json -Depth 5
                ListEntry = 'SRV01'
                JsonFileName = 'SRV01_01-15-2025.json'
                ExpectedOutcome = 'Fully successful'
                ExpectedComputer = 'SRV01'
            }
            @{
                Description = 'legacy compatibility mode discovery'
                JsonContent = @{
                    Metadata = @{
                        ComputerName = 'OLDSRV'
                        PowerShellVersion = '3.0'
                        CompatibilityMode = 'Legacy3to4'
                        UnavailableSections = @('NetworkAdapters', 'Services')
                    }
                    Data = @{}
                } | ConvertTo-Json -Depth 5
                ListEntry = 'OLDSRV'
                JsonFileName = 'OLDSRV_01-15-2025.json'
                ExpectedOutcome = 'Partial success (PowerShell 3/4 — limited sections)'
                ExpectedComputer = 'OLDSRV'
            }
            @{
                Description = 'discovery with unavailable sections'
                JsonContent = @{
                    Metadata = @{
                        ComputerName = 'PARTSRV'
                        PowerShellVersion = '5.1'
                        CompatibilityMode = $null
                        UnavailableSections = @('Printers', 'BitLocker')
                    }
                    Data = @{}
                } | ConvertTo-Json -Depth 5
                ListEntry = 'PARTSRV'
                JsonFileName = 'PARTSRV_01-15-2025.json'
                ExpectedOutcome = 'Partial success (some sections not collected)'
                ExpectedComputer = 'PARTSRV'
            }
            @{
                Description = 'discovery with no metadata'
                JsonContent = '{ "Data": { "SomeSection": "value" } }'
                ListEntry = 'NOMETA'
                JsonFileName = 'NOMETA_01-15-2025.json'
                ExpectedOutcome = 'Fully successful'
                ExpectedComputer = $null
            }
        ) {
            $jsonDir = Join-Path $script:TestTempDir "json_$(New-Guid)"
            New-Item -Path $jsonDir -ItemType Directory -Force | Out-Null
            $jsonPath = Join-Path $jsonDir $JsonFileName
            $JsonContent | Set-Content -Path $jsonPath -Encoding UTF8

            $row = Build-ScanRowFromDiscoveryJsonPath -JsonPath $jsonPath -ListEntry $ListEntry -JsonFileName $JsonFileName

            # Must have all expected fields
            foreach ($field in $scanRowFields) {
                $row.PSObject.Properties.Name | Should -Contain $field -Because "Scan row must contain field '$field'"
            }

            $row.ServerListEntry | Should -BeExactly $ListEntry
            $row.JsonFileName | Should -BeExactly $JsonFileName
            $row.Outcome | Should -BeExactly $ExpectedOutcome

            if ($ExpectedComputer) {
                $row.ResolvedComputerName | Should -BeExactly $ExpectedComputer
            }
        }

        It 'Should handle missing JSON file gracefully' {
            $missingPath = Join-Path $script:TestTempDir 'nonexistent.json'
            $row = Build-ScanRowFromDiscoveryJsonPath -JsonPath $missingPath -ListEntry 'MISSING' -JsonFileName 'nonexistent.json'

            $row.ServerListEntry | Should -BeExactly 'MISSING'
            $row.Outcome | Should -BeExactly 'JSON file missing after reported success'
            $row.JsonFileName | Should -BeExactly 'nonexistent.json'
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 6. Config and remote staging path preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: Config file and remote script staging paths' {
    <#
        **Validates: Requirements 3.4, 3.5**
        Config file staging path must be C:\temp\MigrationDiscovery\config.json
        Remote script staging path must be C:\temp\MigrationDiscovery\run\
    #>

    It 'Should define config staging path as C:\temp\MigrationDiscovery\config.json' {
        # The PS7 script sets $remoteConfigPath = "C:\temp\MigrationDiscovery\config.json"
        $script:PS7ScriptContent | Should -Match 'C:\\temp\\MigrationDiscovery\\config\.json'
    }

    It 'Should define remote run directory as C:\temp\MigrationDiscovery\run' {
        # The PS7 script sets $remoteRunDir = "C:\temp\MigrationDiscovery\run"
        $script:PS7ScriptContent | Should -Match 'C:\\temp\\MigrationDiscovery\\run'
    }

    It 'Should stage config file inside the remote scriptblock at the parent of RemoteRunDir' {
        # Inside $remoteDiscoveryScriptBlock, config is written to:
        #   $configPath = Join-Path (Split-Path -Parent $RemoteRunDir) 'config.json'
        # This resolves to C:\temp\MigrationDiscovery\config.json
        $scriptBlockPattern = '(?s)\$remoteDiscoveryScriptBlock\s*=\s*\{(.+?)\n\}'
        $sbMatch = [regex]::Match($script:PS7ScriptContent, $scriptBlockPattern)
        $sbMatch.Success | Should -BeTrue

        $sbContent = $sbMatch.Groups[1].Value
        $sbContent | Should -Match 'config\.json'
    }

    It 'Should stage scripts to RemoteRunDir inside the remote scriptblock' {
        $scriptBlockPattern = '(?s)\$remoteDiscoveryScriptBlock\s*=\s*\{(.+?)\n\}'
        $sbMatch = [regex]::Match($script:PS7ScriptContent, $scriptBlockPattern)
        $sbMatch.Success | Should -BeTrue

        $sbContent = $sbMatch.Groups[1].Value
        # Scripts are written to $RemoteRunDir
        $sbContent | Should -Match 'Get-WorkstationDiscovery\.ps1'
        $sbContent | Should -Match 'DomainMigrationDiscovery\.Helpers\.psm1'
    }
}

# ═══════════════════════════════════════════════════════════════════════
# 7. Summary report format preservation
# ═══════════════════════════════════════════════════════════════════════
Describe 'Preservation: PS7-orchestrator-summary.txt report format' {
    <#
        **Validates: Requirements 3.6**
        Summary report must write to PS7-orchestrator-summary.txt with
        session/invoke/collect/success counts.
    #>

    It 'Should reference PS7-orchestrator-summary.txt filename in the script' {
        $script:PS7ScriptContent | Should -Match 'PS7-orchestrator-summary\.txt'
    }

    It 'Should include SessionCreate failed count in summary' {
        $script:PS7ScriptContent | Should -Match 'SessionCreate failed:'
    }

    It 'Should include Invoke failed count in summary' {
        $script:PS7ScriptContent | Should -Match 'Invoke failed:'
    }

    It 'Should include Collect failed count in summary' {
        $script:PS7ScriptContent | Should -Match 'Collect failed:'
    }

    It 'Should include Succeeded count in summary' {
        $script:PS7ScriptContent | Should -Match 'Succeeded:'
    }

    It 'Should include PS7 Orchestrator Summary header' {
        $script:PS7ScriptContent | Should -Match 'PS7 Orchestrator Summary'
    }

    It 'Should include ServerListPath in summary' {
        $script:PS7ScriptContent | Should -Match 'ServerListPath:'
    }

    It 'Should include ThrottleLimit in summary' {
        $script:PS7ScriptContent | Should -Match 'ThrottleLimit:'
    }

    It 'Should include Total servers count in summary' {
        $script:PS7ScriptContent | Should -Match 'Total servers:'
    }
}
