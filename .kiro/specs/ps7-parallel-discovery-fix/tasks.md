# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** — PS7 Session Creation in Parallel Runspaces and Hashtable Deserialization
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the two root causes: (1) sessions created in `ForEach-Object -Parallel` are unusable in the main runspace, and (2) hashtable passed via `-ArgumentList` is deserialized into a non-splattable type
  - **Scoped PBT Approach**: Scope the property to the concrete failing patterns in `Invoke-MigrationDiscoveryRemotely.PS7.ps1`
  - Create a Pester test file at `domain-discovery/tests/PS7ParallelDiscoveryFix.BugCondition.Tests.ps1`
  - Test 1 — Session creation method: Parse or mock the PS7 script to verify that `New-PSSession` is called via bulk `New-PSSession -ComputerName $servers` in the main runspace, NOT inside `ForEach-Object -Parallel`. On unfixed code, the script uses `ForEach-Object -Parallel` so this assertion will FAIL.
  - Test 2 — Hashtable splatting: Verify that the remote scriptblock receives a real `[hashtable]` (not `Deserialized.System.Collections.Hashtable`) that can be splatted with `@ScriptParams`. On unfixed code, the hashtable is passed directly via `-ArgumentList` so this assertion will FAIL.
  - Test 3 — End-to-end mock: Mock `New-PSSession` and `Invoke-Command` to simulate a single reachable server. Assert that `Invoke-Command` is called with `-Session` containing valid sessions and that the remote scriptblock produces a discovery result object. On unfixed code, sessions from parallel runspaces are invalid so this will FAIL.
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests FAIL (this is correct — it proves the bug exists)
  - Document counterexamples found to understand root cause
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** — Output Format, Error Handling, and Downstream Behavior Identical to PS5.1
  - **IMPORTANT**: Follow observation-first methodology
  - Create a Pester test file at `domain-discovery/tests/PS7ParallelDiscoveryFix.Preservation.Tests.ps1`
  - Observe on UNFIXED code: `Write-ErrorLog` produces `[timestamp] [ServerName] [ErrorType] ErrorMessage` format — verify this format is preserved
  - Observe on UNFIXED code: `Write-DiscoveryScanResultsFile` produces JSON with `Schema = 'DomainMigrationDiscovery.ScanResults/v1'`, `Orchestrator`, `GeneratedAtUtc`, `ServerListPath`, `PlantId`, and `Hosts` array with per-host fields (`ServerListEntry`, `ResolvedComputerName`, `Outcome`, `ConnectionErrorCategory`, `FailureReasonCode`, `FailureReasonSummary`, `TechnicalDetail`, `JsonFileName`, `PowerShellVersion`, `CompatibilityMode`, `UnavailableSectionsSummary`, `ConfigFileIssue`, `DetailMessage`) — verify schema is preserved
  - Observe on UNFIXED code: `Resolve-RemoteGatheringFailure` with `-Stage SessionCreate` classifies errors identically — verify classification is preserved
  - Observe on UNFIXED code: `Merge-ScanRowsWithAllTargets` fills missing hosts with "No result recorded" placeholder rows — verify this behavior is preserved
  - Observe on UNFIXED code: `Build-ScanRowFromDiscoveryJsonPath` parses discovery JSON metadata and produces scan rows — verify this behavior is preserved
  - Observe on UNFIXED code: Config file staging path is `C:\temp\MigrationDiscovery\config.json` — verify this is preserved
  - Observe on UNFIXED code: Remote script staging path is `C:\temp\MigrationDiscovery\run\` — verify this is preserved
  - Observe on UNFIXED code: Summary report writes to `PS7-orchestrator-summary.txt` with session/invoke/collect/success counts — verify format is preserved
  - Write property-based tests: for various combinations of server lists (empty results, mixed success/failure), verify that `Write-DiscoveryScanResultsFile`, `Write-ErrorLog`, `Merge-ScanRowsWithAllTargets`, and `Build-ScanRowFromDiscoveryJsonPath` produce identical output structure
  - Write property-based tests: for various error records, verify `Resolve-RemoteGatheringFailure` produces consistent classification
  - Verify all tests PASS on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 3. Fix for PS7 parallel discovery — session creation in parallel runspaces and hashtable deserialization

  - [x] 3.1 Replace `ForEach-Object -Parallel` session creation with bulk `New-PSSession`
    - Remove `$sessionErrors = [hashtable]::Synchronized(@{})` and `$sessionPairList = [System.Collections.ArrayList]::Synchronized(...)` synchronized collections
    - Remove the entire `$servers | ForEach-Object -Parallel { ... } -ThrottleLimit $ThrottleLimit` block that creates sessions in child runspaces
    - Replace with bulk `New-PSSession -ComputerName $servers -SessionOption $sessionOption -ErrorAction SilentlyContinue -ErrorVariable sessionCreateErrors`
    - Add credential parameter: `if ($Credential) { $sessionParams['Credential'] = $Credential }`
    - Derive connected computers from sessions: `$connectedComputers = @($sessions | ForEach-Object { $_.ComputerName })`
    - _Bug_Condition: isBugCondition(input) where input.sessionCreationMethod == 'ForEach-Object -Parallel'_
    - _Expected_Behavior: Sessions created in main runspace via bulk New-PSSession, valid for Invoke-Command -Session_
    - _Preservation: Session error logging format and Resolve-RemoteGatheringFailure classification unchanged_
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.2 Replace session error processing to use `-ErrorVariable` records
    - Remove the `foreach ($t in $sessionErrors.Keys)` block that iterates the synchronized hashtable
    - Replace with iteration over `$sessionCreateErrors` ErrorRecords
    - Extract target computer name from each ErrorRecord (e.g., `$errorRecord.TargetObject` or parse from message)
    - Feed each error to `Resolve-RemoteGatheringFailure -ErrorRecord $err -Stage SessionCreate -ComputerName $targetName`
    - Add to `$script:SessionCreateFailed` and `$script:SessionCreateErrorByServer` as before
    - Call `Write-ErrorLog` with same format as before
    - _Bug_Condition: isBugCondition(input) where synchronized hashtable error tracking is removed_
    - _Expected_Behavior: Session errors correctly mapped to server names and classified_
    - _Preservation: Error log entries and scan_results.json rows for failed sessions identical to PS5.1_
    - _Requirements: 2.1, 3.1, 3.2_

  - [x] 3.3 Reconstruct hashtable inside remote scriptblock
    - Change the remote scriptblock `$remoteDiscoveryScriptBlock` parameter list: replace `[hashtable]$ScriptParams` with individual parameters for each scriptParams key (`$ParamOutputRoot`, `$ParamLogRoot`, `$ParamOldDomainFqdn`, `$ParamNewDomainFqdn`, `$ParamOldDomainNetBIOS`, `$ParamPlantId`, `$ParamEmitStdOut`, `$ParamExcludeConfigFiles`, `$ParamLogTimeMetrics`, `$ParamNoDiscoveryTimeouts`, `$ParamDiscoveryTimeoutSeconds`, `$ParamConfigFile`)
    - Inside the scriptblock, reconstruct a real `[hashtable]` from the individual parameters before splatting
    - Conditionally add optional parameters (e.g., `if ($ParamOldDomainNetBIOS) { $ScriptParams['OldDomainNetBIOS'] = $ParamOldDomainNetBIOS }`)
    - Keep the `& ".\Get-WorkstationDiscovery.ps1" @ScriptParams` splatting call unchanged
    - _Bug_Condition: isBugCondition(input) where input.scriptParamsPassingMethod == 'ArgumentList' with hashtable_
    - _Expected_Behavior: Remote scriptblock receives individual values and reconstructs a real [hashtable] for splatting_
    - _Preservation: Get-WorkstationDiscovery.ps1 receives identical parameter set as PS5.1 orchestrator_
    - _Requirements: 2.4, 2.5, 3.5_

  - [x] 3.4 Update `Invoke-Command -ArgumentList` to pass individual values
    - Update the `-ArgumentList` array in the `Invoke-Command` call to pass individual values matching the new parameter list order
    - Pass each `$scriptParams` value separately instead of the hashtable object
    - Keep `-Session $sessions -ThrottleLimit $ThrottleLimit` for parallel fan-out
    - Keep `-ErrorAction Continue` for resilience
    - _Bug_Condition: isBugCondition(input) where hashtable is passed as single ArgumentList element_
    - _Expected_Behavior: Individual values arrive as native types on remote side, reconstructed into real hashtable_
    - _Preservation: Invoke-Command fan-out behavior and ThrottleLimit unchanged_
    - _Requirements: 2.3, 2.4, 2.5_

  - [x] 3.5 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** — Sessions in Main Runspace and Hashtable Reconstructed
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms: sessions are created in main runspace, hashtable is reconstructed as real `[hashtable]`, and `Invoke-Command -Session` produces discovery results
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 3.6 Verify preservation tests still pass
    - **Property 2: Preservation** — Output Format and Error Handling Identical to PS5.1
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Checkpoint — Ensure all tests pass
  - Run all Pester tests in `domain-discovery/tests/` to confirm both bug condition and preservation tests pass
  - Ensure no regressions in error logging, scan results schema, config staging, or summary report
  - Ask the user if questions arise
