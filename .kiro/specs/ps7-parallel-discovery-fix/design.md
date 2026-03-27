# PS7 Parallel Discovery Fix — Bugfix Design

## Overview

The PS7 orchestrator (`Invoke-MigrationDiscoveryRemotely.PS7.ps1`) cannot complete any discovery because it creates `New-PSSession` objects inside `ForEach-Object -Parallel` child runspaces, making them unusable in the main runspace, and passes a `$scriptParams` hashtable via `-ArgumentList` that gets deserialized into a non-splattable type on the remote side. The fix replaces the session-creation phase with bulk `New-PSSession -ComputerName $servers` in the main runspace, uses `Invoke-Command -Session $sessions -ThrottleLimit` for parallel fan-out, and reconstructs the hashtable inside the remote scriptblock. The result is a working PS7 orchestrator that produces output identical to the PS5.1 version.

## Glossary

- **Bug_Condition (C)**: The combination of (a) sessions created in `ForEach-Object -Parallel` child runspaces and (b) a hashtable passed via `-ArgumentList` that is deserialized — any invocation of the PS7 script triggers both conditions
- **Property (P)**: Discovery results are produced for all reachable servers, with JSON files, error logs, and `scan_results.json` matching the PS5.1 orchestrator output
- **Preservation**: Error logging format, `scan_results.json` schema, SMB collection, config file staging, credential handling, summary report, and console output must remain unchanged
- **`Invoke-MigrationDiscoveryRemotely.PS7.ps1`**: The PS7 orchestrator in `domain-discovery/` that fans out discovery to remote servers
- **`Invoke-MigrationDiscoveryRemotely.ps1`**: The working PS5.1 reference orchestrator (the "truth")
- **`$remoteDiscoveryScriptBlock`**: The scriptblock sent to each remote server that stages files and runs `Get-WorkstationDiscovery.ps1`
- **Runspace isolation**: PowerShell objects (including PSSessions) are bound to the runspace that created them and cannot cross runspace boundaries

## Bug Details

### Bug Condition

The bug manifests on every invocation of the PS7 orchestrator. The session-creation phase uses `ForEach-Object -Parallel` which spawns child runspaces; `New-PSSession` objects created there are bound to those child runspaces and become invalid once control returns to the main runspace. Additionally, the `$scriptParams` hashtable passed via `Invoke-Command -ArgumentList` is deserialized on the remote side into a `Deserialized.System.Collections.Hashtable` which cannot be splatted with `@ScriptParams`.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type PS7OrchestratorInvocation
  OUTPUT: boolean

  // Bug 1: Session creation in parallel runspaces
  sessionsCreatedInParallel := input.sessionCreationMethod == 'ForEach-Object -Parallel'
  
  // Bug 2: Hashtable deserialization via -ArgumentList
  hashtablePassedViaArgumentList := input.scriptParamsPassingMethod == 'ArgumentList'
  
  RETURN sessionsCreatedInParallel OR hashtablePassedViaArgumentList
END FUNCTION
```

### Examples

- **Any server list, any credentials**: Running `.\Invoke-MigrationDiscoveryRemotely.PS7.ps1 -ServerListPath .\servers.txt -OldDomainFqdn old.com -NewDomainFqdn new.com` produces zero discovery JSON files and all hosts show "No result recorded" or errors in `scan_results.json`. Expected: discovery JSON for each reachable server.
- **Single server**: Even with one server in the list, the session created in the parallel runspace is invalid in the main runspace, so `Invoke-Command -Session $sessions` silently produces nothing. Expected: one discovery JSON file.
- **Hashtable splatting**: The remote scriptblock receives `$ScriptParams` as a `Deserialized.System.Collections.Hashtable`. The line `& ".\Get-WorkstationDiscovery.ps1" @ScriptParams` fails or passes incorrect parameters. Expected: the hashtable is a real `[hashtable]` that can be splatted.
- **Session error tracking**: When `New-PSSession` fails inside `ForEach-Object -Parallel`, the error is captured in `$using:sessionErrors` but the session object itself is the wrong type — even "successful" sessions are unusable. Expected: failed sessions are logged, successful sessions are usable.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Error logging to `error.log` with identical format and `Resolve-RemoteGatheringFailure` classification
- `scan_results.json` output with `DomainMigrationDiscovery.ScanResults/v1` schema and identical per-host row structure
- SMB collection path when `-UseSmbForResults` is set (CollectorShare or admin share, same file naming)
- Config file staging to `C:\temp\MigrationDiscovery\config.json` on each remote server
- Remote file staging to `C:\temp\MigrationDiscovery\run\` (script + helper module)
- `PS7-orchestrator-summary.txt` report generation
- Console output format (host list, per-host status, final summary)
- Credential prompting and fallback to current user context
- Discovery script parameter set passed to `Get-WorkstationDiscovery.ps1`
- gzip+base64 payload return and local JSON decompression (non-SMB mode)

**Scope:**
All inputs that do NOT involve the session creation mechanism or hashtable passing are completely unaffected by this fix. This includes:
- Server list parsing and deduplication
- Configuration file loading and domain parameter validation
- Helper module content reading
- Result collection, decompression, and local file writing
- Scan results building and summary report generation

## Hypothesized Root Cause

Based on the bug description and code analysis, the confirmed issues are:

1. **PSSession Runspace Isolation** (lines ~230-248 of PS7 script): `$servers | ForEach-Object -Parallel { ... $sess = New-PSSession @p ... }` creates sessions in child runspaces. When the parallel block completes, those runspaces are disposed. The sessions stored in `$using:sessionPairList` reference dead runspaces and cannot be used by `Invoke-Command -Session $sessions` in the main runspace. This is a fundamental PowerShell architecture constraint, not a timing issue.

2. **Hashtable Deserialization** (line ~270 of PS7 script): `Invoke-Command -Session $sessions -ScriptBlock $remoteDiscoveryScriptBlock -ArgumentList @(..., $scriptParams, ...)` serializes `$scriptParams` for transport. On the remote side, the `[hashtable]$ScriptParams` parameter declaration in the scriptblock receives a `Deserialized.System.Collections.Hashtable` which does not support splatting. The line `& ".\Get-WorkstationDiscovery.ps1" @ScriptParams` either throws or passes no parameters.

3. **Compounding Effect**: Bug 1 means no sessions are usable, so `Invoke-Command` produces zero results. Even if sessions worked, Bug 2 would cause the remote discovery to fail or run with wrong parameters. The combination guarantees zero successful discoveries.

## Correctness Properties

Property 1: Bug Condition — Sessions Created in Main Runspace and Hashtable Reconstructed

_For any_ invocation of the fixed PS7 orchestrator with a non-empty server list containing at least one reachable server, the fixed script SHALL create PSSessions in the main runspace (not inside `ForEach-Object -Parallel`), use `Invoke-Command -Session` for parallel fan-out, and reconstruct the `$scriptParams` hashtable inside the remote scriptblock so that `Get-WorkstationDiscovery.ps1` receives correct parameters and produces discovery JSON output.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

Property 2: Preservation — Output Format and Error Handling Identical to PS5.1

_For any_ invocation of the fixed PS7 orchestrator (whether servers are reachable or not), the fixed script SHALL produce `scan_results.json`, `error.log`, and `PS7-orchestrator-summary.txt` with identical schema, format, and content structure as the unfixed script would produce for the same failure scenarios, and identical to the PS5.1 orchestrator for success scenarios, preserving all error classification, file naming, and collection behaviors.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `domain-discovery/Invoke-MigrationDiscoveryRemotely.PS7.ps1`

**Specific Changes**:

1. **Replace `ForEach-Object -Parallel` session creation with bulk `New-PSSession`**: Remove the entire `$servers | ForEach-Object -Parallel { ... } -ThrottleLimit $ThrottleLimit` block (lines ~230-248). Replace with:
   ```powershell
   $sessionParams = @{
       ComputerName  = $servers
       SessionOption = $sessionOption
       ErrorAction   = 'SilentlyContinue'
       ErrorVariable = 'sessionCreateErrors'
   }
   if ($Credential) { $sessionParams['Credential'] = $Credential }
   $sessions = @(New-PSSession @sessionParams)
   ```
   This creates all sessions in the main runspace in one call. `-ErrorAction SilentlyContinue` with `-ErrorVariable` captures per-host failures without aborting.

2. **Remove synchronized collections for session tracking**: Remove `$sessionErrors = [hashtable]::Synchronized(@{})` and `$sessionPairList = [System.Collections.ArrayList]::Synchronized(...)`. These are no longer needed since session creation is in the main runspace.

3. **Process session creation errors from `-ErrorVariable`**: Replace the `foreach ($t in $sessionErrors.Keys)` block with iteration over `$sessionCreateErrors`, extracting the target computer name from each `ErrorRecord` and feeding it to `Resolve-RemoteGatheringFailure` with `-Stage SessionCreate`.

4. **Derive `$connectedComputers` from successful sessions**: Use `$connectedComputers = @($sessions | ForEach-Object { $_.ComputerName })` instead of extracting from the synchronized pair list.

5. **Reconstruct hashtable inside remote scriptblock**: Change the remote scriptblock parameter from `[hashtable]$ScriptParams` to individual string/bool parameters for each key-value pair, then reconstruct a real `[hashtable]` inside the scriptblock before splatting. Alternatively, pass the hashtable keys and values as two arrays and rebuild. The simplest approach: pass individual named parameters and build the hashtable on the remote side:
   ```powershell
   # Inside the remote scriptblock, replace the $ScriptParams parameter with individual params:
   param(
       [string]$HelperModuleContent,
       [string]$RemoteRunDir,
       [string]$ScriptContent,
       [string]$ParamOutputRoot,
       [string]$ParamLogRoot,
       [string]$ParamOldDomainFqdn,
       [string]$ParamNewDomainFqdn,
       [string]$ParamOldDomainNetBIOS,
       [string]$ParamPlantId,
       [bool]$ParamEmitStdOut,
       [bool]$ParamExcludeConfigFiles,
       [bool]$ParamLogTimeMetrics,
       [bool]$ParamNoDiscoveryTimeouts,
       [int]$ParamDiscoveryTimeoutSeconds,
       [string]$ParamConfigFile,
       [string]$RemoteOutputRoot,
       [string]$RemoteLogRoot,
       [string]$ConfigContent,
       [bool]$UseSmbForResults
   )
   # Reconstruct hashtable
   $ScriptParams = @{
       OutputRoot    = $ParamOutputRoot
       LogRoot       = $ParamLogRoot
       OldDomainFqdn = $ParamOldDomainFqdn
       NewDomainFqdn = $ParamNewDomainFqdn
   }
   if ($ParamOldDomainNetBIOS) { $ScriptParams['OldDomainNetBIOS'] = $ParamOldDomainNetBIOS }
   # ... etc for each optional param
   ```

6. **Update `Invoke-Command` call**: Change from `-ArgumentList @(...)` with the hashtable to passing the individual values in the correct order matching the new parameter list. Keep `-Session $sessions -ThrottleLimit $ThrottleLimit`.

7. **Keep all downstream code unchanged**: The result collection, decompression, scan results building, summary report, and error logging phases remain identical — they only depend on the shape of `$allResults` which is unchanged (each remote scriptblock still returns the same `[pscustomobject]`).

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write Pester tests that exercise the session creation and remote invocation phases of the PS7 script. Use mocked `New-PSSession` and `Invoke-Command` to verify the calling patterns. Run these tests on the UNFIXED code to observe failures.

**Test Cases**:
1. **Session Runspace Binding Test**: Verify that sessions created inside `ForEach-Object -Parallel` are not usable in the main runspace (will fail on unfixed code — sessions are invalid)
2. **Hashtable Deserialization Test**: Verify that a hashtable passed via `-ArgumentList` to `Invoke-Command` arrives as a real `[hashtable]` on the remote side (will fail on unfixed code — arrives as `Deserialized.System.Collections.Hashtable`)
3. **End-to-End Zero Results Test**: Run the orchestrator against a mock server and verify discovery results are produced (will fail on unfixed code — zero results)
4. **Session Creation Method Test**: Verify that `New-PSSession` is NOT called inside `ForEach-Object -Parallel` (will fail on unfixed code — it is)

**Expected Counterexamples**:
- Sessions created in parallel runspaces throw or silently fail when used with `Invoke-Command -Session`
- `$ScriptParams` arrives as `Deserialized.System.Collections.Hashtable` and splatting fails
- Possible causes: runspace isolation (confirmed by PS7 architecture), serialization boundary on `-ArgumentList`

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := runPS7Orchestrator_fixed(input)
  ASSERT result.successfulDiscoveries > 0 FOR reachable servers
  ASSERT result.scanResultsJson.Schema == 'DomainMigrationDiscovery.ScanResults/v1'
  ASSERT result.sessionsCreatedInMainRunspace == true
  ASSERT result.remoteHashtableIsSplattable == true
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT runPS7Orchestrator_original(input) = runPS7Orchestrator_fixed(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for error handling, scan results format, and non-session-related code paths, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Error Log Format Preservation**: Observe that `Write-ErrorLog` produces identical format on unfixed code, then verify this continues after fix
2. **Scan Results Schema Preservation**: Observe that `Write-DiscoveryScanResultsFile` produces identical JSON schema on unfixed code, then verify this continues after fix
3. **Session Failure Classification Preservation**: Observe that unreachable servers produce the same `Resolve-RemoteGatheringFailure` output on unfixed code, then verify this continues after fix
4. **Config File Staging Preservation**: Observe that config file is staged to `C:\temp\MigrationDiscovery\config.json` on unfixed code, then verify this continues after fix

### Unit Tests

- Test that `New-PSSession` is called with `-ComputerName $servers` (bulk) in the main runspace, not inside `ForEach-Object -Parallel`
- Test that session creation errors are correctly mapped to server names and classified via `Resolve-RemoteGatheringFailure`
- Test that the remote scriptblock reconstructs a real `[hashtable]` from individual parameters and splats it correctly
- Test that `Invoke-Command` is called with `-Session` and `-ThrottleLimit` (not `-ComputerName` with `-Parallel`)
- Test edge cases: empty server list, all servers unreachable, single server, mixed success/failure

### Property-Based Tests

- Generate random server lists (varying length, with duplicates) and verify session creation produces one session per unique reachable server
- Generate random `$scriptParams` hashtable contents (varying optional parameters present/absent) and verify the reconstructed hashtable on the remote side matches the original
- Generate random mixes of reachable/unreachable servers and verify `scan_results.json` contains exactly one row per server with correct outcome classification

### Integration Tests

- Test full orchestrator flow with mocked remoting: session creation → invoke → collection → scan results → summary report
- Test `-UseSmbForResults` path produces identical collection behavior
- Test `-ConfigFile` path stages config before discovery on each server
- Test that `PS7-orchestrator-summary.txt` contains correct counts for each failure category
