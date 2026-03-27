# Bugfix Requirements Document

## Introduction

The PowerShell 7 orchestrator script (`Invoke-MigrationDiscoveryRemotely.PS7.ps1`) has never worked. It is intended to provide parallel remote discovery execution using PS7's native capabilities, producing identical output to the working PS5.1 orchestrator (`Invoke-MigrationDiscoveryRemotely.ps1`). Multiple fundamental bugs in the session creation and remote invocation phases prevent any successful discovery from completing. The user has a large server fleet requiring the parallel speedup that PS7 can provide.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN `ForEach-Object -Parallel` is used to create `New-PSSession` objects inside parallel runspaces THEN the system creates PSSession objects that are bound to the child runspace and cannot be used in the main runspace, making all subsequent `Invoke-Command -Session $sessions` calls fail or produce no results.

1.2 WHEN sessions created inside `ForEach-Object -Parallel` runspaces are added to a synchronized ArrayList via `$using:sessionPairList` THEN the system stores PSSession objects that are tied to now-disposed runspaces, rendering them invalid for any further remoting operations in the caller's scope.

1.3 WHEN `Invoke-Command -Session $sessions` is called in the main runspace with sessions originating from parallel runspaces THEN the system either throws errors or silently fails because PSSession objects are not transferable across runspace boundaries, resulting in zero discovery results for all hosts.

1.4 WHEN `Invoke-Command` passes `$scriptParams` (a hashtable) via `-ArgumentList` to the remote scriptblock, and the remote scriptblock attempts to splat it with `@ScriptParams` THEN the system may fail because the hashtable is deserialized into a `PSObject`/`Deserialized.System.Collections.Hashtable` on the remote side, which cannot be splatted.

1.5 WHEN the PS7 script runs against any number of servers THEN the system produces zero successful discovery results because the session creation architecture is fundamentally incompatible with PowerShell's runspace isolation model, leaving all hosts in a "no result" or error state in `scan_results.json`.

### Expected Behavior (Correct)

2.1 WHEN sessions need to be created for multiple servers THEN the system SHALL create all `New-PSSession` objects in the main runspace (e.g., using `New-PSSession -ComputerName $servers` in bulk or a sequential loop), so that sessions remain valid and usable for subsequent `Invoke-Command` calls.

2.2 WHEN sessions are created in the main runspace THEN the system SHALL store them in a standard collection accessible to `Invoke-Command`, without requiring synchronized collections or `$using:` scope transfer across runspace boundaries.

2.3 WHEN `Invoke-Command` is called with the valid sessions THEN the system SHALL use `Invoke-Command -Session $sessions -ThrottleLimit $ThrottleLimit` for parallel fan-out execution, which is the correct PS7 pattern for parallel remoting that keeps sessions in the originating runspace.

2.4 WHEN `Invoke-Command` passes `$scriptParams` to the remote scriptblock THEN the system SHALL ensure the hashtable arrives as a splatting-compatible type on the remote side, either by reconstructing it within the remote scriptblock or by passing individual key-value pairs as separate arguments.

2.5 WHEN the PS7 script runs against reachable servers THEN the system SHALL produce discovery JSON results, error logs, and `scan_results.json` output that is identical in schema and content to what the PS5.1 orchestrator produces for the same set of servers.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a server in the server list is unreachable or WinRM fails THEN the system SHALL CONTINUE TO log the failure to `error.log` with the same format and error classification (using `Resolve-RemoteGatheringFailure`) as the PS5.1 orchestrator.

3.2 WHEN discovery completes (with any mix of successes and failures) THEN the system SHALL CONTINUE TO produce a `scan_results.json` file in the same schema (`DomainMigrationDiscovery.ScanResults/v1`) with per-host outcome rows matching the PS5.1 format.

3.3 WHEN `-UseSmbForResults` is specified THEN the system SHALL CONTINUE TO collect JSON files via SMB (CollectorShare or admin share) rather than WinRM payload return, using the same file naming convention (`{ComputerName}_{MM-dd-yyyy}.json`).

3.4 WHEN `-ConfigFile` is specified THEN the system SHALL CONTINUE TO copy the configuration file to each remote server at `C:\temp\MigrationDiscovery\config.json` before running discovery.

3.5 WHEN discovery scripts and helper modules are staged on remote servers THEN the system SHALL CONTINUE TO write them to `C:\temp\MigrationDiscovery\run\` and execute `Get-WorkstationDiscovery.ps1` with the same parameter set as the PS5.1 orchestrator.

3.6 WHEN the script completes THEN the system SHALL CONTINUE TO produce the `PS7-orchestrator-summary.txt` report and display the same console summary format as the current PS7 script.

3.7 WHEN credentials are provided via `-Credential` THEN the system SHALL CONTINUE TO use them for all session creation and remote operations, and when no credentials are provided, SHALL CONTINUE TO prompt and fall back to current user context.
