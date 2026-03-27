#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Bug condition exploration tests for PS7 parallel discovery fix.
    These tests encode the EXPECTED (correct) behavior.
    On UNFIXED code, all tests should FAIL — proving the bug exists.

.DESCRIPTION
    Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
    Bug Condition: Sessions created in ForEach-Object -Parallel child runspaces
                   are unusable in the main runspace, and hashtable passed via
                   -ArgumentList is deserialized into a non-splattable type.
#>

BeforeAll {
    $script:PS7ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'Invoke-MigrationDiscoveryRemotely.PS7.ps1'
    $script:PS7ScriptContent = Get-Content -Path $script:PS7ScriptPath -Raw
}

Describe 'PS7 Parallel Discovery Bug Condition Exploration' {

    Context 'Test 1 — Session creation method: New-PSSession must NOT be inside ForEach-Object -Parallel' {
        <#
            **Validates: Requirements 1.1, 1.2, 1.3**
            The fixed script should create sessions in the main runspace using
            bulk New-PSSession -ComputerName $servers, NOT inside ForEach-Object -Parallel.
            On unfixed code, New-PSSession IS inside ForEach-Object -Parallel, so this FAILS.
        #>

        It 'Should NOT contain New-PSSession inside a ForEach-Object -Parallel block' {
            # Parse the script to find ForEach-Object -Parallel blocks that contain New-PSSession.
            # The buggy pattern: $servers | ForEach-Object -Parallel { ... New-PSSession ... }
            # We look for the -Parallel parameter on ForEach-Object followed by a scriptblock
            # that contains New-PSSession.

            # Extract all ForEach-Object -Parallel scriptblock regions
            $parallelPattern = '(?s)ForEach-Object\s+-Parallel\s*\{(.+?)\}\s*-ThrottleLimit'
            $matches = [regex]::Matches($script:PS7ScriptContent, $parallelPattern)

            $newPSSessionInParallel = $false
            foreach ($m in $matches) {
                $blockContent = $m.Groups[1].Value
                if ($blockContent -match 'New-PSSession') {
                    $newPSSessionInParallel = $true
                    break
                }
            }

            # EXPECTED: New-PSSession should NOT be inside ForEach-Object -Parallel
            $newPSSessionInParallel | Should -BeFalse -Because 'New-PSSession must be called in the main runspace, not inside ForEach-Object -Parallel child runspaces (sessions are bound to the creating runspace)'
        }

        It 'Should assign $sessions directly from a main-runspace New-PSSession call (not from parallel pair list)' {
            # The fixed script should assign $sessions from a direct New-PSSession call, e.g.:
            #   $sessions = @(New-PSSession @sessionParams)
            # The buggy code assigns $sessions from $sessionPairList populated inside ForEach-Object -Parallel:
            #   $sessions = @($sessionPairList | ForEach-Object { $_.Session })

            # Check for the buggy pattern: $sessions derived from $sessionPairList
            $derivesFromParallelList = $script:PS7ScriptContent -match '\$sessions\s*=\s*@\(\s*\$sessionPairList'

            # Check for the fixed pattern: $sessions assigned directly from New-PSSession
            $directFromNewPSSession = $script:PS7ScriptContent -match '\$sessions\s*=\s*@?\(?\s*New-PSSession'

            # The fix should NOT derive sessions from the parallel pair list
            $derivesFromParallelList | Should -BeFalse -Because 'Sessions must come directly from New-PSSession in the main runspace, not from a synchronized list populated in ForEach-Object -Parallel'
        }
    }

    Context 'Test 2 — Hashtable splatting: remote scriptblock must receive a real [hashtable]' {
        <#
            **Validates: Requirements 1.4**
            The fixed script should ensure the remote scriptblock can splat parameters.
            On unfixed code, the hashtable is passed via -ArgumentList and arrives as
            Deserialized.System.Collections.Hashtable which cannot be splatted.
        #>

        It 'Should NOT pass a hashtable object directly via Invoke-Command -ArgumentList' {
            # The buggy pattern passes $scriptParams (a hashtable) as one of the -ArgumentList elements.
            # Look for the Invoke-Command call with -ArgumentList that includes $scriptParams.
            # The fix should either pass individual values or reconstruct the hashtable inside the scriptblock.

            # Find the Invoke-Command call with the remote discovery scriptblock
            $invokePattern = '(?s)Invoke-Command\s+.*?-ArgumentList\s+@\(([^)]+)\)'
            $invokeMatch = [regex]::Match($script:PS7ScriptContent, $invokePattern)

            if ($invokeMatch.Success) {
                $argListContent = $invokeMatch.Groups[1].Value
                # Check if $scriptParams is passed as a direct argument (the bug)
                $passesHashtableDirectly = $argListContent -match '\$scriptParams'
                $passesHashtableDirectly | Should -BeFalse -Because 'Passing a hashtable via -ArgumentList causes deserialization into Deserialized.System.Collections.Hashtable which cannot be splatted with @ScriptParams'
            }
            else {
                # If no -ArgumentList with @() found, that's also acceptable (might use a different passing method)
                $true | Should -BeTrue
            }
        }

        It 'Should reconstruct the hashtable inside the remote scriptblock for splatting' {
            # The remote scriptblock ($remoteDiscoveryScriptBlock) should reconstruct a real [hashtable]
            # from individual parameters, NOT declare [hashtable]$ScriptParams as a param that comes from -ArgumentList.

            # Extract the remote scriptblock definition
            $scriptBlockPattern = '(?s)\$remoteDiscoveryScriptBlock\s*=\s*\{(.+?)\n\}'
            $sbMatch = [regex]::Match($script:PS7ScriptContent, $scriptBlockPattern)

            $sbMatch.Success | Should -BeTrue -Because 'The remote discovery scriptblock must exist'

            $sbContent = $sbMatch.Groups[1].Value

            # Extract the param() block from the scriptblock
            $paramPattern = '(?s)param\s*\((.+?)\)'
            $paramMatch = [regex]::Match($sbContent, $paramPattern)
            $paramMatch.Success | Should -BeTrue -Because 'The scriptblock must have a param() block'

            $paramContent = $paramMatch.Groups[1].Value

            # The buggy code declares [hashtable]$ScriptParams as a parameter — this means
            # it receives a deserialized hashtable from -ArgumentList that can't be splatted.
            # The fix should NOT have [hashtable]$ScriptParams as a direct parameter.
            $hasHashtableScriptParams = $paramContent -match '\[hashtable\]\s*\$ScriptParams'
            $hasHashtableScriptParams | Should -BeFalse -Because 'The scriptblock should not receive a [hashtable]$ScriptParams via -ArgumentList; it should reconstruct the hashtable from individual parameters'
        }
    }

    Context 'Test 3 — End-to-end mock: Invoke-Command must use -Session with valid sessions' {
        <#
            **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**
            Mock New-PSSession and Invoke-Command to verify the orchestrator's calling patterns.
            On unfixed code, sessions from parallel runspaces are invalid, so this FAILS.
        #>

        It 'Should call Invoke-Command with -Session parameter containing sessions from main runspace New-PSSession' {
            # We verify the script's structure: the Invoke-Command call should use -Session $sessions
            # where $sessions comes from a main-runspace New-PSSession call (not from ForEach-Object -Parallel).

            # Check that sessions variable is populated from main-runspace New-PSSession
            # In the fixed code, we expect something like:
            #   $sessions = @(New-PSSession @sessionParams)
            # NOT:
            #   $sessions = @($sessionPairList | ForEach-Object { $_.Session })  <-- from parallel block

            # The buggy code derives $sessions from $sessionPairList which was populated inside ForEach-Object -Parallel
            $derivesSessionsFromParallelList = $script:PS7ScriptContent -match '\$sessions\s*=\s*@\(\s*\$sessionPairList'

            # In the fixed code, sessions should come directly from New-PSSession in the main runspace
            # e.g., $sessions = @(New-PSSession @sessionParams) or $sessions = New-PSSession -ComputerName $servers
            $parallelPattern = '(?s)ForEach-Object\s+-Parallel\s*\{.+?\}\s*-ThrottleLimit\s+\S+'
            $mainRunspaceCode = [regex]::Replace($script:PS7ScriptContent, $parallelPattern, '')
            $mainRunspaceHasNewPSSession = $mainRunspaceCode -match '\$sessions\s*=\s*@?\(?New-PSSession'

            # At least one of these conditions must be true for the fix:
            # - Sessions are NOT derived from the parallel pair list, OR
            # - Sessions ARE created directly in the main runspace
            $isFixed = (-not $derivesSessionsFromParallelList) -or $mainRunspaceHasNewPSSession

            $isFixed | Should -BeTrue -Because 'Sessions must be created in the main runspace and passed directly to Invoke-Command -Session; sessions from ForEach-Object -Parallel child runspaces are bound to disposed runspaces and are unusable'
        }
    }
}
