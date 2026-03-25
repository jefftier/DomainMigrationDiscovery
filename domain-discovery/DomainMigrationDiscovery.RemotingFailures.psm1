<#
.SYNOPSIS
  Classifies WinRM/remoting/discovery failures into stable reason codes and human-readable summaries.
  Uses ErrorRecord type, FullyQualifiedErrorId, category, inner exceptions, then message patterns (last).
#>

function Build-RemotingTechnicalDetail {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [int]$MaxLength = 4000
    )
    if (-not $ErrorRecord) { return $null }
    $parts = [System.Collections.ArrayList]::new()
    $null = $parts.Add("Message: $($ErrorRecord.Exception.Message)")
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.GetType()) {
        $null = $parts.Add("Exception: $($ErrorRecord.Exception.GetType().FullName)")
    }
    if ($ErrorRecord.FullyQualifiedErrorId) {
        $null = $parts.Add("FullyQualifiedErrorId: $($ErrorRecord.FullyQualifiedErrorId)")
    }
    if ($ErrorRecord.CategoryInfo -and $ErrorRecord.CategoryInfo.Category) {
        $null = $parts.Add("Category: $($ErrorRecord.CategoryInfo.Category) Reason: $($ErrorRecord.CategoryInfo.Reason)")
    }
    $inner = $ErrorRecord.Exception
    $depth = 0
    while ($inner.InnerException -and $depth -lt 5) {
        $inner = $inner.InnerException
        $depth++
        $null = $parts.Add("Inner: $($inner.GetType().FullName): $($inner.Message)")
    }
    $s = $parts -join ' | '
    if ($s.Length -gt $MaxLength) {
        $take = [Math]::Max(0, $MaxLength - 3)
        return $s.Substring(0, $take) + '...'
    }
    return $s
}

function Test-WinRmHealCandidate {
    <#
    .SYNOPSIS
      Returns true if AttemptWinRmHeal may help (service/listener issues), false for auth/DNS/network-only.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FailureReasonCode
    )
    $candidates = @(
        'WinRmEndpointUnreachable'
        'UnknownRemotingFailure'
        'WinRmServiceNotRunning'
    )
    return $candidates -contains $FailureReasonCode
}

function Resolve-RemoteGatheringFailure {
    <#
    .SYNOPSIS
      Maps an ErrorRecord and pipeline stage to FailureReasonCode, FailureReasonSummary, TechnicalDetail.
    .PARAMETER Stage
      SessionCreate | ConnectivityTest | RemoteInvoke | Heal | SmbCollect | PayloadDecode | ConfigCopy | FileCollection | Orchestrator
    #>
    [CmdletBinding()]
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)]
        [ValidateSet(
            'SessionCreate', 'ConnectivityTest', 'RemoteInvoke', 'Heal', 'SmbCollect',
            'PayloadDecode', 'ConfigCopy', 'FileCollection', 'Orchestrator'
        )]
        [string]$Stage,
        [string]$ComputerName = ''
    )

    $technical = if ($ErrorRecord) { Build-RemotingTechnicalDetail -ErrorRecord $ErrorRecord } else { 'No error record was captured.' }

    if (-not $ErrorRecord) {
        return [pscustomobject]@{
            FailureReasonCode    = 'UnknownRemotingFailure'
            FailureReasonSummary = 'No error details were captured; see TechnicalDetail.'
            TechnicalDetail      = $technical
        }
    }

    $ex = $ErrorRecord.Exception
    $msg = if ($ex.Message) { $ex.Message } else { '' }
    $msgLower = $msg.ToLowerInvariant()
    $fq = if ($ErrorRecord.FullyQualifiedErrorId) { $ErrorRecord.FullyQualifiedErrorId } else { '' }
    $cat = if ($ErrorRecord.CategoryInfo.Category) { [string]$ErrorRecord.CategoryInfo.Category } else { '' }

    # --- Socket / network (strong signals) ---
    $socketEx = $null
    $walk = $ex
    $w = 0
    while ($walk -and $w -lt 8) {
        if ($walk -is [System.Net.Sockets.SocketException] -or $walk.PSObject.TypeNames -contains 'System.Net.Sockets.SocketException') {
            $socketEx = $walk
            break
        }
        $walk = $walk.InnerException
        $w++
    }
    if ($socketEx) {
        $code = [int]$socketEx.SocketErrorCode
        # Interop: 10061 connection refused, 10060 timeout, 11001 host not found, 10051 unreachable
        switch ($code) {
            { $_ -in @(10061, 10048) } {
                return [pscustomobject]@{
                    FailureReasonCode    = 'TcpConnectionRefused'
                    FailureReasonSummary = "TCP connection was refused (often nothing listening on the WinRM port or wrong target). Target: $ComputerName"
                    TechnicalDetail      = $technical
                }
            }
            { $_ -in @(10060, 10051) } {
                return [pscustomobject]@{
                    FailureReasonCode    = 'TcpUnreachable'
                    FailureReasonSummary = "Connection timed out or network unreachable (often firewall, offline host, or routing). Target: $ComputerName"
                    TechnicalDetail      = $technical
                }
            }
            { $_ -eq 11001 } {
                return [pscustomobject]@{
                    FailureReasonCode    = 'DnsNameNotResolved'
                    FailureReasonSummary = "Host name could not be resolved (DNS). Target: $ComputerName"
                    TechnicalDetail      = $technical
                }
            }
            default {
                return [pscustomobject]@{
                    FailureReasonCode    = 'TcpUnreachable'
                    FailureReasonSummary = "Network socket error ($($socketEx.SocketErrorCode)). Target: $ComputerName"
                    TechnicalDetail      = $technical
                }
            }
        }
    }

    # --- FQID / remoting transport ---
    if ($fq -match 'DNS|NameResolution|CouldNotResolve|NameNotFound' -or $msgLower -match 'name resolution|could not be resolved|getaddrinfo|no such host|known dns') {
        return [pscustomobject]@{
            FailureReasonCode    = 'DnsNameNotResolved'
            FailureReasonSummary = "Host name could not be resolved (DNS). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($fq -match 'AccessDenied|LogonFailure|Authentication|Authorization|InvalidCredentials') {
        return [pscustomobject]@{
            FailureReasonCode    = 'AuthenticationFailed'
            FailureReasonSummary = "Authentication failed (wrong account, expired password, or no logon rights). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($ErrorRecord.CategoryInfo.Category -eq 'AuthenticationError' -or $ErrorRecord.CategoryInfo.Category -eq 'SecurityError') {
        return [pscustomobject]@{
            FailureReasonCode    = 'AuthenticationFailed'
            FailureReasonSummary = "Authentication or security error. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # TLS / HTTPS
    if ($msgLower -match 'certificate|ssl|tls|remote certificate|trust relationship') {
        return [pscustomobject]@{
            FailureReasonCode    = 'TlsCertificateMismatch'
            FailureReasonSummary = "TLS/certificate problem (name mismatch, untrusted CA, or HTTPS listener). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Auth by message (narrower than legacy 'credential' substring)
    if ($msgLower -match 'access is denied' -or
        $msgLower -match '\b401\b' -or $msgLower -match '\b403\b' -or
        $msgLower -match 'logon failure|logon failed|unknown user name or bad password|invalid credentials' -or
        ($msgLower -match 'kerberos' -and $msgLower -match 'fail|error|invalid|wrong|ticket') -or
        ($msgLower -match 'ntlm' -and $msgLower -match 'fail|auth')) {
        return [pscustomobject]@{
            FailureReasonCode    = 'AuthenticationFailed'
            FailureReasonSummary = "Authentication or access denied when connecting. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Authorization (authenticated but not allowed)
    if ($msgLower -match 'authorized|not permitted|policy|restricted') {
        return [pscustomobject]@{
            FailureReasonCode    = 'AuthorizationFailed'
            FailureReasonSummary = "Connected but operation not permitted (policy or rights). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Connection refused / reset in text
    if ($msgLower -match 'actively refused|connection refused|forcibly closed') {
        return [pscustomobject]@{
            FailureReasonCode    = 'TcpConnectionRefused'
            FailureReasonSummary = "Connection refused (WinRM port may be closed or wrong address). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Timeouts / unreachable
    if ($msgLower -match 'timed out|timeout|network is unreachable|no route to host') {
        return [pscustomobject]@{
            FailureReasonCode    = 'TcpUnreachable'
            FailureReasonSummary = "Connection timed out or network unreachable (firewall, offline, or routing). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Classic network / path
    if ($msgLower -match 'the network path was not found|no connection could be made|rpc server is unavailable|host.*not found|cannot resolve') {
        return [pscustomobject]@{
            FailureReasonCode    = 'TcpUnreachable'
            FailureReasonSummary = "Network path or RPC unreachable (offline, firewall, or name resolution). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # WinRM generic (often listener/firewall/service)
    if ($ex -is [System.Management.Automation.Remoting.PSRemotingTransportException] -or
        $fq -match 'WinRM|RemotingTransport|WSMan|PSSessionOpenFailed') {
        return [pscustomobject]@{
            FailureReasonCode    = 'WinRmEndpointUnreachable'
            FailureReasonSummary = "WinRM transport failed (service/listener, firewall on 5985/5986, or TLS). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($msgLower -match 'winrm cannot complete the operation|ws-management|the client cannot process the request') {
        return [pscustomobject]@{
            FailureReasonCode    = 'WinRmEndpointUnreachable'
            FailureReasonSummary = "WinRM could not complete the operation (listener, firewall, or configuration). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($msgLower -match 'winrm service|ws-management service|service.*not running') {
        return [pscustomobject]@{
            FailureReasonCode    = 'WinRmServiceNotRunning'
            FailureReasonSummary = "WinRM service appears stopped or not accepting requests. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    # Stage-specific
    if ($Stage -eq 'Heal') {
        return [pscustomobject]@{
            FailureReasonCode    = 'WinRmHealFailed'
            FailureReasonSummary = "Attempt to start or verify the WinRM service failed. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'PayloadDecode') {
        return [pscustomobject]@{
            FailureReasonCode    = 'PayloadOrSerializationFailed'
            FailureReasonSummary = "Failed to decode or deserialize the discovery payload (gzip/base64). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'SmbCollect' -or $Stage -eq 'FileCollection') {
        return [pscustomobject]@{
            FailureReasonCode    = 'FileCollectionFailed'
            FailureReasonSummary = "Failed to collect result files (SMB/share/copy). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'ConfigCopy') {
        return [pscustomobject]@{
            FailureReasonCode    = 'ConfigCopyFailed'
            FailureReasonSummary = "Failed to copy configuration to the target. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'RemoteInvoke') {
        return [pscustomobject]@{
            FailureReasonCode    = 'RemoteScriptFailed'
            FailureReasonSummary = "Discovery script failed on the remote system (see TechnicalDetail). Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'SessionCreate' -or $Stage -eq 'ConnectivityTest') {
        return [pscustomobject]@{
            FailureReasonCode    = 'UnknownRemotingFailure'
            FailureReasonSummary = "Remoting failed; see TechnicalDetail for the exact error. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    if ($Stage -eq 'Orchestrator') {
        return [pscustomobject]@{
            FailureReasonCode    = 'OrchestratorError'
            FailureReasonSummary = "Unexpected error in the discovery orchestrator. Target: $ComputerName"
            TechnicalDetail      = $technical
        }
    }

    return [pscustomobject]@{
        FailureReasonCode    = 'UnknownRemotingFailure'
        FailureReasonSummary = "Unexpected failure; see TechnicalDetail. Stage: $Stage Target: $ComputerName"
        TechnicalDetail      = $technical
    }
}

Export-ModuleMember -Function @(
    'Resolve-RemoteGatheringFailure'
    'Test-WinRmHealCandidate'
    'Build-RemotingTechnicalDetail'
)
