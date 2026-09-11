function Disconnect-METSession {
    <#
    .SYNOPSIS
        Tears down the Exchange Online, Microsoft Graph and Microsoft Teams sessions Connect-METSession established.

    .DESCRIPTION
        Disconnects each of the three legs (Exchange Online, Microsoft Graph, Microsoft Teams)
        in its own try/catch, so a failure disconnecting one leg does not prevent the others
        from being torn down. Each failure is surfaced as a warning naming the leg.

        The module's tracked tenant identity (used by Connect-METSession to verify a reused
        session actually belongs to the tenant just requested) is cleared only when every leg is
        confirmed disconnected. If any leg fails to disconnect, the tracking is left in place and
        Connect-METSession will refuse to switch -DelegatedOrganization until the failure is
        resolved - clearing it unconditionally would let a later Connect-METSession call reuse a
        leg that never actually disconnected, the exact cross-customer session leak this tracking
        exists to prevent, reopened from the disconnect side instead of connect.

        Run this before switching to a different -DelegatedOrganization in the same PowerShell
        session.

    .OUTPUTS
        None. Progress and any per-leg disconnect failures are reported via Write-Verbose and
        Write-Warning, not returned as objects.

    .EXAMPLE
        Disconnect-METSession

        Tears down all three legs at the end of an assessment session.

    .EXAMPLE
        Connect-METSession -DelegatedOrganization customerA.onmicrosoft.com
        Invoke-METAssessment | Get-METReport -Format All -OutputPath ./assessments/customerA/
        Disconnect-METSession
        Connect-METSession -DelegatedOrganization customerB.onmicrosoft.com

        The required step between two customers in an MSSP engagement run from a single
        PowerShell process - Connect-METSession will not switch -DelegatedOrganization on a live
        session for a different customer without this in between.

    .EXAMPLE
        Disconnect-METSession -WarningVariable disconnectWarnings -WarningAction SilentlyContinue
        if ($disconnectWarnings) {
            Write-Host 'One or more legs failed to disconnect cleanly - see the captured warnings.'
        }

        Capturing any per-leg disconnect failures in script code, since Disconnect-METSession
        communicates them only via Write-Warning rather than a return value or thrown error.
    #>
    [CmdletBinding()]
    param()

    $failures = [System.Collections.Generic.List[string]]::new()

    try {
        if (Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            Write-Verbose 'Disconnecting Exchange Online...'
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
        }
    }
    catch {
        $failures.Add('Exchange Online')
        Write-Warning "Failed to disconnect Exchange Online: $($_.Exception.Message)"
    }

    try {
        if (Get-MgContext -ErrorAction SilentlyContinue) {
            Write-Verbose 'Disconnecting Microsoft Graph...'
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $failures.Add('Microsoft Graph')
        Write-Warning "Failed to disconnect Microsoft Graph: $($_.Exception.Message)"
    }

    try {
        $teamsConnected = $false

        # Connect-METSession records which legs it actually connected, but ServicesConnected
        # is rebuilt fresh per call: a second connect for the same tenant/org with -SkipTeams
        # drops 'Teams' from the list while the Teams session from the first call is still
        # live. Trusting that list alone then skipped the probe, recorded no failure, and
        # cleared the tracking with Teams still authenticated to the previous customer. The
        # module being loaded is the authority on whether a session can exist at all - if it
        # is not loaded, Get-CsTenant could only be CommandNotFound anyway, which is the
        # false disconnect failure this gate was added to avoid.
        $teamsWasConnected = -not $script:METSessionInfo -or
                             ($script:METSessionInfo.ServicesConnected -contains 'Teams') -or
                             [bool](Get-Module -Name MicrosoftTeams)

        if ($teamsWasConnected) {
            try {
                $null = Get-CsTenant -ErrorAction Stop
                $teamsConnected = $true
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                # MicrosoftTeams was never imported in this session - definitely never connected.
                $teamsConnected = $false
            }
            catch {
                # The module's own not-connected error. Treating this as a disconnect
                # failure left $script:METConnection populated, and the next
                # Connect-METSession for a different -DelegatedOrganization then threw
                # "Run Disconnect-METSession first" - advice that could never succeed.
                if ($_.Exception.Message -match 'Session is not established') {
                    $teamsConnected = $false
                }
                else {
                    # Any other probe failure is ambiguous: it could mean "not connected", or a
                    # transient error while a session is genuinely live. Treating it as not
                    # connected would let the caller clear session tracking with Teams still
                    # authenticated. Fail closed by re-throwing into the outer catch.
                    throw
                }
            }
        }

        if ($teamsConnected) {
            Write-Verbose 'Disconnecting Microsoft Teams...'
            Disconnect-MicrosoftTeams -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $failures.Add('Microsoft Teams')
        Write-Warning "Failed to disconnect Microsoft Teams: $($_.Exception.Message)"
    }

    # Only clear the tracked identity when every leg is confirmed torn down. Clearing it
    # unconditionally would let a subsequent Connect-METSession call for a different
    # -DelegatedOrganization skip the cross-call guard in Connect-METSession.ps1 and silently
    # reuse a leg that failed to disconnect above - the exact cross-customer leak this
    # tracking exists to prevent, just reopened from the disconnect side instead of connect.
    if ($failures.Count -gt 0) {
        Write-Warning "MET session tracking was left in place because $($failures -join ', ') failed to disconnect cleanly. Connect-METSession will refuse to switch tenant/org until this is resolved (e.g. by closing and reopening the PowerShell session)."
    }
    else {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Write-Verbose 'MET session disconnected.'
    }
}
