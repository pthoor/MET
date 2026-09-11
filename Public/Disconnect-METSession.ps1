function Disconnect-METSession {
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

        # Connect-METSession records which legs it actually connected. If Teams was
        # never one of them there is nothing to probe, and probing anyway was the whole
        # source of the false disconnect failure below.
        $teamsWasConnected = -not $script:METSessionInfo -or
                             ($script:METSessionInfo.ServicesConnected -contains 'Teams')

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
