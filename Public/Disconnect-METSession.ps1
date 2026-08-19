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
        try {
            $null = Get-CsTenant -ErrorAction Stop
            $teamsConnected = $true
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            # MicrosoftTeams was never imported in this session - definitely never connected.
            $teamsConnected = $false
        }
        catch {
            # Any other probe failure is ambiguous: it could mean "not connected" (the expected
            # case), or a transient/auth error while a session is still genuinely live. Treating
            # it as "not connected" would silently skip Disconnect-MicrosoftTeams below and let
            # the caller clear session tracking even though Teams might still be authenticated -
            # undermining the very invariant this tracking exists to enforce. Fail closed by
            # re-throwing into the outer catch, which records it as a disconnect failure.
            throw
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
