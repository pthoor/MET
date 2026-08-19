$delegationRetrieved = $false
$delegationValue = $null
$delegationError = $null

try {
    $config = Get-CsTenantFederationConfiguration -ErrorAction Stop
    $delegationRetrieved = $true
    $delegationValue = $config.SecurityTeamAllowBlockListDelegation
}
catch {
    $delegationError = $_.Exception.Message
    Write-Verbose "Could not retrieve tenant federation configuration: $_"
}

$blockedUsersRetrieved = $false
$blockedUsersCount = 0
$blockedUsersError = $null

try {
    $extConfig = Get-CsTeamsExternalAccessConfiguration -ErrorAction Stop
    $blockedUsersRetrieved = $true
    if ($extConfig.PSObject.Properties.Match('BlockedUsers').Count -gt 0 -and $extConfig.BlockedUsers) {
        $blockedUsersCount = @($extConfig.BlockedUsers).Count
    }
}
catch {
    $blockedUsersError = $_.Exception.Message
    Write-Verbose "Could not retrieve Teams external access configuration: $_"
}

if (-not $delegationRetrieved -and -not $blockedUsersRetrieved) {
    New-METCheckResult -CheckId 'MET-Teams011' -Category Teams -Name 'SecOps Blocklist Authority & Blocked Entities' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Tenant Federation Configuration' `
        -Finding 'Unable to retrieve tenant federation configuration or Teams external access configuration.' `
        -Recommendation 'Set-CsTenantFederationConfiguration -SecurityTeamAllowBlockListDelegation Enabled' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration' `
        -ErrorMessage "Could not retrieve tenant federation configuration: $delegationError; Could not retrieve Teams external access configuration: $blockedUsersError"
    return
}

if ($delegationRetrieved -and $delegationValue -eq 'Enabled') {
    $result = 'Pass'
    $findingBase = 'SecOps can add domains/users to the Teams blocklist from the Defender security portal during an active incident (SecurityTeamAllowBlockListDelegation is Enabled).'
}
elseif ($delegationRetrieved) {
    $result = 'Warning'
    $findingBase = "SecOps cannot block malicious domains/users from the security portal during an incident (SecurityTeamAllowBlockListDelegation is '$delegationValue'); must fall back to Set-CsTenantFederationConfiguration PowerShell access instead."
}
else {
    $result = 'Warning'
    $findingBase = "Could not determine whether SecOps can block malicious domains/users from the security portal - retrieving SecurityTeamAllowBlockListDelegation failed: $delegationError"
}

if ($blockedUsersRetrieved) {
    if ($blockedUsersCount -gt 0) {
        $blockedUsersNote = " $blockedUsersCount user(s) currently blocked via Teams external access configuration."
    }
    else {
        $blockedUsersNote = ' No users currently blocked via Teams external access configuration - verify this is expected for a mature tenant.'
    }
}
else {
    $blockedUsersNote = " Could not retrieve current Teams external access blocked users list: $blockedUsersError"
}

New-METCheckResult -CheckId 'MET-Teams011' -Category Teams -Name 'SecOps Blocklist Authority & Blocked Entities' `
    -Result $result -Severity Medium -AffectedObject 'Teams Tenant Federation Configuration' `
    -Finding ($findingBase + $blockedUsersNote) `
    -Recommendation 'Set-CsTenantFederationConfiguration -SecurityTeamAllowBlockListDelegation Enabled' `
    -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
