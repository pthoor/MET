try {
    $policies = Get-SafeLinksPolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding 'Unable to retrieve Safe Links policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams' -ErrorMessage $_.ToString()
    return
}

if (-not $policies) {
    New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding 'No Safe Links policies found' `
        -Recommendation 'Create a Safe Links policy with EnableSafeLinksForTeams enabled and apply it to Teams users.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams'
    return
}

$teamsEnabled = $policies | Where-Object { $_.EnableSafeLinksForTeams -eq $true }

if (-not $teamsEnabled) {
    New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding 'No Safe Links policy has EnableSafeLinksForTeams enabled — Teams URLs are not scanned' `
        -Recommendation 'Enable EnableSafeLinksForTeams in at least one Safe Links policy and ensure it covers all Teams users. Consider applying the Standard or Strict preset which includes Teams protection.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams'
    return
}

foreach ($policy in $teamsEnabled) {
    New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
        -Result Pass -Severity High -AffectedObject $policy.Name `
        -Finding 'Safe Links for Teams is enabled' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams'
}
