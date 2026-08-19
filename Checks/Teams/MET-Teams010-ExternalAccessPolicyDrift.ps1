$results = [System.Collections.Generic.List[object]]::new()

try {
    $policies = @(Get-CsExternalAccessPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
        -Result Fail -Severity Medium -AffectedObject 'Teams External Access Policies' `
        -Finding 'Unable to retrieve external access policies.' `
        -Recommendation 'Ensure the account has Teams administrator or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy' -ErrorMessage $_.ToString()
    return
}

$flaggedPolicies = @(
    $policies | Where-Object {
        $_.Identity -ne 'Global' -and
        ($_.EnableFederationAccess -eq $true -or $_.EnablePublicCloudAccess -eq $true)
    }
)

foreach ($policy in $flaggedPolicies) {
    $flags = [System.Collections.Generic.List[string]]::new()
    if ($policy.EnableFederationAccess -eq $true) {
        $flags.Add('EnableFederationAccess')
    }
    if ($policy.EnablePublicCloudAccess -eq $true) {
        $flags.Add('EnablePublicCloudAccess')
    }
    $results.Add((New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
                -Result Warning -Severity Medium -AffectedObject $policy.Identity `
                -Finding "Non-Global external access policy '$($policy.Identity)' re-opens federation/public-cloud access ($($flags -join ', ') enabled) for whoever it is assigned to, undoing any tenant-wide federation restriction set on the Global policy" `
                -Recommendation "Review non-Global external access policies and disable EnableFederationAccess/EnablePublicCloudAccess unless there's a specific business need for that user set to bypass tenant-wide federation restrictions. Run: Get-CsOnlineUser -Filter `"ExternalAccessPolicy -eq '$($policy.Identity)'`" to identify affected users before changing scope." `
                -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy'))
}

if ($results.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams010' -Category Teams -Name 'Per-User External Access Policy Drift' `
        -Result Pass -Severity Medium -AffectedObject 'External Access Policies' `
        -Finding 'No non-Global external access policy re-opens federation or public-cloud access' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy'
}
else {
    $results
}
