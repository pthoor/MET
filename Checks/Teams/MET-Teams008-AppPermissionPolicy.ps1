$issues = [System.Collections.Generic.List[string]]::new()

try {
    $policies = @(Get-CsTeamsAppPermissionPolicy -ErrorAction Stop)
    foreach ($policy in $policies) {
        foreach ($propName in @('GlobalCatalogAppsType', 'DefaultCatalogAppsType', 'PrivateCatalogAppsType')) {
            $value = $policy.$propName
            if ($value -notin @('AllowedAppList', 'BlockedAppList')) {
                $issues.Add("Policy '$($policy.Identity)': $propName is '$value' — apps from this catalog are not restricted to a reviewed allow-list or block-list")
            }
        }
    }
}
catch {
    $issues.Add("Could not retrieve Teams app permission policies: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams app permission policies: $_"
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams008' -Category Teams -Name 'App Permission Policy' `
        -Result Warning -Severity Medium -AffectedObject 'Teams App Permission Policies' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Third-party Teams apps carry delegated Graph permissions and are a growing OAuth-consent-phishing and supply-chain vector. Configure app permission policies in the Teams admin center (Teams apps > Permission policies) to use an explicit allowed-app list or blocked-app list rather than leaving any catalog unrestricted. Note: app permission policies must be created/modified in the admin center, not via PowerShell Set-/New- cmdlets.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies'
}
else {
    New-METCheckResult -CheckId 'MET-Teams008' -Category Teams -Name 'App Permission Policy' `
        -Result Pass -Severity Medium -AffectedObject 'Teams App Permission Policies' `
        -Finding 'All Teams app permission policies restrict app catalogs to an explicit allow-list or block-list' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies'
}
