$issues = [System.Collections.Generic.List[string]]::new()
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

try {
    $policies = @(Get-CsTeamsAppPermissionPolicy -ErrorAction Stop)
    foreach ($policy in $policies) {
        foreach ($propName in @('GlobalCatalogAppsType', 'DefaultCatalogAppsType', 'PrivateCatalogAppsType')) {
            $value = $policy.$propName
            if ($value -notin @('AllowedAppList', 'BlockedAppList')) {
                $issues.Add("Policy '$($policy.Identity)': $propName is '$value' - apps from this catalog are not restricted to a reviewed allow-list or block-list")
            }
        }
    }
}
catch {
    $retrievalErrors.Add("Could not retrieve Teams app permission policies: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams app permission policies: $_"
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams008' -Category Teams -Name 'App Permission Policy' `
        -Result Warning -Severity Medium -AffectedObject 'Teams App Permission Policies' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Third-party Teams apps carry delegated Graph permissions and are a growing OAuth-consent-phishing and supply-chain vector. Configure app permission policies in the Teams admin center (Teams apps > Permission policies) to use an explicit allowed-app list or blocked-app list rather than leaving any catalog unrestricted. Note: app permission policies must be created/modified in the admin center, not via PowerShell Set-/New- cmdlets. If this tenant has migrated to App Centric Management (ACM) or Unified App Management (UAM), this policy may no longer be enforced - verify current app governance in the Teams admin center (admin.teams.microsoft.com) rather than relying solely on this check.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies' `
        -ErrorMessage ($retrievalErrors -join "`n")
}
elseif ($retrievalErrors.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams008' -Category Teams -Name 'App Permission Policy' `
        -Result Warning -Severity Medium -AffectedObject 'Teams App Permission Policies' `
        -Finding 'The Teams app permission policies could not be read, so whether each app catalog is restricted to an explicit allow-list or block-list was not assessed.' `
        -Recommendation 'Ensure the MicrosoftTeams module is installed and the session has permission to read Teams app permission policies, then rerun the assessment. App governance can also be reviewed directly in the Teams admin center (admin.teams.microsoft.com).' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies' `
        -ErrorMessage ($retrievalErrors -join "`n")
}
else {
    New-METCheckResult -CheckId 'MET-Teams008' -Category Teams -Name 'App Permission Policy' `
        -Result Pass -Severity Medium -AffectedObject 'Teams App Permission Policies' `
        -Finding 'All Teams app permission policies restrict app catalogs to an explicit allow-list or block-list' `
        -Recommendation 'If this tenant has migrated to App Centric Management (ACM) or Unified App Management (UAM), this policy may no longer be enforced - verify current app governance in the Teams admin center (admin.teams.microsoft.com) rather than relying solely on this check.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies'
}
