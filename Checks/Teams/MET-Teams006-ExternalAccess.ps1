$issues = [System.Collections.Generic.List[string]]::new()

# Check Teams federation (external access) allow-list scope
try {
    $config = Get-CsTenantFederationConfiguration -ErrorAction Stop

    $allowedDomainsValue = $config.AllowedDomains
    $isAllowAllKnownDomains = $false
    if ($allowedDomainsValue -eq 'AllowAllKnownDomains') {
        $isAllowAllKnownDomains = $true
    }
    elseif ($allowedDomainsValue -and $allowedDomainsValue.ToString() -eq 'AllowAllKnownDomains') {
        $isAllowAllKnownDomains = $true
    }

    if ($config.AllowFederatedUsers -eq $true -and $isAllowAllKnownDomains) {
        $issues.Add('Federation is open to all external domains (AllowAllKnownDomains) - any external Teams user can attempt to chat with your staff, a common vector for Teams-based phishing and vishing')
    }

    if ($config.AllowTeamsConsumer -eq $true) {
        $inboundOpen = $config.AllowTeamsConsumerInbound -ne $false
        if ($inboundOpen) {
            $issues.Add('Teams accounts not managed by any organization (consumer/personal accounts) are allowed to federate, and AllowTeamsConsumerInbound is enabled - unmanaged personal accounts can discover and initiate first contact with your staff, the higher-risk direction for Teams-based phishing and vishing')
        }
        else {
            $issues.Add('Teams accounts not managed by any organization (consumer/personal accounts) are allowed to federate, but AllowTeamsConsumerInbound is disabled - this is partially mitigated: personal/consumer accounts cannot discover or initiate contact with your staff, only your staff can start a conversation outbound')
        }

        $restrictProperty = $config.PSObject.Properties['RestrictTeamsConsumerToExternalUserProfiles']
        if ($restrictProperty -and $config.RestrictTeamsConsumerToExternalUserProfiles -eq $true) {
            $issues.Add('RestrictTeamsConsumerToExternalUserProfiles is enabled, further limiting consumer/personal account interaction to users in the Extended Directory external user profiles rather than any arbitrary personal account')
        }
    }

    if ($config.AllowFederatedUsers -eq $true -and -not $config.BlockedDomains) {
        $issues.Add('No explicit BlockedDomains deny-list is configured - there is no domain-level backstop in place as a defense-in-depth measure if the allow-list scope is ever widened')
    }
}
catch {
    $issues.Add("Could not retrieve tenant federation configuration: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve tenant federation configuration: $_"
}

if ($issues.Count -gt 0) {
    $result = if ($issues | Where-Object { $_ -match 'AllowAllKnownDomains' }) { 'Fail' } else { 'Warning' }
    New-METCheckResult -CheckId 'MET-Teams006' -Category Teams -Name 'External Access / Federation Allow-List' `
        -Result $result -Severity High -AffectedObject 'Teams External Access Configuration' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Restrict AllowedDomains to a specific, reviewed allow-list of trusted partner domains instead of AllowAllKnownDomains, and configure a BlockedDomains deny-list as a defense-in-depth backstop. Disable AllowTeamsConsumer unless there is a specific business need for staff to chat with personal Teams/Skype accounts; if it must stay enabled, run Set-CsTenantFederationConfiguration -AllowTeamsConsumerInbound $false so personal/consumer accounts cannot discover or initiate contact with your organization, and consider -RestrictTeamsConsumerToExternalUserProfiles $true to further narrow exposure. Run: Set-CsTenantFederationConfiguration -AllowedDomains <AllowedDomainsObject> to scope federation, or -AllowFederatedUsers $false to disable entirely.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
}
else {
    New-METCheckResult -CheckId 'MET-Teams006' -Category Teams -Name 'External Access / Federation Allow-List' `
        -Result Pass -Severity High -AffectedObject 'Teams External Access Configuration' `
        -Finding 'Teams external access (federation) is appropriately scoped' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
}
