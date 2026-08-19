try {
    $config = Get-CsTenantFederationConfiguration -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams009' -Category Teams -Name 'Trial Tenant Federation Exposure' `
        -Result Fail -Severity High -AffectedObject 'Teams External Access Configuration' `
        -Finding 'Unable to retrieve tenant federation configuration.' `
        -Recommendation 'Ensure the account has Teams administrator or higher permissions and that the MicrosoftTeams module is connected.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration' -ErrorMessage $_.ToString()
    return
}

$trialAccess = $config.ExternalAccessWithTrialTenants

$allowedTrialDomains = $null
if ($null -ne $config.PSObject.Properties['AllowedTrialTenantDomains']) {
    $allowedTrialDomains = $config.AllowedTrialTenantDomains
}
$hasAllowedTrialDomains = $allowedTrialDomains -and @($allowedTrialDomains).Count -gt 0
$allowedTrialDomainsText = if ($hasAllowedTrialDomains) {
    " An explicit allow-list of trial tenant domains is configured: $(@($allowedTrialDomains) -join ', ')."
}
else {
    ''
}

switch ($trialAccess) {
    'Allowed' {
        New-METCheckResult -CheckId 'MET-Teams009' -Category Teams -Name 'Trial Tenant Federation Exposure' `
            -Result Fail -Severity High -AffectedObject 'Teams External Access Configuration' `
            -Finding "Communication with trial/unlicensed Microsoft 365 tenants is allowed (ExternalAccessWithTrialTenants = Allowed). Trial tenants are trivial to spin up disposably, making them a known first-contact vector for phishing and vishing (Storm-1811-style attacks): an attacker creates a fresh, clean-looking tenant, uses it once to reach your users via Teams chat or calls, then discards it before it can be flagged or blocked.$allowedTrialDomainsText" `
            -Recommendation 'Run: Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
    }
    'Blocked' {
        New-METCheckResult -CheckId 'MET-Teams009' -Category Teams -Name 'Trial Tenant Federation Exposure' `
            -Result Pass -Severity High -AffectedObject 'Teams External Access Configuration' `
            -Finding "Communication with trial/unlicensed Microsoft 365 tenants is blocked (ExternalAccessWithTrialTenants = Blocked).$allowedTrialDomainsText" `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
    }
    default {
        New-METCheckResult -CheckId 'MET-Teams009' -Category Teams -Name 'Trial Tenant Federation Exposure' `
            -Result Warning -Severity High -AffectedObject 'Teams External Access Configuration' `
            -Finding "ExternalAccessWithTrialTenants returned an unrecognized or missing value ('$trialAccess') - could not determine whether communication with trial/unlicensed tenants is allowed or blocked.$allowedTrialDomainsText" `
            -Recommendation 'Verify the MicrosoftTeams module version supports ExternalAccessWithTrialTenants, then run Get-CsTenantFederationConfiguration and confirm the value manually. Run: Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked to enforce the secure setting.' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration'
    }
}
