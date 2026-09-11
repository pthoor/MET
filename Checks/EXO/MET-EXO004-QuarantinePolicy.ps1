[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Quarantine Policies'
    Severity       = 'Medium'
    Description    = 'Reviews genuinely custom quarantine policies (excluding the 4 immutable built-ins) for ESNEnabled combined with a granted end-user permission.'
    RequiresModule = @('ExchangeOnlineManagement')
}

try {
    $policies = Get-QuarantinePolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
        -Result Fail -Severity Medium -AffectedObject 'Quarantine Policies' `
        -Finding 'Unable to retrieve quarantine policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies' -ErrorMessage $_.ToString()
    return
}

$customPolicies = @($policies | Where-Object { -not (Test-METIsBuiltInQuarantinePolicyName -Name $_.Name) })

if ($customPolicies.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
        -Result Pass -Severity Medium -AffectedObject 'Quarantine Policies' `
        -Finding 'No custom quarantine policies exist - only the 4 Microsoft built-in policies (AdminOnlyAccessPolicy, DefaultFullAccessPolicy, DefaultFullAccessWithNotificationPolicy, NotificationEnabledPolicy) are present, nothing to review' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    return
}

foreach ($policy in $customPolicies) {
    # Get-QuarantinePolicy returns EndUserQuarantinePermissions as a formatted string and
    # does not return EndUserQuarantinePermissionsValue at all (that name is a New-/Set-
    # input parameter only). Get-METEndUserQuarantinePermission parses the string into
    # typed booleans, or $null when nothing could be read - so absence is still detected,
    # per the CLAUDE.md absent-property convention, just against the property that exists.
    $esnProperty  = $policy.PSObject.Properties['ESNEnabled']
    $permissions  = Get-METEndUserQuarantinePermission -QuarantinePolicy $policy
    $missingProperties = [System.Collections.Generic.List[string]]::new()
    if (-not $esnProperty -or $null -eq $esnProperty.Value) { $missingProperties.Add('ESNEnabled') }
    if ($null -eq $permissions) { $missingProperties.Add('EndUserQuarantinePermissions') }

    if ($missingProperties.Count -gt 0) {
        $propertyList = $missingProperties -join ' and '
        $verb = if ($missingProperties.Count -eq 1) { 'was' } else { 'were' }
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Warning -Severity Medium -AffectedObject $policy.Name `
            -Finding "The $propertyList propert$(if ($missingProperties.Count -eq 1) { 'y' } else { 'ies' }) $verb not returned by Get-QuarantinePolicy for this policy, so whether end users are notified about quarantined mail they have permission to act on was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a policy whose notification settings match its permissions from one where they conflict." `
            -Recommendation "Confirm the settings directly with: Get-QuarantinePolicy -Identity '$($policy.Name)' | Format-List ESNEnabled, EndUserQuarantinePermissions. An absent or unreadable property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment." `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies' `
            -ErrorMessage "Get-QuarantinePolicy did not return $propertyList for this policy."
        continue
    }

    $anyPermissionGranted = @($permissions.PSObject.Properties | Where-Object { $_.Value -eq $true }).Count -gt 0

    if (-not $policy.ESNEnabled -and $anyPermissionGranted) {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Warning -Severity Medium -AffectedObject $policy.Name `
            -Finding 'End users are granted quarantine permissions (e.g. review, release, delete) but end-user spam notifications (ESN) are disabled, so they are never notified that anything is quarantined and have no way to know to use those permissions' `
            -Recommendation 'Enable end-user spam notifications (ESNEnabled) on this quarantine policy so users are alerted when they have messages to review, or remove their end-user permissions if notifications are intentionally disabled.' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Pass -Severity Medium -AffectedObject $policy.Name `
            -Finding 'Notification settings are consistent with the permissions granted to end users' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
}
