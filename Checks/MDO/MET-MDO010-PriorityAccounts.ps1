[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Priority Account Protection Toggle'
    Severity       = 'High'
    Description    = 'Checks whether the priority account protection toggle is enabled and whether priority account tags are applied to a differentiated protection policy.'
    RequiresModule = @('ExchangeOnlineManagement')
}

# Check - tenant-wide priority account protection toggle (MDO Plan 2 only)
try {
    $tenantSettings = Get-EmailTenantSettings -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
        -Result Fail -Severity High -AffectedObject 'EmailTenantSettings' `
        -Finding 'Unable to retrieve EmailTenantSettings to assess priority account protection' `
        -Recommendation 'Ensure the account has the Security Reader or Security Administrator role in Defender for Office 365.' `
        -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection' `
        -ErrorMessage $_.ToString()
    return
}

$tenantSettingsList = @($tenantSettings)
$tenantSettingsObj = if ($tenantSettingsList.Count -gt 0) { $tenantSettingsList[0] } else { $null }
$toggleProperty = if ($null -ne $tenantSettingsObj) { $tenantSettingsObj.PSObject.Properties['EnablePriorityAccountProtection'] } else { $null }

if ($null -eq $tenantSettingsObj) {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
        -Result NotApplicable -Severity High -AffectedObject 'EmailTenantSettings' `
        -Finding 'Get-EmailTenantSettings returned no object, so whether tenant-wide priority account protection is enabled was not established for this tenant. Microsoft Defender for Office 365 Plan 2 licensing is required for this control, so a tenant without it may legitimately return nothing here. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with the setting on from one with it switched off.' `
        -Recommendation 'Confirm Microsoft Defender for Office 365 Plan 2 licensing is assigned to the tenant, then run Get-EmailTenantSettings directly to confirm whether it returns data.' `
        -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection' `
        -ErrorMessage 'Get-EmailTenantSettings returned no object.'
}
elseif (-not $toggleProperty -or $null -eq $toggleProperty.Value) {
    $affectedObject = if ($tenantSettingsObj.PSObject.Properties['Identity'] -and $tenantSettingsObj.Identity) { $tenantSettingsObj.Identity } else { 'EmailTenantSettings' }
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
        -Result NotApplicable -Severity High -AffectedObject $affectedObject `
        -Finding 'The EnablePriorityAccountProtection property was not returned by Get-EmailTenantSettings, so whether tenant-wide priority account protection is enabled was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with the setting on from one with it switched off.' `
        -Recommendation 'Confirm the setting directly with: Get-EmailTenantSettings | Format-List EnablePriorityAccountProtection.' `
        -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection' `
        -ErrorMessage 'Get-EmailTenantSettings did not return an EnablePriorityAccountProtection value.'
}
elseif ($toggleProperty.Value -eq $true) {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
        -Result Pass -Severity High -AffectedObject $tenantSettingsObj.Identity `
        -Finding 'Priority account protection is enabled. Tagged accounts receive additional MDO heuristics tuned to executive mail flow patterns.' `
        -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection'
}
else {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
        -Result Fail -Severity High -AffectedObject $tenantSettingsObj.Identity `
        -Finding 'Priority account protection is disabled; users tagged as Priority accounts silently lose differentiated MDO protections even if the tag and per-policy configuration appear correct' `
        -Recommendation 'Enable priority account protection at https://security.microsoft.com/securitysettings/priorityAccountProtection' `
        -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection'
}

# Check - whether any users are actually tagged as Priority Accounts
try {
    $priorityUsers = Get-User -IsVIP -ResultSize Unlimited -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Tagging' `
        -Result Fail -Severity Medium -AffectedObject 'Priority Account Tags' `
        -Finding 'Unable to retrieve Priority Account tag membership' `
        -Recommendation 'Ensure the account has the Security Administrator and Exchange Admin roles.' `
        -ReferenceUrl 'https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts' `
        -ErrorMessage $_.ToString()
    return
}

$count = @($priorityUsers).Count
$userLabel = if ($count -eq 1) { '1 user has' } else { "$count users have" }

if ($count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Tagging' `
        -Result Warning -Severity Medium -AffectedObject 'Priority Account Tags' `
        -Finding 'No users have the Priority Account tag applied' `
        -Recommendation 'Tag high-value accounts (executives, IT admins, finance leads) as Priority Accounts in the Microsoft 365 admin center to enable enhanced threat protection and differentiated reporting.' `
        -ReferenceUrl 'https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts'
}
else {
    New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Tagging' `
        -Result Pass -Severity Medium -AffectedObject "Priority Account Tags ($count tagged)" `
        -Finding "$userLabel the Priority Account tag applied" `
        -ReferenceUrl 'https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts'
}
