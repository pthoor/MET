# Check — tenant-wide priority account protection toggle (MDO Plan 2 only)
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

if ($null -ne $tenantSettings) {
    if ($tenantSettings.EnablePriorityAccountProtection -eq $true) {
        New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
            -Result Pass -Severity High -AffectedObject $tenantSettings.Identity `
            -Finding 'Priority account protection is enabled. Tagged accounts receive additional MDO heuristics tuned to executive mail flow patterns.' `
            -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO010' -Category MDO -Name 'Priority Account Protection Toggle' `
            -Result Fail -Severity High -AffectedObject $tenantSettings.Identity `
            -Finding 'Priority account protection is disabled; users tagged as Priority accounts silently lose differentiated MDO protections even if the tag and per-policy configuration appear correct' `
            -Recommendation 'Enable priority account protection at https://security.microsoft.com/securitysettings/priorityAccountProtection' `
            -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection'
    }
}

# Check — whether any users are actually tagged as Priority Accounts
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
