try {
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO021' -Category EXO -Name 'Mailbox Audit Logging' `
        -Result Fail -Severity Medium -AffectedObject 'Organization Configuration' `
        -Finding 'Unable to retrieve organization configuration, so the mailbox audit logging state could not be determined' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions, then re-run this check.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-mailboxes' -ErrorMessage $_.ToString()
    return
}

$auditDisabled = $orgConfig.AuditDisabled

if ($auditDisabled -eq $true) {
    New-METCheckResult -CheckId 'MET-EXO021' -Category EXO -Name 'Mailbox Audit Logging' `
        -Result Fail -Severity Medium -AffectedObject 'Organization Configuration' `
        -Finding 'Mailbox audit logging is turned off organization-wide (AuditDisabled is set to true) - no mailbox audit records are being written, so there is no way to reconstruct what a compromised account read, moved, or exported. This history cannot be backfilled: a tenant that discovers this during an incident has already lost the evidence base every business email compromise investigation depends on' `
        -Recommendation 'Run: Set-OrganizationConfig -AuditDisabled $false to re-enable mailbox audit logging for the organization. Then confirm per-mailbox auditing is on (Get-Mailbox -ResultSize Unlimited | Format-List UserPrincipalName, AuditEnabled) - the organization-wide switch does not by itself guarantee every mailbox is being audited, and records only start accruing from the moment auditing is on.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-mailboxes'
}
elseif ($null -eq $auditDisabled) {
    New-METCheckResult -CheckId 'MET-EXO021' -Category EXO -Name 'Mailbox Audit Logging' `
        -Result Pass -Severity Medium -AffectedObject 'Organization Configuration' `
        -Finding 'Mailbox audit logging is assumed to be enabled - the AuditDisabled property was absent from the organization configuration, so this state was assumed from the platform default (mailbox auditing is on by default) rather than observed on this tenant' `
        -Recommendation 'Confirm the state directly: Get-OrganizationConfig | Format-List AuditDisabled. If it reports true, run Set-OrganizationConfig -AuditDisabled $false, then confirm per-mailbox auditing is on (Get-Mailbox -ResultSize Unlimited | Format-List UserPrincipalName, AuditEnabled).' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-mailboxes'
}
else {
    New-METCheckResult -CheckId 'MET-EXO021' -Category EXO -Name 'Mailbox Audit Logging' `
        -Result Pass -Severity Medium -AffectedObject 'Organization Configuration' `
        -Finding 'Mailbox audit logging is enabled organization-wide (AuditDisabled is set to false) - mailbox audit records are being written, preserving the evidence needed to reconstruct what an account read, moved, or exported' `
        -Recommendation 'Confirm per-mailbox auditing is on as well (Get-Mailbox -ResultSize Unlimited | Format-List UserPrincipalName, AuditEnabled) - the organization-wide switch does not by itself guarantee every mailbox is being audited.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-mailboxes'
}
