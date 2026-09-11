[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Mailbox Audit Logging'
    Severity       = 'Medium'
    Description    = 'Checks AuditDisabled on Get-OrganizationConfig, the tenant-wide mailbox audit logging setting.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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
        -Result Warning -Severity Medium -AffectedObject 'Organization Configuration' `
        -Finding 'The AuditDisabled property was not returned by the organization configuration, so whether mailbox audit logging is on was not established for this tenant. An unconfirmed state is reported as a gap rather than a pass: the platform default is on, but a default is not an observation, and a tenant that has switched auditing off looks identical here' `
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
