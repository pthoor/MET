try {
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO023' -Category EXO -Name 'Unified Audit Log Ingestion' `
        -Result Fail -Severity High -AffectedObject 'Admin Audit Log Configuration' `
        -Finding 'Unable to retrieve the admin audit log configuration, so unified audit log ingestion could not be confirmed' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions, then re-run this check.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-log-enable-disable' -ErrorMessage $_.ToString()
    return
}

$ingestionEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled

$retentionNote = 'This check does not verify audit log retention. Retention duration is governed by audit retention policies that are not readable over the Exchange Online connection this module uses, so confirm retention separately in the compliance portal as a manual follow-up.'

if ($ingestionEnabled -eq $true) {
    New-METCheckResult -CheckId 'MET-EXO023' -Category EXO -Name 'Unified Audit Log Ingestion' `
        -Result Pass -Severity High -AffectedObject 'Admin Audit Log Configuration' `
        -Finding 'Unified audit log ingestion is enabled - the tenant-wide record that mail-flow, admin, and sign-in investigations are reconstructed from is being written' `
        -Recommendation $retentionNote `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-log-enable-disable'
}
elseif ($null -eq $ingestionEnabled) {
    New-METCheckResult -CheckId 'MET-EXO023' -Category EXO -Name 'Unified Audit Log Ingestion' `
        -Result Fail -Severity High -AffectedObject 'Admin Audit Log Configuration' `
        -Finding 'The UnifiedAuditLogIngestionEnabled property was absent from the admin audit log configuration, so unified audit log ingestion could not be confirmed. An unconfirmed state is reported as a gap rather than a pass because ingestion has historically shipped switched off in some tenants, and if it is off nothing is being recorded - switching it on later does not recover the missing window' `
        -Recommendation ('Confirm the state directly (Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled) and, if it is not enabled, run: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. ' + $retentionNote) `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-log-enable-disable'
}
else {
    New-METCheckResult -CheckId 'MET-EXO023' -Category EXO -Name 'Unified Audit Log Ingestion' `
        -Result Fail -Severity High -AffectedObject 'Admin Audit Log Configuration' `
        -Finding 'Unified audit log ingestion is disabled - nothing is being recorded to the tenant-wide audit log that mail-flow, admin, and sign-in investigations are reconstructed from, and enabling it later does not recover the window that went unlogged' `
        -Recommendation ('Run: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. ' + $retentionNote) `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/purview/audit-log-enable-disable'
}
