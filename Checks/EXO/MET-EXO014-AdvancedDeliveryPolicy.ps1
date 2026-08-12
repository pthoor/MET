try {
    $overrideRules = @(Get-ExoPhishSimOverrideRule -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Fail -Severity Medium -AffectedObject 'Advanced Delivery Policy' `
        -Finding 'Unable to retrieve Advanced Delivery (phishing simulation override) rules' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure' -ErrorMessage $_.ToString()
    return
}

$enabledRules = @($overrideRules | Where-Object { $_.State -eq 'Enabled' })

if ($enabledRules.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Info -Severity Medium -AffectedObject 'Advanced Delivery Policy' `
        -Finding 'No Advanced Delivery phishing simulation overrides are configured' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
}
else {
    $ruleNames = ($enabledRules | Select-Object -ExpandProperty Name) -join ', '
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Info -Severity Medium -AffectedObject "Advanced Delivery Policy ($($enabledRules.Count) override rule(s))" `
        -Finding "$($enabledRules.Count) enabled phishing simulation override rule(s) found: $ruleNames — these exempt matching mail from all MDO/EOP filtering, ZAP, and alerting" `
        -Recommendation 'Advanced Delivery overrides are meant for third-party phishing simulation platforms and are legitimate when scoped narrowly to the simulation vendor''s specific sending infrastructure. Periodically verify each rule is still tied to an active simulation platform or SecOps process — a stale or overly broad override is an unfiltered inbound channel that completely bypasses MDO. Review scope at https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
}
