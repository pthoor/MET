$retrievalErrors = [System.Collections.Generic.List[string]]::new()

try { $phishSimulationRules = @(Get-ExoPhishSimOverrideRule -ErrorAction Stop) }
catch {
    $phishSimulationRules = @()
    $retrievalErrors.Add("Phishing simulation overrides: $($_.ToString())")
}

try { $secOpsRules = @(Get-ExoSecOpsOverrideRule -ErrorAction Stop) }
catch {
    $secOpsRules = @()
    $retrievalErrors.Add("SecOps mailbox overrides: $($_.ToString())")
}

if ($retrievalErrors.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Fail -Severity Medium -AffectedObject 'Advanced Delivery Policy' `
        -Finding 'Unable to retrieve all Advanced Delivery override rules' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure' `
        -ErrorMessage ($retrievalErrors -join "`n")
    return
}

$activePhishSimulationRules = @($phishSimulationRules | Where-Object { $_.Mode -eq 'Enforce' })
$activeSecOpsRules = @($secOpsRules | Where-Object { $_.Mode -eq 'Enforce' })
$activeCount = $activePhishSimulationRules.Count + $activeSecOpsRules.Count

if ($activeCount -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Info -Severity Medium -AffectedObject 'Advanced Delivery Policy' `
        -Finding 'No enforceable Advanced Delivery phishing simulation or SecOps mailbox overrides are configured' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
}
else {
    $ruleDescriptions = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in $activePhishSimulationRules) { $ruleDescriptions.Add("Phishing simulation: $($rule.Name)") }
    foreach ($rule in $activeSecOpsRules) { $ruleDescriptions.Add("SecOps mailbox: $($rule.Name)") }

    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Info -Severity Medium -AffectedObject "Advanced Delivery Policy ($activeCount override rule(s))" `
        -Finding "$activeCount enforceable Advanced Delivery override rule(s) found: $($ruleDescriptions -join '; ') - matching messages bypass significant MDO/EOP filtering and ZAP actions" `
        -Recommendation 'Advanced Delivery overrides are legitimate for narrowly scoped third-party phishing simulations and dedicated SecOps mailboxes. Periodically verify every rule is still required and correctly scoped; stale simulation infrastructure or an unintended SecOps recipient creates a filtering-bypass path. Review scope at https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
}
