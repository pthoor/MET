try {
    $antiPhishRules    = @(Get-AntiPhishRule    -ErrorAction Stop | Sort-Object Priority)
    $antiPhishPolicies = @(Get-AntiPhishPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO004' -Category MDO -Name 'Anti-Spoofing' `
        -Result Fail -Severity High -AffectedObject 'Anti-Phish Policies' `
        -Finding 'Unable to retrieve anti-phishing policies (anti-spoofing settings are part of these policies)' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-antispoofing' -ErrorMessage $_.ToString()
    return
}

$ruleByPolicy = @{}
foreach ($r in $antiPhishRules) { $ruleByPolicy[$r.AntiPhishPolicy] = $r }

foreach ($policy in $antiPhishPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule      = $ruleByPolicy[$policy.Name]

    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }

    $scope = if ($isDefault) {
        'catch-all (default — applies to all uncovered recipients)'
    } else {
        Get-METRuleScope -Rule $rule
    }
    $label = "$($policy.Name) [$scope]"

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $policy.EnableSpoofIntelligence) {
        $issues.Add('Spoof intelligence is disabled')
    }

    if ($policy.AuthenticationFailAction -eq 'MoveToJmf') {
        $issues.Add("Authentication failure action is 'MoveToJmf' — consider 'Quarantine' for stronger enforcement")
    }
    elseif ($policy.AuthenticationFailAction -notin 'MoveToJmf','Quarantine') {
        $issues.Add("Authentication failure action is '$($policy.AuthenticationFailAction)' — should be 'Quarantine' or at minimum 'MoveToJmf'")
    }

    if (-not $policy.EnableUnauthenticatedSender) {
        $issues.Add('Unauthenticated sender indicators (? and via tags) are disabled')
    }

    if (-not $policy.HonorDmarcPolicy) {
        $issues.Add('DMARC policy enforcement is not honored')
    }

    if ($issues.Count -gt 0) {
        $result = if ($policy.EnableSpoofIntelligence -eq $false) { 'Fail' } else { 'Warning' }
        New-METCheckResult -CheckId 'MET-MDO004' -Category MDO -Name 'Anti-Spoofing' `
            -Result $result -Severity High -AffectedObject $label `
            -Finding ($issues -join '; ') `
            -Recommendation "Enable spoof intelligence, set AuthenticationFailAction to 'Quarantine', enable unauthenticated sender indicators, and honor DMARC policy." `
            -ReferenceUrl 'https://aka.ms/mdo-antispoofing'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO004' -Category MDO -Name 'Anti-Spoofing' `
            -Result Pass -Severity High -AffectedObject $label `
            -Finding 'Anti-spoofing controls are correctly configured' `
            -ReferenceUrl 'https://aka.ms/mdo-antispoofing'
    }
}
