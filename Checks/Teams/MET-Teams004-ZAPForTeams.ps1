try {
    $teamsPolicy = Get-TeamsProtectionPolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Fail -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding 'Unable to retrieve Teams protection policy' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions and that Defender for Office 365 Plan 1 or Plan 2 is licensed.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap' -ErrorMessage $_.ToString()
    return
}

if (-not $teamsPolicy) {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Fail -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding 'No Teams protection policy found' `
        -Recommendation 'Configure the Teams protection policy in the Microsoft Defender portal at security.microsoft.com/securitysettings/teamsProtectionPolicy.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap'
    return
}

function Test-QuarantineTagPermission {
    param([string]$TagName, [string]$Label)

    if (-not $TagName) {
        return "No quarantine policy is assigned for $Label — the tenant default may allow users to self-release"
    }

    if ($TagName -eq 'AdminOnlyAccessPolicy') {
        return $null
    }

    try {
        $policy = Get-QuarantinePolicy -Identity $TagName -ErrorAction Stop
    }
    catch {
        return "Unable to retrieve quarantine policy '$TagName' for $Label — cannot verify user release permissions"
    }

    if ($policy.EndUserQuarantinePermissions.PermissionToRelease) {
        return "$Label quarantine policy '$TagName' allows users to self-release quarantined messages — set PermissionToRelease to false or use AdminOnlyAccessPolicy"
    }

    return $null
}

$issues = [System.Collections.Generic.List[string]]::new()

if (-not $teamsPolicy.ZapEnabled) {
    $issues.Add('Zero-hour auto purge (ZAP) for Teams is disabled — malicious messages already delivered to Teams chats are not retroactively removed')
}

$malwareIssue = Test-QuarantineTagPermission -TagName $teamsPolicy.MalwareQuarantineTag -Label 'Malware'
if ($malwareIssue) { $issues.Add($malwareIssue) }

$hcpIssue = Test-QuarantineTagPermission -TagName $teamsPolicy.HighConfidencePhishQuarantineTag -Label 'High-confidence phish'
if ($hcpIssue) { $issues.Add($hcpIssue) }

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Fail -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Enable ZAP for Teams: Set-TeamsProtectionPolicy -ZapEnabled $true. Ensure MalwareQuarantineTag and HighConfidencePhishQuarantineTag use AdminOnlyAccessPolicy or a custom policy with PermissionToRelease disabled.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap'
}
else {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Pass -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding 'ZAP for Teams is enabled and quarantine policies do not allow user self-release' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap'
}
