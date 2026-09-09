$ruleRetrievalError = $null

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
        return [PSCustomObject]@{ Severity = 'Fail'; Message = "No quarantine policy is assigned for $Label - the tenant default may allow users to self-release" }
    }

    if ($TagName -eq 'AdminOnlyAccessPolicy') {
        return $null
    }

    try {
        $policy = Get-QuarantinePolicy -Identity $TagName -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{ Severity = 'Fail'; Message = "Unable to retrieve quarantine policy '$TagName' for $Label - cannot verify user release permissions" }
    }

    # EndUserQuarantinePermissions.PermissionToRelease is a nested property: absent on
    # either level, or present-but-$null on either level, reads as $null just like a
    # confirmed $false would. Distinguish "not returned" from "returned and false" before
    # branching, so an unobserved permission cannot be reported as a prevented one.
    $permissionsProperty = $policy.PSObject.Properties['EndUserQuarantinePermissions']
    $releaseProperty = $null
    if ($permissionsProperty -and $null -ne $permissionsProperty.Value) {
        $releaseProperty = $permissionsProperty.Value.PSObject.Properties['PermissionToRelease']
    }

    if (-not $permissionsProperty -or $null -eq $permissionsProperty.Value -or -not $releaseProperty -or $null -eq $releaseProperty.Value) {
        return [PSCustomObject]@{
            Severity = 'Warning'
            Message  = "$Label quarantine policy '$TagName' whose EndUserQuarantinePermissions.PermissionToRelease was not returned by Get-QuarantinePolicy, so whether users can self-release quarantined messages via this tag was not established"
        }
    }

    if ($releaseProperty.Value) {
        return [PSCustomObject]@{ Severity = 'Fail'; Message = "$Label quarantine policy '$TagName' allows users to self-release quarantined messages - set PermissionToRelease to false or use AdminOnlyAccessPolicy" }
    }

    return $null
}

$issues = [System.Collections.Generic.List[string]]::new()
$permissionWarnings = [System.Collections.Generic.List[string]]::new()

if (-not $teamsPolicy.ZapEnabled) {
    $issues.Add('Zero-hour auto purge (ZAP) for Teams is disabled - malicious messages already delivered to Teams chats are not retroactively removed')
}

$malwareResult = Test-QuarantineTagPermission -TagName $teamsPolicy.MalwareQuarantineTag -Label 'Malware'
if ($malwareResult) {
    if ($malwareResult.Severity -eq 'Fail') { $issues.Add($malwareResult.Message) } else { $permissionWarnings.Add($malwareResult.Message) }
}

$hcpResult = Test-QuarantineTagPermission -TagName $teamsPolicy.HighConfidencePhishQuarantineTag -Label 'High-confidence phish'
if ($hcpResult) {
    if ($hcpResult.Severity -eq 'Fail') { $issues.Add($hcpResult.Message) } else { $permissionWarnings.Add($hcpResult.Message) }
}

$warningIssues = [System.Collections.Generic.List[string]]::new()

try {
    $protectionRules = @(Get-TeamsProtectionPolicyRule -ErrorAction Stop)
    $rulesWithExceptions = @($protectionRules | Where-Object {
        $_.State -eq 'Enabled' -and (
            @($_.ExceptIfSentTo | Where-Object { $_ }).Count -gt 0 -or
            @($_.ExceptIfSentToMemberOf | Where-Object { $_ }).Count -gt 0 -or
            @($_.ExceptIfRecipientDomainIs | Where-Object { $_ }).Count -gt 0
        )
    })
    foreach ($rule in $rulesWithExceptions) {
        $exceptedRecipients = @($rule.ExceptIfSentTo | Where-Object { $_ }).Count
        $exceptedGroups = @($rule.ExceptIfSentToMemberOf | Where-Object { $_ }).Count
        $exceptedDomains = @($rule.ExceptIfRecipientDomainIs | Where-Object { $_ }).Count
        $exceptionParts = [System.Collections.Generic.List[string]]::new()
        if ($exceptedRecipients -gt 0) { $exceptionParts.Add("$exceptedRecipients recipient(s)") }
        if ($exceptedGroups -gt 0) { $exceptionParts.Add("$exceptedGroups group(s)") }
        if ($exceptedDomains -gt 0) { $exceptionParts.Add("$exceptedDomains domain(s)") }
        $warningIssues.Add("Teams protection rule '$($rule.Name)' excepts $($exceptionParts -join ', ') from Teams ZAP protection - excluded recipients do not receive retroactive removal of malicious messages")
    }
}
catch {
    # The exception data is what narrows effective ZAP coverage. Losing it silently and
    # then reporting Pass would claim coverage that was never verified.
    Write-Verbose "Could not retrieve Teams protection policy rules - skipping rule exception check: $_"
    $ruleRetrievalError = $_.ToString()
}

if ($issues.Count -gt 0) {
    # A confirmed failure on one tag must not swallow an unconfirmed permission
    # on the other, or a rule-retrieval failure - the reader still needs to know
    # that second signal was never established, distinct from the confirmed
    # failure so it is not mistaken for one.
    $finding = ($issues + $warningIssues) -join '; '
    $failErrorParts = [System.Collections.Generic.List[string]]::new()
    if ($permissionWarnings.Count -gt 0) {
        $finding += ' Additionally, the following have an unconfirmed release permission rather than a confirmed failure: ' + ($permissionWarnings -join '; ') + '.'
        $failErrorParts.Add("Get-QuarantinePolicy did not return EndUserQuarantinePermissions.PermissionToRelease for: $($permissionWarnings -join '; ').")
    }
    if ($ruleRetrievalError) {
        $finding += " Additionally, the Teams protection policy rules could not be retrieved, so any recipient exceptions narrowing ZAP coverage are unverified rather than a confirmed failure: $ruleRetrievalError"
        $failErrorParts.Add($ruleRetrievalError)
    }
    $failErrorMessage = if ($failErrorParts.Count -gt 0) { $failErrorParts -join "`n" } else { $null }
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Fail -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding $finding `
        -Recommendation 'Enable ZAP for Teams: Set-TeamsProtectionPolicy -ZapEnabled $true. Ensure MalwareQuarantineTag and HighConfidencePhishQuarantineTag use AdminOnlyAccessPolicy or a custom policy with PermissionToRelease disabled.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap' `
        -ErrorMessage $failErrorMessage
}
elseif ($permissionWarnings.Count -gt 0) {
    $finding = ($permissionWarnings -join '; ') +
        '. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a quarantine policy that prevents self-release from one that allows it.'
    if ($warningIssues.Count -gt 0) {
        $finding += ' ' + ($warningIssues -join '; ')
    }
    $warningErrorParts = [System.Collections.Generic.List[string]]::new()
    $warningErrorParts.Add("Get-QuarantinePolicy did not return EndUserQuarantinePermissions.PermissionToRelease for: $($permissionWarnings -join '; ').")
    if ($ruleRetrievalError) {
        $finding += " Additionally, the Teams protection policy rules could not be retrieved, so any recipient exceptions narrowing ZAP coverage are unverified: $ruleRetrievalError"
        $warningErrorParts.Add($ruleRetrievalError)
    }
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Warning -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding $finding `
        -Recommendation 'Confirm the setting directly with: Get-QuarantinePolicy -Identity <tag name> | Select-Object -ExpandProperty EndUserQuarantinePermissions. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap' `
        -ErrorMessage ($warningErrorParts -join "`n")
}
elseif ($warningIssues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Warning -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding ($warningIssues -join '; ') `
        -Recommendation 'Review Teams protection policy rule exceptions (ExceptIfSentTo, ExceptIfSentToMemberOf, ExceptIfRecipientDomainIs) and remove any that are not intentional - excluded recipients do not benefit from ZAP for Teams.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap'
}
elseif ($ruleRetrievalError) {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Warning -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding 'ZAP for Teams is enabled and quarantine policies do not allow user self-release, but the Teams protection policy rules could not be read, so any recipient exceptions narrowing ZAP coverage are unverified.' `
        -Recommendation 'Rerun with a connected MicrosoftTeams session and Security Reader permissions, or review Get-TeamsProtectionPolicyRule exceptions manually.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap' -ErrorMessage $ruleRetrievalError
}
else {
    New-METCheckResult -CheckId 'MET-Teams004' -Category Teams -Name 'ZAP for Teams' `
        -Result Pass -Severity High -AffectedObject 'Teams Protection Policy' `
        -Finding 'ZAP for Teams is enabled and quarantine policies do not allow user self-release' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-zap'
}
