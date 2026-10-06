[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Call Reporting'
    Severity       = 'Medium'
    Description    = 'Checks ReportCall and SpamFilteringEnabledType across all Get-CsTeamsCallingPolicy instances, the closest native controls to helpdesk-vishing attacks over a Teams or PSTN call.'
    RequiresModule = @('MicrosoftTeams')
}

$issues = [System.Collections.Generic.List[string]]::new()

$referenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy'

try {
    $policies = @(Get-CsTeamsCallingPolicy -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'Unable to retrieve Teams calling policies.' `
        -Recommendation 'Ensure the account has Teams administrator or higher permissions.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

$withProperty    = @($policies | Where-Object { $null -ne $_.PSObject.Properties['ReportCall'] -and $null -ne $_.ReportCall })
$withoutProperty = @($policies | Where-Object { $null -eq $_.PSObject.Properties['ReportCall'] -or  $null -eq $_.ReportCall })

if ($withProperty.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'No Teams calling policy returned a ReportCall property, so whether users can report a suspicious call was not established for any policy. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with call reporting enabled from one with it switched off.' `
        -Recommendation 'Confirm the state directly (Get-CsTeamsCallingPolicy | Format-List Identity, ReportCall). If the property is absent there too, update the MicrosoftTeams module to a version that exposes it and re-run this check.' `
        -ReferenceUrl $referenceUrl `
        -ErrorMessage 'The ReportCall property was not returned by Get-CsTeamsCallingPolicy - the installed MicrosoftTeams module version may not expose it.'
}
else {
    $disabledPolicies = @($withProperty | Where-Object { $_.ReportCall -ne 'Enabled' })

    if ($disabledPolicies.Count -gt 0) {
        $names = ($disabledPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("Call reporting (ReportCall) is disabled in the following Teams calling policy/policies: $names - users assigned to these policies cannot report a suspicious call, such as a helpdesk-vishing attempt")
    }

    if ($withoutProperty.Count -gt 0) {
        $unknownNames = ($withoutProperty | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("The ReportCall property was not returned for the following Teams calling policy/policies: $unknownNames - call reporting was not established for the users they are assigned to")
    }

    $confirmNote = "Confirm the policies whose ReportCall property was not returned directly (Get-CsTeamsCallingPolicy -Identity <name> | Format-List ReportCall)."

    if ($disabledPolicies.Count -gt 0) {
        $recommendation = 'Set-CsTeamsCallingPolicy -Identity <name> -ReportCall Enabled'
        if ($withoutProperty.Count -gt 0) { $recommendation = "$recommendation. $confirmNote" }

        New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
            -Result Fail -Severity Medium -AffectedObject 'Teams Calling Policies' `
            -Finding ($issues -join '; ') `
            -Recommendation $recommendation `
            -ReferenceUrl $referenceUrl
    }
    elseif ($withoutProperty.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
            -Result Warning -Severity Medium -AffectedObject 'Teams Calling Policies' `
            -Finding ($issues -join '; ') `
            -Recommendation $confirmNote `
            -ReferenceUrl $referenceUrl
    }
    else {
        New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
            -Result Pass -Severity Medium -AffectedObject 'Teams Calling Policies' `
            -Finding 'Call reporting is enabled in all Teams calling policies, allowing users to report suspicious calls such as helpdesk-vishing attempts.' `
            -ReferenceUrl $referenceUrl
    }
}

$spamReferenceUrl = 'https://learn.microsoft.com/en-us/microsoftteams/configure-call-spam-filtering'

$spamWith    = @($policies | Where-Object { $null -ne $_.PSObject.Properties['SpamFilteringEnabledType'] -and "$($_.SpamFilteringEnabledType)" -ne '' })
$spamWithout = @($policies | Where-Object { $null -eq $_.PSObject.Properties['SpamFilteringEnabledType'] -or  "$($_.SpamFilteringEnabledType)" -eq '' })

if ($spamWith.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'PSTN Call Spam Filtering' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'No Teams calling policy returned a SpamFilteringEnabledType property, so whether inbound PSTN calls are screened for spam was not established for any policy. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with call spam filtering on from one with it switched off.' `
        -Recommendation 'Confirm the state directly (Get-CsTeamsCallingPolicy | Format-List Identity, SpamFilteringEnabledType). If the property is absent there too, update the MicrosoftTeams module and re-run this check.' `
        -ReferenceUrl $spamReferenceUrl `
        -ErrorMessage 'The SpamFilteringEnabledType property was not returned by Get-CsTeamsCallingPolicy - the installed MicrosoftTeams module version may not expose it.'
    return
}

$spamIssues   = [System.Collections.Generic.List[string]]::new()
$spamDisabled = @($spamWith | Where-Object { "$($_.SpamFilteringEnabledType)" -eq 'Disabled' })
$spamUnknown  = @($spamWith | Where-Object { "$($_.SpamFilteringEnabledType)" -ne 'Disabled' -and "$($_.SpamFilteringEnabledType)" -notlike 'Enabled*' })

if ($spamDisabled.Count -gt 0) {
    $names = ($spamDisabled | Select-Object -ExpandProperty Identity) -join ', '
    $spamIssues.Add("PSTN call spam filtering (SpamFilteringEnabledType) is disabled in the following Teams calling policy/policies: $names - users assigned to these policies get no Spam Likely warning on inbound phone calls, the delivery channel for helpdesk-vishing and callback-phishing follow-ups")
}
foreach ($policy in $spamUnknown) {
    $spamIssues.Add("SpamFilteringEnabledType returned the unrecognized value '$($policy.SpamFilteringEnabledType)' for $($policy.Identity) - call spam filtering was not established for the users it is assigned to")
}
if ($spamWithout.Count -gt 0) {
    $unknownNames = ($spamWithout | Select-Object -ExpandProperty Identity) -join ', '
    $spamIssues.Add("The SpamFilteringEnabledType property was not returned for the following Teams calling policy/policies: $unknownNames - call spam filtering was not established for the users they are assigned to")
}

if ($spamDisabled.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'PSTN Call Spam Filtering' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding ($spamIssues -join '; ') `
        -Recommendation 'Set-CsTeamsCallingPolicy -Identity <name> -SpamFilteringEnabledType Enabled' `
        -ReferenceUrl $spamReferenceUrl
}
elseif ($spamIssues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'PSTN Call Spam Filtering' `
        -Result Warning -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding ($spamIssues -join '; ') `
        -Recommendation 'Confirm the named policies directly (Get-CsTeamsCallingPolicy -Identity <name> | Format-List SpamFilteringEnabledType) and set -SpamFilteringEnabledType Enabled explicitly.' `
        -ReferenceUrl $spamReferenceUrl
}
else {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'PSTN Call Spam Filtering' `
        -Result Pass -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'PSTN call spam filtering is enabled in all Teams calling policies, so likely spam calls are labelled Spam Likely before the user answers.' `
        -ReferenceUrl $spamReferenceUrl
}
