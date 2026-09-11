[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Call Reporting'
    Severity       = 'Medium'
    Description    = 'Checks ReportCall across all Get-CsTeamsCallingPolicy instances, the closest native control to helpdesk-vishing attacks over a Teams call.'
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
    return
}

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
