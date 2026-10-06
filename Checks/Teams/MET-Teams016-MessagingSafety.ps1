[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Teams Messaging Safety'
    Severity       = 'High'
    Description    = 'Checks the built-in Teams messaging safety settings on Get-CsTeamsMessagingConfiguration: weaponizable file type blocking (FileTypeCheck), malicious URL warnings (UrlReputationCheck), and user reporting of incorrect detections (ReportIncorrectSecurityDetections).'
    RequiresModule = @('MicrosoftTeams')
}

$referenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsmessagingconfiguration'

try {
    $config = Get-CsTeamsMessagingConfiguration -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams016' -Category Teams -Name 'Teams Messaging Safety' `
        -Result Fail -Severity High -AffectedObject 'Teams Messaging Configuration' `
        -Finding 'Unable to retrieve the Teams messaging configuration, so weaponizable file blocking, malicious URL warnings and incorrect-detection reporting were not assessed.' `
        -Recommendation 'Ensure the MicrosoftTeams module is installed and the account has Teams administrator or higher permissions, then re-run this check.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

$settings = @(
    @{
        Property       = 'FileTypeCheck'
        Severity       = 'High'
        DisabledResult = 'Fail'
        Feature        = 'weaponizable file type protection'
        Enabled        = 'Weaponizable file type protection is enabled (FileTypeCheck is Enabled) - Teams blocks chat and channel messages carrying file types commonly used to deliver malware, such as .exe, .iso, .lnk and .hta.'
        Disabled       = 'Weaponizable file type protection is disabled (FileTypeCheck is Disabled) - Teams delivers chat and channel messages carrying file types commonly used to deliver malware, such as .exe, .iso, .lnk and .hta. This is the built-in Teams control that works without a Defender for Office 365 licence, so on tenants without Safe Attachments for Teams it is the only file-type barrier in chat. In external conversations the protection still applies if any participating organization has it on, so the exposure is greatest in internal and unprotected-partner chats.'
        Recommendation = 'Run Set-CsTeamsMessagingConfiguration -Identity Global -FileTypeCheck Enabled, or turn on Scan messages for file types that are not allowed under Messaging settings > Messaging safety in the Teams admin center.'
    },
    @{
        Property       = 'UrlReputationCheck'
        Severity       = 'Medium'
        DisabledResult = 'Fail'
        Feature        = 'malicious URL protection'
        Enabled        = 'Malicious URL protection is enabled (UrlReputationCheck is Enabled) - Teams checks links in chat, channel and meeting messages against threat intelligence and warns the sender and recipients when a link is flagged.'
        Disabled       = 'Malicious URL protection is disabled (UrlReputationCheck is Disabled) - Teams does not warn senders or recipients about known-malicious URL links in chat, channel and meeting messages. This built-in warning works without a Defender for Office 365 licence and complements, but does not replace, Safe Links time-of-click blocking.'
        Recommendation = 'Run Set-CsTeamsMessagingConfiguration -Identity Global -UrlReputationCheck Enabled, or turn on Scan messages for unsafe URLs under Messaging settings > Messaging safety in the Teams admin center.'
    },
    @{
        Property       = 'ReportIncorrectSecurityDetections'
        Severity       = 'Low'
        DisabledResult = 'Warning'
        Feature        = 'reporting of incorrect security detections'
        Enabled        = 'Users can report incorrect security detections on Teams messages (ReportIncorrectSecurityDetections is Enabled), giving false positives from file and URL protection a route back to Microsoft.'
        Disabled       = 'Users cannot report incorrect security detections on Teams messages (ReportIncorrectSecurityDetections is Disabled). This does not weaken protection directly, but false positives from file and URL protection have no feedback route, which tends to build pressure to switch those protections off instead.'
        Recommendation = 'Run Set-CsTeamsMessagingConfiguration -Identity Global -ReportIncorrectSecurityDetections Enabled.'
    }
)

foreach ($setting in $settings) {
    $property = $setting.Property
    $affectedObject = "Teams Messaging Configuration ($property)"
    $value = $null
    if ($config -and $config.PSObject.Properties[$property]) { $value = $config.$property }

    if ($null -eq $value -or "$value" -eq '') {
        New-METCheckResult -CheckId 'MET-Teams016' -Category Teams -Name 'Teams Messaging Safety' `
            -Result NotApplicable -Severity $setting.Severity -AffectedObject $affectedObject `
            -Finding "The $property property was not returned by Get-CsTeamsMessagingConfiguration, so whether $($setting.Feature) is on was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with the protection on from one with it off. The setting is not available in GCC, GCC High or DoD, and older MicrosoftTeams module versions do not expose it." `
            -Recommendation "Confirm the state directly (Get-CsTeamsMessagingConfiguration | Format-List $property). If the property is absent outside a government cloud, update the MicrosoftTeams module and re-run this check." `
            -ReferenceUrl $referenceUrl `
            -ErrorMessage "The $property property was not returned by Get-CsTeamsMessagingConfiguration - the tenant cloud or the installed MicrosoftTeams module version may not expose it."
        continue
    }

    $text = "$value"
    if ($text -eq 'Enabled') {
        New-METCheckResult -CheckId 'MET-Teams016' -Category Teams -Name 'Teams Messaging Safety' `
            -Result Pass -Severity $setting.Severity -AffectedObject $affectedObject `
            -Finding $setting.Enabled `
            -ReferenceUrl $referenceUrl
    }
    elseif ($text -eq 'Disabled') {
        New-METCheckResult -CheckId 'MET-Teams016' -Category Teams -Name 'Teams Messaging Safety' `
            -Result $setting.DisabledResult -Severity $setting.Severity -AffectedObject $affectedObject `
            -Finding $setting.Disabled `
            -Recommendation $setting.Recommendation `
            -ReferenceUrl $referenceUrl
    }
    else {
        New-METCheckResult -CheckId 'MET-Teams016' -Category Teams -Name 'Teams Messaging Safety' `
            -Result Warning -Severity $setting.Severity -AffectedObject $affectedObject `
            -Finding "$property returned the unrecognized value '$text', so whether $($setting.Feature) is on was not established. Only Enabled and Disabled are documented values; an unrecognized value is reported as a gap rather than a pass." `
            -Recommendation "Review the setting (Get-CsTeamsMessagingConfiguration | Format-List $property) and set it explicitly. $($setting.Recommendation)" `
            -ReferenceUrl $referenceUrl
    }
}
