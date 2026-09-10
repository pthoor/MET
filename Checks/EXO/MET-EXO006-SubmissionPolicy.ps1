try {
    $policy = Get-ReportSubmissionPolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO -Name 'User Reported Message Settings' `
        -Result Fail -Severity Medium -AffectedObject 'Report Submission Policy' `
        -Finding 'Unable to retrieve report submission policy.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings' -ErrorMessage $_.ToString()
    return
}

if (-not $policy) {
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO -Name 'User Reported Message Settings' `
        -Result Fail -Severity Medium -AffectedObject 'Report Submission Policy' `
        -Finding 'No report submission policy found.' `
        -Recommendation 'Configure user reported settings in the Defender portal: Settings > Email & collaboration > User reported settings.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    return
}

# Resolve the custom submission mailbox from the associated rule
$submissionMailbox = $null
$additionalMailboxes = @()
try {
    $rule = Get-ReportSubmissionRule -ErrorAction Stop
    if ($rule -and $rule.SentTo) {
        $ruleRecipients = @($rule.SentTo)
        $submissionMailbox = $ruleRecipients | Select-Object -First 1
        $additionalMailboxes = @($ruleRecipients | Select-Object -Skip 1)
    }
}
catch { Write-Verbose "Could not retrieve report submission rule: $_" }

$additionalMailboxNote = ''
if ($additionalMailboxes.Count -gt 0) {
    $additionalMailboxNote = " The rule also routes reports to $($additionalMailboxes -join ', '); only the first address is compared against the policy's own reporting addresses."
}

# ── Determine reporting mode from the combination of two flags ────────────────
# EnableReportToMicrosoft  EnableThirdPartyAddress  Meaning
# $true                    $false                   Built-in button → MS (+ optional custom mailbox)
# $true                    $true                    Third-party add-in → MS and custom mailbox
# $false                   $false (+ custom mbx)    Built-in tools, custom mailbox ONLY - MS gets nothing
# $false                   $true                    Third-party add-in → custom mailbox only; NOT in Defender Submissions
# $false                   $false (no custom mbx)   Reporting completely disabled
# (absent)                 any                      Reporting mode not returned - not confirmed disabled (see below)
# any                      (absent)                 Reporting mode not returned - not confirmed disabled (see below)
$reportToMicrosoftProperty = $policy.PSObject.Properties['EnableReportToMicrosoft']
$thirdPartyAddressProperty = $policy.PSObject.Properties['EnableThirdPartyAddress']
$reportToMicrosoftUnknown  = -not $reportToMicrosoftProperty -or $null -eq $reportToMicrosoftProperty.Value
$thirdPartyAddressUnknown  = -not $thirdPartyAddressProperty -or $null -eq $thirdPartyAddressProperty.Value
$reportingModeUnknown      = $reportToMicrosoftUnknown -or $thirdPartyAddressUnknown

$reportsToMicrosoft = -not $reportToMicrosoftUnknown -and $reportToMicrosoftProperty.Value -eq $true
$thirdPartyMode     = -not $thirdPartyAddressUnknown -and $thirdPartyAddressProperty.Value -eq $true
$junkToCustom       = $policy.ReportJunkToCustomizedAddress    -eq $true
$notJunkToCustom    = $policy.ReportNotJunkToCustomizedAddress -eq $true
$phishToCustom      = $policy.ReportPhishToCustomizedAddress   -eq $true
$allFlowsToCustom   = $junkToCustom -and $notJunkToCustom -and $phishToCustom
$anyFlowToCustom    = $junkToCustom -or  $notJunkToCustom -or  $phishToCustom
$reportingDisabled  = -not $reportsToMicrosoft -and -not $thirdPartyMode -and -not $anyFlowToCustom

# ── Check 1: Report button mode and Microsoft feedback loop ───────────────────
if ($reportingDisabled -and $reportingModeUnknown) {
    $unknownProps = [System.Collections.Generic.List[string]]::new()
    if ($reportToMicrosoftUnknown) { $unknownProps.Add('EnableReportToMicrosoft') }
    if ($thirdPartyAddressUnknown) { $unknownProps.Add('EnableThirdPartyAddress') }
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding "$($unknownProps -join ' and ') $(if ($unknownProps.Count -eq 1) { 'was' } else { 'were' }) not returned by the report submission policy, so whether user reporting in Outlook is enabled, and whether reports reach Microsoft or a SecOps mailbox, was not established." `
        -Recommendation "Confirm the setting directly with: Get-ReportSubmissionPolicy | Format-List EnableReportToMicrosoft, EnableThirdPartyAddress. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment. In the Defender portal go to Settings > Email & collaboration > User reported settings to confirm reporting is configured; the recommended configuration is the built-in Microsoft report button sending to both Microsoft and a custom SecOps mailbox." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings' `
        -ErrorMessage "Get-ReportSubmissionPolicy did not return $($unknownProps -join ' and ')."
}
elseif ($reportingDisabled) {
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'User reporting in Outlook is completely disabled. No report button is available to users and no messages reach Microsoft or a SecOps mailbox.' `
        -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable reporting. The recommended configuration is the built-in Microsoft report button sending to both Microsoft and a custom SecOps mailbox." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif ($thirdPartyMode -and -not $reportsToMicrosoft) {
    # Third-party add-in → custom mailbox only; submissions NOT visible in Defender portal
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'A non-Microsoft add-in is configured and "Send reported messages to Microsoft" is disabled. User-reported messages are not visible on the Submissions page in the Defender portal and Microsoft receives no feedback for threat analysis.' `
        -Recommendation "1. In the Defender portal go to Settings > Email & collaboration > User reported settings.`n2. Enable `"Send reported messages to Microsoft`" to make submissions visible in the Defender portal and restore the threat intelligence feedback loop.`n3. Alternatively switch to the built-in Microsoft report button." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif (-not $reportsToMicrosoft -and -not $thirdPartyMode -and $anyFlowToCustom) {
    # Built-in tools but reports go to custom mailbox ONLY - Microsoft is cut out
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'The built-in Outlook report button is active but "Send reported messages to Microsoft" is disabled. Reports reach the custom mailbox but Microsoft performs no analysis - the Submissions page in the Defender portal will be empty.' `
        -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable `"Send reported messages to Microsoft`"." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif ($thirdPartyMode -and $reportsToMicrosoft) {
    # Third-party add-in, reports go to both Microsoft and custom mailbox
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Warning -Severity Medium -AffectedObject 'Report Submission Policy' `
        -Finding 'A non-Microsoft add-in is in use and reports are forwarded to Microsoft. If the add-in stops forwarding or strips message metadata, the feedback loop breaks silently.' `
        -Recommendation 'Consider switching to the built-in Microsoft report button for a directly supported path. If keeping the add-in, verify it is current and that full message headers are preserved in forwarded copies.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif ($thirdPartyAddressUnknown) {
    # $reportsToMicrosoft is confirmed true here (the reportingDisabled/reportingModeUnknown
    # branch above already claimed every case where it wasn't), but whether the button is the
    # built-in one or a non-Microsoft add-in was never observed. Reaching the Pass sentence
    # below would assert "built-in" on a value this check did not confirm.
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result NotApplicable -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'EnableThirdPartyAddress was not returned by the report submission policy, so whether user reports come from the built-in Microsoft report button or a non-Microsoft add-in was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes the built-in report button from a third-party add-in, which needs its own verification that message headers are preserved.' `
        -Recommendation 'Confirm the setting directly with: Get-ReportSubmissionPolicy | Format-List EnableThirdPartyAddress. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings' `
        -ErrorMessage 'Get-ReportSubmissionPolicy did not return an EnableThirdPartyAddress value.'
}
else {
    # Built-in button, reports to Microsoft (with or without custom mailbox)
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings - Report Button' `
        -Result Pass -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'The built-in Microsoft report button is active and reports are sent to Microsoft for analysis.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}

# ── Check 2: SecOps mailbox routing ───────────────────────────────────────────
# Skip if reporting is completely disabled - covered by Check 1 already.
if (-not $reportingDisabled) {
    if (-not $anyFlowToCustom -or -not $submissionMailbox) {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - SecOps Mailbox' `
            -Result Warning -Severity Medium -AffectedObject 'Report Submission Policy' `
            -Finding 'No custom SecOps mailbox is configured. Your security team has no direct inbox copy of user-reported messages.' `
            -Recommendation "1. Create or designate a shared mailbox for security operations (e.g. secops-reports@contoso.com).`n2. In the Defender portal go to Settings > Email & collaboration > User reported settings.`n3. Enable the custom mailbox and route all three report types (Junk, Not Junk, Phishing) to it." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
    elseif (-not $allFlowsToCustom) {
        $missingFlows = @(
            if (-not $junkToCustom)    { 'Junk' }
            if (-not $notJunkToCustom) { 'Not Junk' }
            if (-not $phishToCustom)   { 'Phishing' }
        )
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - SecOps Mailbox' `
            -Result Warning -Severity Low -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "Custom mailbox '$submissionMailbox' is configured but the following report types are not routed to it: $($missingFlows -join ', ').$additionalMailboxNote" `
            -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable the custom mailbox for all three report types: Junk, Not Junk, and Phishing." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - SecOps Mailbox' `
            -Result Pass -Severity Medium -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "All three report flows (Junk, Not Junk, Phishing) are routed to the SecOps mailbox '$submissionMailbox'.$additionalMailboxNote" `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
}

# ── Check 3: User notification after review ───────────────────────────────────
if (-not $reportingDisabled -and $reportsToMicrosoft) {
    if (-not $policy.EnableUserEmailNotification) {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - User Notifications' `
            -Result Warning -Severity Low -AffectedObject 'Report Submission Policy' `
            -Finding 'User notification after submission review is disabled. Users receive no feedback when their reported messages are reviewed.' `
            -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable post-review user notifications." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - User Notifications' `
            -Result Pass -Severity Low -AffectedObject 'Report Submission Policy' `
            -Finding 'Users are notified after their submitted messages are reviewed.' `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
}

# ── Check 4: Rule/Policy mailbox address consistency ──────────────────────────
# Set-ReportSubmissionRule changes only the rule's SentTo; Microsoft's own docs
# note the parallel *Addresses fields on the policy are not auto-updated, so the
# two can silently drift onto different mailboxes for individual report types.
if (-not $reportingDisabled -and $submissionMailbox) {
    $addressMismatches = [System.Collections.Generic.List[string]]::new()

    if ($junkToCustom -and $policy.ReportJunkAddresses -and (@($policy.ReportJunkAddresses)[0] -ne $submissionMailbox)) {
        $addressMismatches.Add("Junk reports go to '$(@($policy.ReportJunkAddresses)[0])' instead of the rule's '$submissionMailbox'")
    }
    if ($notJunkToCustom -and $policy.ReportNotJunkAddresses -and (@($policy.ReportNotJunkAddresses)[0] -ne $submissionMailbox)) {
        $addressMismatches.Add("Not Junk reports go to '$(@($policy.ReportNotJunkAddresses)[0])' instead of the rule's '$submissionMailbox'")
    }
    if ($phishToCustom -and $policy.ReportPhishAddresses -and (@($policy.ReportPhishAddresses)[0] -ne $submissionMailbox)) {
        $addressMismatches.Add("Phishing reports go to '$(@($policy.ReportPhishAddresses)[0])' instead of the rule's '$submissionMailbox'")
    }
    if ($thirdPartyMode -and $policy.ThirdPartyReportAddresses -and (@($policy.ThirdPartyReportAddresses)[0] -ne $submissionMailbox)) {
        $addressMismatches.Add("Third-party add-in reports go to '$(@($policy.ThirdPartyReportAddresses)[0])' instead of the rule's '$submissionMailbox'")
    }

    if ($addressMismatches.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - Mailbox Address Consistency' `
            -Result Warning -Severity Low -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "The report submission rule and policy point at different mailboxes for at least one report type: $($addressMismatches -join '; '). This typically happens when Set-ReportSubmissionRule is used to change the reporting mailbox without also updating the matching *Addresses parameters on Set-ReportSubmissionPolicy." `
            -Recommendation "Run Set-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy -ReportJunkAddresses $submissionMailbox -ReportNotJunkAddresses $submissionMailbox -ReportPhishAddresses $submissionMailbox (add -ThirdPartyReportAddresses $submissionMailbox if using a non-Microsoft add-in) to bring the policy back in line with the rule." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-reportsubmissionpolicy'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings - Mailbox Address Consistency' `
            -Result Pass -Severity Low -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "The report submission rule and policy agree on the reporting mailbox for every report type in use." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-reportsubmissionpolicy'
    }
}
