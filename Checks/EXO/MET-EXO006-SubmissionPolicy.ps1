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
try {
    $rule = Get-ReportSubmissionRule -ErrorAction Stop
    if ($rule -and $rule.SentTo) { $submissionMailbox = $rule.SentTo }
}
catch { Write-Verbose "Could not retrieve report submission rule: $_" }

# ── Determine reporting mode from the combination of two flags ────────────────
# EnableReportToMicrosoft  EnableThirdPartyAddress  Meaning
# $true                    $false                   Built-in button → MS (+ optional custom mailbox)
# $true                    $true                    Third-party add-in → MS and custom mailbox
# $false                   $false (+ custom mbx)    Built-in tools, custom mailbox ONLY — MS gets nothing
# $false                   $true                    Third-party add-in → custom mailbox only; NOT in Defender Submissions
# $false                   $false (no custom mbx)   Reporting completely disabled
$reportsToMicrosoft = $policy.EnableReportToMicrosoft  -eq $true
$thirdPartyMode     = $policy.EnableThirdPartyAddress   -eq $true
$junkToCustom       = $policy.ReportJunkToCustomizedAddress    -eq $true
$notJunkToCustom    = $policy.ReportNotJunkToCustomizedAddress -eq $true
$phishToCustom      = $policy.ReportPhishToCustomizedAddress   -eq $true
$allFlowsToCustom   = $junkToCustom -and $notJunkToCustom -and $phishToCustom
$anyFlowToCustom    = $junkToCustom -or  $notJunkToCustom -or  $phishToCustom
$reportingDisabled  = -not $reportsToMicrosoft -and -not $thirdPartyMode -and -not $anyFlowToCustom

# ── Check 1: Report button mode and Microsoft feedback loop ───────────────────
if ($reportingDisabled) {
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings — Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'User reporting in Outlook is completely disabled. No report button is available to users and no messages reach Microsoft or a SecOps mailbox.' `
        -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable reporting. The recommended configuration is the built-in Microsoft report button sending to both Microsoft and a custom SecOps mailbox." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif ($thirdPartyMode -and -not $reportsToMicrosoft) {
    # Third-party add-in → custom mailbox only; submissions NOT visible in Defender portal
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings — Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'A non-Microsoft add-in is configured and "Send reported messages to Microsoft" is disabled. User-reported messages are not visible on the Submissions page in the Defender portal and Microsoft receives no feedback for threat analysis.' `
        -Recommendation "1. In the Defender portal go to Settings > Email & collaboration > User reported settings.`n2. Enable `"Send reported messages to Microsoft`" to make submissions visible in the Defender portal and restore the threat intelligence feedback loop.`n3. Alternatively switch to the built-in Microsoft report button." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif (-not $reportsToMicrosoft -and -not $thirdPartyMode -and $anyFlowToCustom) {
    # Built-in tools but reports go to custom mailbox ONLY — Microsoft is cut out
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings — Report Button' `
        -Result Fail -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'The built-in Outlook report button is active but "Send reported messages to Microsoft" is disabled. Reports reach the custom mailbox but Microsoft performs no analysis — the Submissions page in the Defender portal will be empty.' `
        -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable `"Send reported messages to Microsoft`"." `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
elseif ($thirdPartyMode -and $reportsToMicrosoft) {
    # Third-party add-in, reports go to both Microsoft and custom mailbox
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings — Report Button' `
        -Result Warning -Severity Medium -AffectedObject 'Report Submission Policy' `
        -Finding 'A non-Microsoft add-in is in use and reports are forwarded to Microsoft. If the add-in stops forwarding or strips message metadata, the feedback loop breaks silently.' `
        -Recommendation 'Consider switching to the built-in Microsoft report button for a directly supported path. If keeping the add-in, verify it is current and that full message headers are preserved in forwarded copies.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}
else {
    # Built-in button, reports to Microsoft (with or without custom mailbox)
    New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
        -Name 'User Reported Message Settings — Report Button' `
        -Result Pass -Severity High -AffectedObject 'Report Submission Policy' `
        -Finding 'The built-in Microsoft report button is active and reports are sent to Microsoft for analysis.' `
        -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
}

# ── Check 2: SecOps mailbox routing ───────────────────────────────────────────
# Skip if reporting is completely disabled — covered by Check 1 already.
if (-not $reportingDisabled) {
    if (-not $anyFlowToCustom -or -not $submissionMailbox) {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings — SecOps Mailbox' `
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
            -Name 'User Reported Message Settings — SecOps Mailbox' `
            -Result Warning -Severity Low -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "Custom mailbox '$submissionMailbox' is configured but the following report types are not routed to it: $($missingFlows -join ', ')." `
            -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable the custom mailbox for all three report types: Junk, Not Junk, and Phishing." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings — SecOps Mailbox' `
            -Result Pass -Severity Medium -AffectedObject "Report Submission Policy ($submissionMailbox)" `
            -Finding "All three report flows (Junk, Not Junk, Phishing) are routed to the SecOps mailbox '$submissionMailbox'." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
}

# ── Check 3: User notification after review ───────────────────────────────────
if (-not $reportingDisabled -and $reportsToMicrosoft) {
    if (-not $policy.EnableUserEmailNotification) {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings — User Notifications' `
            -Result Warning -Severity Low -AffectedObject 'Report Submission Policy' `
            -Finding 'User notification after submission review is disabled. Users receive no feedback when their reported messages are reviewed.' `
            -Recommendation "In the Defender portal go to Settings > Email & collaboration > User reported settings and enable post-review user notifications." `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO006' -Category EXO `
            -Name 'User Reported Message Settings — User Notifications' `
            -Result Pass -Severity Low -AffectedObject 'Report Submission Policy' `
            -Finding 'Users are notified after their submitted messages are reviewed.' `
            -ReferenceUrl 'https://aka.ms/mdo-user-reported-settings'
    }
}
