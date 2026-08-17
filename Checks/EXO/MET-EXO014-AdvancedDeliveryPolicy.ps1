function ConvertTo-METIPv4AddressValue {
    param([Parameter(Mandatory)][string] $IPAddressString)

    $bytes = [System.Net.IPAddress]::Parse($IPAddressString).GetAddressBytes()
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function Test-METSenderIpRangeIsBroad {
    param([Parameter(Mandatory)][string] $Entry)

    if ($Entry -match '^(?<ip>[\d.]+)/(?<prefix>\d{1,2})$') {
        return ([int]$Matches['prefix'] -le 16)
    }

    if ($Entry -match '^(?<start>[\d.]+)\s*-\s*(?<end>[\d.]+)$') {
        try {
            $startValue = ConvertTo-METIPv4AddressValue -IPAddressString $Matches['start'].Trim()
            $endValue = ConvertTo-METIPv4AddressValue -IPAddressString $Matches['end'].Trim()
            $addressCount = ([int64]$endValue - [int64]$startValue) + 1
            return ($addressCount -gt 65536)
        }
        catch {
            return $false
        }
    }

    return $false
}

$retrievalErrors = [System.Collections.Generic.List[string]]::new()

# Get-ExoPhishSimOverrideRule/Get-ExoSecOpsOverrideRule fail with a generic
# server-side error when the -ErrorAction parameter is bound at all (a known
# ExchangeOnlineManagement issue: https://learn.microsoft.com/answers/a/1859386).
# $ErrorActionPreference achieves the same Stop-on-error behavior without
# binding that parameter.
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {
    try { $phishSimulationRules = @(Get-ExoPhishSimOverrideRule) }
    catch {
        $phishSimulationRules = @()
        $retrievalErrors.Add("Phishing simulation overrides: $($_.ToString())")
    }

    try { $secOpsRules = @(Get-ExoSecOpsOverrideRule) }
    catch {
        $secOpsRules = @()
        $retrievalErrors.Add("SecOps mailbox overrides: $($_.ToString())")
    }
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

if ($retrievalErrors.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Fail -Severity Medium -AffectedObject 'Advanced Delivery Policy' `
        -Finding 'Unable to retrieve all Advanced Delivery override rules' `
        -Recommendation 'This check already avoids the known ExchangeOnlineManagement bug where binding -ErrorAction on Get-ExoPhishSimOverrideRule/Get-ExoSecOpsOverrideRule causes a spurious generic server-side error (https://learn.microsoft.com/answers/a/1859386) - a failure here is more likely a genuine issue. Confirm the account holds Global Reader or Security Reader (Email & collaboration RBAC) or View-Only Organization Management (Exchange Online RBAC) - the documented read permissions for the advanced delivery policy. If permissions are correct, retry with a fresh Connect-ExchangeOnline session before ruling out a transient Microsoft-side issue.' `
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
    foreach ($rule in $activePhishSimulationRules) { $ruleDescriptions.Add("Phishing simulation (domains: $(@($rule.Domains) -join ', '))") }
    foreach ($rule in $activeSecOpsRules) { $ruleDescriptions.Add("SecOps mailbox: $(@($rule.SentTo) -join ', ')") }

    $hasPhishSim = $activePhishSimulationRules.Count -gt 0
    $hasSecOps = $activeSecOpsRules.Count -gt 0

    if ($hasSecOps -and $hasPhishSim) {
        $scopeRecommendation = 'Advanced Delivery overrides are legitimate for narrowly scoped third-party phishing simulations and dedicated SecOps mailboxes, but their bypass surfaces differ. SecOps mailbox overrides bypass anti-malware filtering AND zero-hour auto purge (ZAP) for malware - malware filtering is bypassed for SecOps mailboxes only, the widest bypass Advanced Delivery grants. Phishing simulation overrides do NOT bypass malware filtering; they bypass spam/phish filtering, Safe Links time-of-click blocking (URLs are still wrapped but never blocked), Safe Attachments detonation, default alerts, and Automated Investigation and Response (AIR). Periodically verify every rule is still required and correctly scoped; stale simulation infrastructure or an unintended SecOps recipient creates a filtering-bypass path. Review scope at https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.'
    }
    elseif ($hasSecOps) {
        $scopeRecommendation = 'SecOps mailbox overrides bypass anti-malware filtering AND zero-hour auto purge (ZAP) for malware for the listed mailboxes only - malware filtering is bypassed for SecOps mailboxes only, the widest bypass Advanced Delivery grants. Periodically verify every listed mailbox still needs this exemption; an unintended or stale SecOps recipient creates a filtering-bypass path. Review scope at https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.'
    }
    else {
        $scopeRecommendation = 'Phishing simulation overrides do NOT bypass malware filtering; they bypass spam/phish filtering, Safe Links time-of-click blocking (URLs are still wrapped but never blocked), Safe Attachments detonation, default alerts, and Automated Investigation and Response (AIR). Periodically verify every rule is still required and correctly scoped to the simulation vendor''s published sending infrastructure; stale simulation infrastructure creates a filtering-bypass path. Review scope at https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.'
    }

    New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy' `
        -Result Info -Severity Medium -AffectedObject "Advanced Delivery Policy ($activeCount override rule(s))" `
        -Finding "$activeCount enforceable Advanced Delivery override rule(s) found: $($ruleDescriptions -join '; ') - matching messages bypass significant MDO/EOP filtering and ZAP actions" `
        -Recommendation $scopeRecommendation `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
}

foreach ($rule in $activeSecOpsRules) {
    $sentToCount = @($rule.SentTo).Count
    if ($sentToCount -gt 2) {
        $sentToList = @($rule.SentTo) -join ', '
        New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy - SecOps Mailbox Scope' `
            -Result Warning -Severity Medium -AffectedObject "SecOps mailboxes: $sentToList" `
            -Finding "The SecOps override lists $sentToCount mailboxes in SentTo: $sentToList. Every mailbox in that list has anti-malware filtering and malware ZAP fully bypassed. This count is a MET-authored heuristic, not a Microsoft-documented limit - confirm the blast radius is still deliberate. Microsoft already blocks distribution groups as SentTo targets, so this only catches individually-added mailboxes, not group-based scope creep." `
            -Recommendation "Review the SecOps mailbox list ($sentToList) and remove any mailbox that no longer needs the malware-filtering bypass. Run Get-ExoSecOpsOverrideRule | Select-Object -ExpandProperty SentTo to view current scope, then Set-SecOpsOverridePolicy -Identity SecOpsOverridePolicy -RemoveSentTo <mailbox> to narrow it." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
    }
}

foreach ($rule in $activePhishSimulationRules) {
    $broadEntries = @($rule.SenderIpRanges | Where-Object { $_ -and (Test-METSenderIpRangeIsBroad -Entry $_) })
    if ($broadEntries.Count -gt 0) {
        $domainList = @($rule.Domains) -join ', '
        New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy - Phishing Simulation Sender Scope' `
            -Result Warning -Severity Medium -AffectedObject "Phishing simulation override (domains: $domainList)" `
            -Finding "The phishing simulation override for domain(s) $domainList includes overly broad SenderIpRanges entries: $($broadEntries -join ', '). Microsoft's own guidance warns that overly broad sending infrastructure here effectively bypasses spam filtering for any internet sender who impersonates the domain specified." `
            -Recommendation "Narrow SenderIpRanges on the override for $domainList to the specific IP addresses or CIDR ranges published by the simulation vendor - avoid CIDR blocks wider than /16 and explicit ranges spanning more than 65,536 addresses. Run Get-ExoPhishSimOverrideRule | Set-ExoPhishSimOverrideRule -RemoveSenderIpRanges <range> to remove an overly broad entry." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
    }
}

try {
    $reportPolicy = Get-ReportSubmissionPolicy -ErrorAction Stop
    $reportRule = Get-ReportSubmissionRule -ErrorAction Stop

    $reportsToMicrosoft = $reportPolicy.EnableReportToMicrosoft -eq $true
    $anyFlowToCustom = $reportPolicy.ReportJunkToCustomizedAddress -eq $true -or
        $reportPolicy.ReportNotJunkToCustomizedAddress -eq $true -or
        $reportPolicy.ReportPhishToCustomizedAddress -eq $true

    $reportingMailbox = $null
    if ($reportRule -and $reportRule.SentTo) { $reportingMailbox = @($reportRule.SentTo) | Select-Object -First 1 }

    # Every mailbox actually receiving reported messages needs SecOps coverage,
    # not just the rule's primary SentTo address - a per-flow policy address
    # that has drifted from the rule (see MET-EXO006's rule/policy consistency
    # check) would otherwise go unchecked even though real reports land there.
    $activeReportAddresses = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $addReportAddress = {
        param($Address, $Label)
        if (-not $Address) { return }
        if (-not $activeReportAddresses.ContainsKey($Address)) {
            $activeReportAddresses[$Address] = [System.Collections.Generic.List[string]]::new()
        }
        $activeReportAddresses[$Address].Add($Label)
    }

    if ($reportingMailbox -and ($reportsToMicrosoft -or $anyFlowToCustom)) {
        & $addReportAddress $reportingMailbox 'report submission rule'
    }
    if ($reportPolicy.ReportJunkToCustomizedAddress -eq $true) {
        & $addReportAddress (@($reportPolicy.ReportJunkAddresses) | Select-Object -First 1) 'Junk reports'
    }
    if ($reportPolicy.ReportNotJunkToCustomizedAddress -eq $true) {
        & $addReportAddress (@($reportPolicy.ReportNotJunkAddresses) | Select-Object -First 1) 'Not Junk reports'
    }
    if ($reportPolicy.ReportPhishToCustomizedAddress -eq $true) {
        & $addReportAddress (@($reportPolicy.ReportPhishAddresses) | Select-Object -First 1) 'Phishing reports'
    }
    if ($reportPolicy.EnableThirdPartyAddress -eq $true) {
        & $addReportAddress (@($reportPolicy.ThirdPartyReportAddresses) | Select-Object -First 1) 'third-party add-in reports'
    }

    $secOpsSentTo = @($activeSecOpsRules | ForEach-Object { $_.SentTo } | Where-Object { $_ })

    if ($activeReportAddresses.Count -gt 0) {
        $uncovered = @($activeReportAddresses.Keys | Where-Object { @($secOpsSentTo) -inotcontains $_ })

        if ($uncovered.Count -gt 0) {
            $uncoveredDescriptions = $uncovered | ForEach-Object { "'$_' ($($activeReportAddresses[$_] -join ', '))" }
            New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy - Reporting Mailbox Coverage' `
                -Result Warning -Severity Medium -AffectedObject "Reporting mailbox(es): $($uncovered -join ', ')" `
                -Finding "The following user-reported message mailbox(es) are not covered by a SecOps mailbox override: $($uncoveredDescriptions -join '; '). Reported messages sent to these mailboxes are filtered (and potentially defanged) before your security team reviews the original message, and simulated-phish reports submitted by users can incorrectly trigger training assignments." `
                -Recommendation "Add the missing mailbox(es) to the SecOps override policy: Set-SecOpsOverridePolicy -Identity SecOpsOverridePolicy -AddSentTo $($uncovered -join ',')" `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox'
        }
    }

    # The reverse direction is not a documented Microsoft requirement - a SecOps
    # mailbox can legitimately exist for reasons other than the reporting flow
    # (e.g. a security team member manually reviewing forwarded samples) - so
    # this is an Info nudge to confirm intent, not a Warning misconfiguration.
    if ($secOpsSentTo.Count -gt 0) {
        $unlinked = @($secOpsSentTo | Where-Object { -not $activeReportAddresses.ContainsKey($_) })
        if ($unlinked.Count -gt 0) {
            New-METCheckResult -CheckId 'MET-EXO014' -Category EXO -Name 'Advanced Delivery Policy - SecOps Mailbox Purpose' `
                -Result Info -Severity Low -AffectedObject "SecOps mailbox(es): $($unlinked -join ', ')" `
                -Finding "The following SecOps mailbox(es) are not tied to any user-reported-message flow in the report submission policy/rule: $($unlinked -join ', '). This is not a documented misconfiguration - a SecOps mailbox can exist for other purposes (e.g. a security team member manually reviewing forwarded samples) - but every message delivered to it still bypasses anti-malware filtering, so confirm the purpose is still intentional." `
                -Recommendation 'If this mailbox should be receiving user-reported messages, add it via Set-ReportSubmissionRule/-Policy. If it is intentionally used for another purpose, no action is needed - just confirm it still needs the malware-filtering bypass.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox'
        }
    }
}
catch { Write-Verbose "Could not evaluate reporting mailbox / SecOps override coverage: $_" }
