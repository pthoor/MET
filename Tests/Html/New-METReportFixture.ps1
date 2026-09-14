<#
.SYNOPSIS
    Generates an HTML report fixture for the Playwright browser tests.

.DESCRIPTION
    Invoked by the Playwright global setup so every browser run exercises the CURRENT
    Get-METReport generator instead of a stale checked-in HTML file. Nothing here is
    committed - the generated file lives under Tests/Html/.tmp/ which is git-ignored.

.PARAMETER Scenario
    Rich           - a nine-check result set spanning MDO/EXO/Teams and every Result value.
    Single         - a single check (exercises the one-element JSON serialisation path).
    Empty          - no checks at all.
    RepeatedCheckId - three MET-EXO004 results with distinct AffectedObject values, all Fail
                       (risk acceptance is keyed on the result, not the CheckId).
    ErrorBuckets   - one clean Fail, one clean Warning, and one result in every Result
                       bucket carrying a populated Error field. Error is mutually exclusive
                       with every Result-based bucket, so only the two clean results may
                       appear under Fail/Warning and the donut must show three segments.
    ErrorWithRecommendation - a single Fail carrying both a populated Error (the check
                       itself failed to run) and a populated Recommendation. Regression
                       fixture for G-2: the two must render together, not the recommendation
                       being discarded because an error is present.
    SameAffectedObject - three MET-EXO006 results sharing both CheckId AND AffectedObject
                       (the real-world shape - EXO006's ten sections all use AffectedObject
                       'Report Submission Policy'), distinguished only by Name. Regression
                       fixture for the residual collision: CheckId + AffectedObject alone
                       is not a unique key.
    InfoOnly       - every result is Info (Score = $null). Nothing is scorable, but unlike
                       Empty the CHECKS array is non-empty - exercises the band-band-on-load
                       path for an unscorable-but-nonempty result set.
    FailPlusInfo   - one scorable Fail plus an Info result. Accepting the Fail's risk in the
                       browser leaves nothing scorable, which is the live client-side path
                       (recalcScore/bandOf) that produced a false Critical band before the
                       'None' band existed on that side too.
    LongFinding    - one Fail with a short Finding and one Fail with a 1600+ character
                       Finding. Regression fixture for G-6: the Top 5 row for the long
                       Finding must stay clamped to roughly the short row's height instead
                       of expanding to fit the whole text.
    RankingBySum   - three MET-EXO004 Medium-severity Fails (weight 10 each, summing to 30)
                       plus a single MET-MDO001 High-severity Fail (weight 20). Regression
                       fixture for G-5: proves Top 5 ranks groups by the SUM of member
                       severity weights, not by the single highest per-item severity in a
                       group (which would rank the Medium group below the lone High result).
    DesignHierarchy - regression fixture for G-13 item 2/9 (result, not severity, drives a
                       card's visual weight): a Pass at Critical severity, a Fail at
                       Informational severity, and a NotApplicable-with-Error at Critical
                       severity - the combinations that would be indistinguishable, or
                       actively misleading, under the old severity-driven left border.
    UnknownCategory  - one MDO check plus one check carrying a Category outside MDO/EXO/Teams.
                       Regression fixture for G-14 item 3: the All Controls table and its
                       tc-controls tab badge must agree on the total even when a category
                       isn't one of the three MET ships today.
    NullFields       - a check with null Name, AffectedObject and Finding. Regression fixture
                       for G-14 item 6: a null field must not render a labelled .card-field
                       with nothing under it, and a null Name must fall back to the CheckId
                       as the card title.
    CoverageTable    - a check carrying EffectivePolicyCoverage Metadata, the same shape
                       New-METEffectivePolicyCoverageResult emits. Regression fixture for
                       G-14 item 7: the coverage table must render inside a block container,
                       not nested inside a <span class="field-value">.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputFile,

    [Parameter()]
    [ValidateSet('Rich', 'Single', 'Empty', 'Hostile', 'RepeatedCheckId', 'SameAffectedObject', 'ErrorBuckets', 'ErrorWithRecommendation', 'InfoOnly', 'FailPlusInfo', 'LongFinding', 'RankingBySum', 'DesignHierarchy', 'UnknownCategory', 'NullFields', 'CoverageTable')]
    [string] $Scenario = 'Rich'
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force

function New-FixtureResult {
    param(
        [string] $CheckId, [string] $Category, [string] $Name, [string] $Result,
        [string] $Severity, [object] $Score, [string] $AffectedObject, [string] $Finding,
        [string] $Recommendation = '', [string] $ReferenceUrl = '', [string] $ErrorText = $null,
        [object] $Metadata = $null
    )
    [PSCustomObject]@{
        CheckId        = $CheckId
        Category       = $Category
        Name           = $Name
        Result         = $Result
        Severity       = $Severity
        Score          = $Score
        AffectedObject = $AffectedObject
        Finding        = $Finding
        Recommendation = $Recommendation
        ReferenceUrl   = $ReferenceUrl
        Timestamp      = [datetime]::new(2026, 6, 1, 14, 32, 0, [System.DateTimeKind]::Utc)
        Error          = $ErrorText
        Metadata       = $Metadata
    }
}

$fixtures = switch ($Scenario) {
    'Empty' { @() }

    # Every field a check can populate, carrying a payload crafted for the sink it
    # reaches: an https URL that closes the href attribute, and enum values that close
    # a class attribute. Both survive scheme validation and .toLowerCase() respectively.
    'Hostile' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Href breakout <img src=n1 onerror="window.__xssName=1">' `
                -Result 'Fail' -Severity 'High' -Score 0 `
                -AffectedObject 'Policy "><img src=n2 onerror="window.__xssAffected=1">' `
                -Finding 'Finding "><img src=n3 onerror="window.__xssFinding=1">' `
                -Recommendation 'Recommendation "><img src=n4 onerror="window.__xssRec=1">' `
                -ReferenceUrl 'https://x.example/"><img src=n5 onerror="window.__xssHref=1">'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO"><img src=n6 onerror="window.__xssCat=1">' `
                -Name 'Class breakout' -Result 'Warning' -Severity 'Medium"><img src=n7 onerror="window.__xssSev=1">' `
                -Score 50 -AffectedObject 'Domain' -Finding 'Class attribute payload' `
                -Recommendation 'none' -ReferenceUrl 'https://aka.ms/dmarc'

            New-FixtureResult -CheckId 'MET-Teams003' -Category 'Teams' -Name 'Errored with payload' `
                -Result 'NotApplicable' -Severity 'Low' -Score $null -AffectedObject 'Teams' `
                -Finding 'Check could not run' `
                -ErrorText 'Error "><img src=n8 onerror="window.__xssError=1">'

            # Scheme-based payloads: neither survives safeHref's allow-list, and neither may
            # ever reach the document as a live href - clicking one executes in the report's
            # own origin, where the reader's risk-acceptance justifications live.
            New-FixtureResult -CheckId 'MET-EXO010' -Category 'EXO' -Name 'Javascript URI reference' `
                -Result 'Fail' -Severity 'High' -Score 0 -AffectedObject 'Direct Send' `
                -Finding 'Reference URL carries a script scheme' -Recommendation 'none' `
                -ReferenceUrl 'javascript:window.__xssJsUri=1'

            New-FixtureResult -CheckId 'MET-EXO011' -Category 'EXO' -Name 'Data URI reference' `
                -Result 'Warning' -Severity 'Low' -Score 50 -AffectedObject 'Connector' `
                -Finding 'Reference URL carries a data scheme' -Recommendation 'none' `
                -ReferenceUrl 'data:text/html,<script>window.__xssDataUri=1</script>'
        )
    }

    # Error is its own bucket in both the server-rendered banner and renderDonut(): a result
    # carrying an Error belongs to it and to nothing else. Five of these seven results pair a
    # populated Error with a different Result value - deliberately including combinations a
    # real check would not emit (Pass with an Error), because the point is that the bucket
    # exclusion is driven by the Error field alone and not by the Result it happens to carry.
    'ErrorBuckets' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Clean Fail' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' `
                -Recommendation 'Enable Safe Links for email.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'

            New-FixtureResult -CheckId 'MET-MDO002' -Category 'MDO' -Name 'Fail that failed to run' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Safe Attachments' `
                -Finding 'Retrieval failed' -ErrorText 'Get-SafeAttachmentPolicy threw'

            New-FixtureResult -CheckId 'MET-MDO009' -Category 'MDO' -Name 'Clean Warning' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'All anti-spam policies' `
                -Finding 'ZAP is enabled for spam but not for phish' `
                -Recommendation 'Enable ZAP for phish.'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'Warning that failed to run' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'contoso.com' `
                -Finding 'Retrieval failed' -ErrorText 'Resolve-DnsName threw'

            New-FixtureResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Pass that failed to run' -Result 'Pass' `
                -Severity 'High' -Score 100 -AffectedObject 'Mail flow rules' `
                -Finding 'Partial retrieval' -ErrorText 'Get-TransportRule threw'

            New-FixtureResult -CheckId 'MET-Teams003' -Category 'Teams' -Name 'NotApplicable that failed to run' `
                -Result 'NotApplicable' -Severity 'Medium' -Score $null -AffectedObject 'Meeting policies' `
                -Finding 'MicrosoftTeams module unavailable' -ErrorText 'Get-CsTeamsMeetingPolicy threw'

            New-FixtureResult -CheckId 'MET-Teams006' -Category 'Teams' -Name 'Info that failed to run' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Tenant federation configuration' `
                -Finding 'Partial retrieval' -ErrorText 'Get-CsTenantFederationConfiguration threw'
        )
    }

    # G-2: the recommendation must survive alongside the error banner - a check that failed
    # to run because of a permission gap still needs to tell the operator how to fix that gap.
    'ErrorWithRecommendation' {
        @(
            New-FixtureResult -CheckId 'MET-EXO011' -Category 'EXO' -Name 'Mail Flow Connector Hygiene' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Inbound connectors' `
                -Finding 'Retrieval failed' `
                -Recommendation 'Re-run with a Security Reader role.' `
                -ErrorText "The term 'Get-InboundConnector' is not recognized as the name of a cmdlet."
        )
    }

    'RepeatedCheckId' {
        @(
            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy A' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'

            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy B' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'

            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy C' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'
        )
    }

    'SameAffectedObject' {
        @(
            New-FixtureResult -CheckId 'MET-EXO006' -Category 'EXO' -Name 'Non-Microsoft Report Add-in' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Report Submission Policy' `
                -Finding 'User reports are routed through a third-party add-in, not the built-in Microsoft report button' `
                -Recommendation 'Review whether the non-Microsoft reporting flow still meets requirements.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox'

            New-FixtureResult -CheckId 'MET-EXO006' -Category 'EXO' -Name 'SecOps Mailbox Routing' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Report Submission Policy' `
                -Finding 'No custom SecOps mailbox configured for reported messages' `
                -Recommendation 'Configure a SecOps review mailbox for Junk/Not Junk/Phishing reports.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox'

            New-FixtureResult -CheckId 'MET-EXO006' -Category 'EXO' -Name 'User Post-Review Notifications' -Result 'Warning' `
                -Severity 'Low' -Score 50 -AffectedObject 'Report Submission Policy' `
                -Finding 'Users are not notified of the outcome after reporting a message' `
                -Recommendation 'Enable post-review notifications so users learn the result of their report.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox'
        )
    }

    'Single' {
        @(
            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'DMARC policy is set to none' `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'
        )
    }

    # Nothing scorable anywhere in the set (every Score is $null), but the CHECKS array is
    # non-empty - distinct from Empty, which exercises the zero-element serialisation path.
    'InfoOnly' {
        @(
            New-FixtureResult -CheckId 'MET-EXO016' -Category 'EXO' -Name 'ARC Trusted Sealers' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Tenant' `
                -Finding 'No trusted sealers configured'

            New-FixtureResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Transport Rule Audit' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Mail flow rules' `
                -Finding 'Two rules bypass spam filtering'
        )
    }

    # One scorable Fail plus an Info result. Accepting the Fail's risk client-side removes
    # the only scorable result, which must rescore the band to None, not Critical.
    'FailPlusInfo' {
        @(
            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'DMARC policy is set to none' `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'

            New-FixtureResult -CheckId 'MET-EXO016' -Category 'EXO' -Name 'ARC Trusted Sealers' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Tenant' `
                -Finding 'No trusted sealers configured'
        )
    }

    'RankingBySum' {
        @(
            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy A' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'

            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy B' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'

            New-FixtureResult -CheckId 'MET-EXO004' -Category 'EXO' -Name 'Quarantine Policies' -Result 'Fail' `
                -Severity 'Medium' -Score 0 -AffectedObject 'Policy C' `
                -Finding 'ESNEnabled is false but end users have release permission' `
                -Recommendation 'Enable end-user spam notifications or remove the release permission.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/quarantine-policies'

            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' `
                -Recommendation 'Enable Safe Links for email.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'
        )
    }

    'LongFinding' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email.' `
                -Recommendation 'Enable Safe Links for email.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'Critical' -Score 0 -AffectedObject 'contoso.com' `
                -Finding (('DMARC policy is set to none, which means no enforcement action is taken against spoofed mail failing authentication checks. ' * 20).Trim()) `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'
        )
    }

    'DesignHierarchy' {
        @(
            New-FixtureResult -CheckId 'MET-MDO009' -Category 'MDO' -Name 'Zero-Hour Auto Purge' -Result 'Pass' `
                -Severity 'Critical' -Score 100 -AffectedObject 'All anti-spam policies' `
                -Finding 'Auto purge of delivered mail is enabled everywhere' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge'

            New-FixtureResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Transport Rule Audit' -Result 'Fail' `
                -Severity 'Informational' -Score 0 -AffectedObject 'Mail flow rules' `
                -Finding 'Two rules bypass spam filtering' `
                -Recommendation 'Review the two rules that set SCL to -1.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/anti-spam-policies-configure'

            New-FixtureResult -CheckId 'MET-Teams014' -Category 'Teams' -Name 'Cross-Tenant Access' -Result 'NotApplicable' `
                -Severity 'Critical' -Score $null -AffectedObject 'Cross-tenant access policy' `
                -Finding 'Microsoft Graph is not connected' `
                -ErrorText 'Authentication needed. Please call Connect-MgGraph.'
        )
    }

    'UnknownCategory' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' `
                -Recommendation 'Enable Safe Links for email.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'

            New-FixtureResult -CheckId 'MET-XYZ001' -Category 'Compliance' -Name 'Retention Label Coverage' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Tenant' `
                -Finding 'Not every mailbox has a retention label applied'
        )
    }

    # A null Name/AffectedObject/Finding must not render a labelled field with nothing under
    # it, and a null Name must fall back to the CheckId as the card title (G-14 item 6).
    'NullFields' {
        @(
            New-FixtureResult -CheckId 'MET-EXO099' -Category 'EXO' -Name $null -Result 'Warning' `
                -Severity 'Low' -Score 50 -AffectedObject $null -Finding $null `
                -Recommendation 'Investigate why this check returned no descriptive fields.'
        )
    }

    # Metadata shape mirrors New-METEffectivePolicyCoverageResult - the coverage table must
    # render inside a block container, not a <span class="field-value"> (G-14 item 7).
    'CoverageTable' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Effective Coverage' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Tenant (2 mailboxes)' `
                -Finding "1 of 2 mailboxes meet the Safe Links baseline; 1 receives an effective policy below baseline.`nPolicy coverage:`nDefault Policy | Type: Custom | Scope: All recipients | Effective subjects: 1 of 2 | Configuration: Below baseline | Impact: Affects 1 subject(s)" `
                -Recommendation 'Enable Safe Links on the effective policy for the affected mailbox.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about' `
                -Metadata @{
                    DetailType              = 'EffectivePolicyCoverage'
                    ProtectionType          = 'Safe Links'
                    TotalRecipients         = 2
                    CompliantRecipients     = 1
                    CoverageRecommendations = @('Enable Safe Links on Default Policy.')
                    Policies                = @(
                        @{
                            PolicyName              = 'Default Policy'
                            PolicyType              = 'Custom'
                            State                    = 'Enabled'
                            Priority                 = 0
                            Scope                    = 'All recipients'
                            EffectiveRecipientCount = 1
                            ConfigurationStatus     = 'Below baseline'
                            CurrentImpact           = 'Affects 1 subject(s)'
                            OrderingObservations    = @()
                            Issues                   = @('Safe Links is disabled for email')
                        }
                    )
                }
        )
    }

    default {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' `
                -Recommendation "Open the Defender portal.`nEdit the Safe Links policy.`nEnable Safe Links for email." `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'

            New-FixtureResult -CheckId 'MET-MDO002' -Category 'MDO' -Name 'Safe Attachments Policy' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Marketing Attachments Policy' `
                -Finding 'Action is set to Monitor rather than Block' `
                -Recommendation 'Set the Safe Attachments action to Block.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-attachments-about'

            New-FixtureResult -CheckId 'MET-MDO009' -Category 'MDO' -Name 'Zero-Hour Auto Purge' -Result 'Pass' `
                -Severity 'High' -Score 100 -AffectedObject 'All anti-spam policies' `
                -Finding 'Auto purge of delivered mail is enabled everywhere' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'Critical' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'DMARC policy is set to none' `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'

            New-FixtureResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Transport Rule Audit' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Mail flow rules' `
                -Finding 'Two rules bypass spam filtering'

            New-FixtureResult -CheckId 'MET-EXO012' -Category 'EXO' -Name 'Mailbox Forwarding' -Result 'Pass' `
                -Severity 'Low' -Score 100 -AffectedObject 'finance@contoso.com' `
                -Finding 'No silent external forwarding configured'

            New-FixtureResult -CheckId 'MET-Teams003' -Category 'Teams' -Name 'Meeting Protection' -Result 'Warning' `
                -Severity 'High' -Score 50 -AffectedObject 'Global meeting policy' `
                -Finding 'Anonymous participants bypass the lobby' `
                -Recommendation 'Restrict lobby bypass to people in the organization.' `
                -ReferenceUrl 'https://learn.microsoft.com/microsoftteams/settings-policies-reference'

            New-FixtureResult -CheckId 'MET-Teams006' -Category 'Teams' -Name 'External Access Federation' -Result 'Pass' `
                -Severity 'Medium' -Score 100 -AffectedObject 'Tenant federation configuration' `
                -Finding 'Federation is limited to an explicit allow list'

            New-FixtureResult -CheckId 'MET-Teams014' -Category 'Teams' -Name 'Cross-Tenant Access' -Result 'NotApplicable' `
                -Severity 'Medium' -Score $null -AffectedObject 'Cross-tenant access policy' `
                -Finding 'Microsoft Graph is not connected' `
                -ErrorText 'Authentication needed. Please call Connect-MgGraph.'
        )
    }
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ('met-html-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    $fixtures | Get-METReport -Format HTML -OutputPath $staging -TenantName 'contoso.onmicrosoft.com' -NoLaunch | Out-Null

    $generated = Get-ChildItem -Path $staging -Recurse -Filter '*.html' | Select-Object -First 1
    if (-not $generated) {
        throw "Get-METReport did not produce an HTML file under $staging"
    }

    $destinationFolder = Split-Path -Path $OutputFile -Parent
    if ($destinationFolder -and -not (Test-Path $destinationFolder)) {
        New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
    }

    Copy-Item -Path $generated.FullName -Destination $OutputFile -Force
    Write-Output $OutputFile
}
finally {
    Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
}
