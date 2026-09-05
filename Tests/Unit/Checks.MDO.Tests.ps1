BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METSafeLinksEffectivePolicy.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    # Stub EXO cmdlets so Pester's Mock can override them
    function Get-SafeLinksPolicy               { [CmdletBinding()] param() }
    function Get-SafeLinksRule                 { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule       { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule       { [CmdletBinding()] param([string]$Identity) }
    function Get-EXOMailbox                    { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-SafeAttachmentPolicy          { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule            { [CmdletBinding()] param() }
    function Get-AtpPolicyForO365              { [CmdletBinding()] param() }
    function Get-AntiPhishPolicy               { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy           { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy     { [CmdletBinding()] param() }
    function Get-HostedContentFilterRule       { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() }
}

Describe 'MET-MDO001 Safe Links' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO001-SafeLinks.ps1'
        Mock Get-EXOMailbox { [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com' } }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    Context 'When all Safe Links settings are correctly configured' {
        BeforeAll {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $true
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $false
                }
            }
        }

        It 'Returns a Pass result' {
            $results = & $checkFile
            $results | Should -Not -BeNullOrEmpty
            $results[0].Result | Should -Be 'Pass'
            $results[0].CheckId | Should -Be 'MET-MDO001'
        }
    }

    Context 'When Safe Links for email is disabled' {
        BeforeAll {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $false
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $false
                }
            }
        }

        It 'Returns a Fail because the effective policy is below baseline' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }

        It 'Finding mentions email being disabled' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'email'
        }
    }

    Context 'When no Safe Links policies exist' {
        BeforeAll {
            Mock Get-SafeLinksPolicy { @() }
        }

        It 'Returns a Warning because effective coverage cannot be resolved' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
        }
    }

    Context 'When Get-SafeLinksPolicy throws' {
        BeforeAll {
            Mock Get-SafeLinksPolicy { throw 'Unauthorized' }
        }

        It 'Returns a Warning result with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # A Safe Links policy object that returns none of the settings the check reads is
    # indistinguishable, to a -not test, from one that has every setting switched off.
    Context 'The effective Safe Links policy omits every setting the check reads' {
        BeforeAll {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy' }
            }
        }

        It 'Does not return Pass on settings it never observed' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
        }

        # Pins current behaviour, whose wording is wrong: the check reports each setting
        # as disabled on the strength of properties Exchange Online never returned. The
        # verdict is fail-closed and safe, but the sentence states an observation that was
        # not made. Left pinned rather than corrected here so the defect is visible and
        # cannot change unnoticed.
        It 'Currently states each setting is disabled rather than that it was not returned' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Safe Links for email is disabled'
            $results[0].Finding | Should -Match 'Real-time URL scanning is disabled'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }

    # AllowClickThrough is the one Safe Links setting whose secure value is $false; the
    # six beside it are all secure at $true and are read with -not. A pass that
    # normalised the list onto one form would invert this one and nothing else would
    # notice, so both senses are pinned.
    Context 'Inverted-sense regression guard' {
        It 'Raises the click-through issue only when AllowClickThrough is true' {
            Mock Get-SafeLinksRule   { @() }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $true
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $false
                }
            }
            $secure = (& $checkFile)[0]
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'click through to blocked URLs'

            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Built-In Protection Policy'
                    EnableSafeLinksForEmail   = $true
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    DeliverMessageAfterScan   = $true
                    AllowClickThrough         = $true
                }
            }
            $insecure = (& $checkFile)[0]
            $insecure.Result | Should -Be 'Fail'
            $insecure.Finding | Should -Match 'Users can click through to blocked URLs'
        }
    }
}

Describe 'MET-MDO002 Safe Attachments' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO002-SafeAttachments.ps1'
    }

    Context 'Policy enabled with Block action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Policy enabled with Allow action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Allow' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Fail'
        }
        It 'Finding mentions Allow' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Finding | Should -Match 'Allow'
        }
    }

    Context 'Policy is disabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $false; Action = 'Block' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Fail'
        }
    }

    Context 'Global SharePoint, OneDrive and Teams setting is enabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Reports the global setting as Pass instead of emitting nothing for it' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Result | Should -Be 'Pass'
            $globalResult.Error  | Should -BeNullOrEmpty
        }
    }

    Context 'Global SharePoint, OneDrive and Teams setting is disabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $false } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Returns Fail for the global setting' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Result | Should -Be 'Fail'
        }
    }

    Context 'Global Safe Attachments policy cannot be retrieved' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { throw 'Access denied' }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Emits a result for the global setting carrying the failure in Error' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Error | Should -Match 'Access denied'
        }
        It 'Does not report the unread global setting as Pass' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Result | Should -Not -Be 'Pass'
        }
        It 'Finding says the setting was not established rather than naming a state' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Finding | Should -Match 'not established'
        }
        It 'Still assesses the Safe Attachment policies' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Global policy does not return the EnableATPForSPOTeamsODB property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ Identity = 'Default' } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Reports the absent property as unassessed, not as a pass or a disabled setting' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Result | Should -Be 'NotApplicable'
            $globalResult.Error  | Should -Not -BeNullOrEmpty
            $globalResult.Finding | Should -Match 'not established'
        }
    }

    # Get-SafeAttachmentPolicy omits Action on a reduced object. The check tests it with
    # -eq 'Allow', so an absent Action is read as "not Allow" and never questioned.
    Context 'An enabled Safe Attachments policy omits the Action property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true }
            }
        }

        # Pins current behaviour, which is wrong: the policy is reported as protecting
        # mail with an action the check never read, and the empty value is rendered
        # straight into the Finding. Per the repo's own rule an absent property must not
        # yield Pass. Left pinned rather than corrected here so the defect is visible and
        # cannot change unnoticed.
        It 'Currently returns Pass and renders an empty action into the Finding' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult | Should -Not -BeNullOrEmpty
            $policyResult.Result | Should -Be 'Pass'
            $policyResult.Finding | Should -Match "Safe Attachments is enabled with action ''"
            $policyResult.Finding | Should -Not -Match 'not returned'
        }
    }

    # Enable is read with -not, so an absent Enable is graded as a disabled policy.
    Context 'A Safe Attachments policy omits the Enable property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Action = 'Block' }
            }
        }

        It 'Does not return Pass on a state it never observed' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Not -Be 'Pass'
        }

        # Pins current behaviour, whose wording is wrong: the check reports Safe
        # Attachments as disabled for a property that was never returned. Left pinned so
        # the defect is visible and cannot change unnoticed.
        It 'Currently states Safe Attachments is disabled rather than that the property was not returned' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Fail'
            $policyResult.Finding | Should -Match 'Safe Attachments is disabled'
            $policyResult.Finding | Should -Not -Match 'not returned'
        }
    }
}

Describe 'MET-MDO009 ZAP' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO009-ZAP.ps1'
        $script:METContext = $null
        Mock Get-EXOMailbox { [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' } }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    Context 'ZAP fully enabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Legacy aggregate ZAP flag disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $false
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Pass when the documented spam and phish ZAP settings are enabled' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Phish ZAP disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $false
                }
            }
        }
        It 'Returns Fail and mentions phishing' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'phish'
        }
    }

    # An anti-spam policy object that returns neither ZAP property leaves both -not
    # tests true, which is indistinguishable from both settings being switched off.
    Context 'The effective anti-spam policy omits SpamZapEnabled and PhishZapEnabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true }
            }
        }

        It 'Does not return Pass on settings it never observed' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
        }

        # Pins current behaviour, whose wording is wrong: the check reports both ZAP
        # settings as disabled on the strength of properties Exchange Online never
        # returned. The verdict is fail-closed and safe, but the sentence states an
        # observation that was not made. Left pinned rather than corrected here so the
        # defect is visible and cannot change unnoticed.
        It 'Currently states both ZAP settings are disabled rather than that they were not returned' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'ZAP for spam is disabled'
            $results[0].Finding | Should -Match 'ZAP for phishing is disabled'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }

    # Both ZAP properties are read with -not, so the secure value is $true and the issue
    # text is the negative. Reading either as "ZAP is off" inverts the verdict, so both
    # senses are pinned for both properties, and each is pinned independently so one
    # cannot silently stand in for the other.
    Context 'Inverted-sense regression guard' {
        It 'Fails only when the ZAP settings are false and passes only when they are true' {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true }
            }
            $secure = (& $checkFile)[0]
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'ZAP for spam is disabled'
            $secure.Finding | Should -Not -Match 'ZAP for phishing is disabled'

            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $false; PhishZapEnabled = $false }
            }
            $insecure = (& $checkFile)[0]
            $insecure.Result | Should -Be 'Fail'
            $insecure.Finding | Should -Match 'ZAP for spam is disabled'
            $insecure.Finding | Should -Match 'ZAP for phishing is disabled'
        }

        It 'Keeps the spam and phish settings independent' {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $false; PhishZapEnabled = $true }
            }
            $spamOnly = (& $checkFile)[0]
            $spamOnly.Finding | Should -Match 'ZAP for spam is disabled'
            $spamOnly.Finding | Should -Not -Match 'ZAP for phishing is disabled'

            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $false }
            }
            $phishOnly = (& $checkFile)[0]
            $phishOnly.Finding | Should -Match 'ZAP for phishing is disabled'
            $phishOnly.Finding | Should -Not -Match 'ZAP for spam is disabled'
        }
    }
}
