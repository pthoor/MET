BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METSafeLinksEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox               { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-SafeLinksRule            { [CmdletBinding()] param() }
    function Get-SafeLinksPolicy          { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule  { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule  { [CmdletBinding()] param([string]$Identity) }
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

    # A Safe Links policy object that returns none of the settings the check reads used to
    # be indistinguishable, to a -not test, from one that has every setting switched off.
    # The check now branches on absence before the falsy test, so the two are distinguished.
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

        It 'States each setting was not returned rather than asserting it is disabled' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'EnableSafeLinksForEmail was not returned'
            $results[0].Finding | Should -Match 'ScanUrls was not returned'
            $results[0].Finding | Should -Not -Match 'Safe Links for email is disabled'
            $results[0].Finding | Should -Not -Match 'Real-time URL scanning is disabled'
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

    # AllowClickThrough is boolean-inverted: its secure value is $false, so it is tested
    # with a bare `if ($Policy.AllowClickThrough)` rather than -not. An absent property is
    # therefore falsy and used to record no issue at all - silently contributing toward a
    # Pass on a control this check never observed. This is the most important case in this
    # file: confirmed against the pre-fix check to actually reach Pass (see report).
    Context 'AllowClickThrough is absent while every other setting is secure' {
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
                }
            }
        }

        It 'Does not return Pass on a click-through state it never observed' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
        }

        It 'States AllowClickThrough was not returned rather than silently passing it' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'AllowClickThrough was not returned'
            $results[0].Finding | Should -Match 'whether users can click through to blocked URLs was not established'
            $results[0].Finding | Should -Not -Match 'Issues: Users can click through to blocked URLs'
        }
    }

    # DisableURLRewrite shares AllowClickThrough's inverted-sense shape (secure value is
    # $false) and the same absence gap: `if ($PolicyType -ne 'BuiltIn' -and
    # $Policy.DisableURLRewrite)` treats an absent property as "not disabled" and records
    # nothing. Exercised on a custom (non-BuiltIn) policy, since the BuiltIn branch skips
    # this property entirely.
    Context 'DisableURLRewrite is absent on a custom policy while every other setting is secure' {
        BeforeAll {
            Mock Get-SafeLinksRule {
                [PSCustomObject]@{ Name = 'CustomSafeLinksRule'; SafeLinksPolicy = 'Custom Policy'; Priority = 0; State = 'Enabled'
                    SentTo = $null; SentToMemberOf = $null; RecipientDomainIs = @('contoso.com')
                    ExceptIfSentTo = $null; ExceptIfSentToMemberOf = $null; ExceptIfRecipientDomainIs = $null }
            }
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'Custom Policy'
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

        It 'Does not return Pass on a URL-rewrite state it never observed' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
        }

        It 'States DisableURLRewrite was not returned rather than silently passing it' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'DisableURLRewrite was not returned'
            $results[0].Finding | Should -Match 'whether URL rewriting is disabled was not established'
            $results[0].Finding | Should -Not -Match 'Issues: URL rewriting is disabled'
        }
    }
}
