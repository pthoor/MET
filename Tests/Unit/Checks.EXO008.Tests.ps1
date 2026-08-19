BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METPresetSecurityPolicyTier.ps1"
    . "$root/Private/Test-METIsPresetSecurityPolicyName.ps1"

    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
}

Describe 'MET-EXO008 Quarantine Retention' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO008-QuarantineRetention.ps1'
    }

    Context 'Strict preset policy at the expected 30-day retention' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{
                    Name                     = 'Strict Preset Security Policy1707729536596'
                    HostedContentFilterPolicy = 'Strict Preset Security Policy1707729536596'
                    Priority                 = 0
                    State                    = 'Enabled'
                })
            }
            Mock Get-HostedContentFilterPolicy {
                @([PSCustomObject]@{
                    Name                      = 'Strict Preset Security Policy1707729536596'
                    IsDefault                 = $false
                    QuarantineRetentionPeriod = 30
                })
            }
        }
        It 'Returns Pass noting the value is fixed by the preset and not admin-configurable' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'fixed'
            $results[0].Finding | Should -Match 'not admin-configurable'
        }
    }

    Context 'Strict preset policy with an unexpectedly low retention value' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{
                    Name                     = 'Strict Preset Security Policy1707729536596'
                    HostedContentFilterPolicy = 'Strict Preset Security Policy1707729536596'
                    Priority                 = 0
                    State                    = 'Enabled'
                })
            }
            Mock Get-HostedContentFilterPolicy {
                @([PSCustomObject]@{
                    Name                      = 'Strict Preset Security Policy1707729536596'
                    IsDefault                 = $false
                    QuarantineRetentionPeriod = 15
                })
            }
        }
        It 'Returns Warning, not Fail, and does not issue an actionable Set-HostedContentFilterPolicy command against it' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'Run: Set-HostedContentFilterPolicy'
            $results[0].Recommendation | Should -Not -Match 'Run: Set-HostedContentFilterPolicy'
        }
    }

    Context 'Custom policy at the default 15-day retention' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{
                    Name                     = 'Contoso Custom Policy'
                    HostedContentFilterPolicy = 'Contoso Custom Policy'
                    Priority                 = 1
                    State                    = 'Enabled'
                    SentTo                   = @('user@contoso.com')
                })
            }
            Mock Get-HostedContentFilterPolicy {
                @([PSCustomObject]@{
                    Name                      = 'Contoso Custom Policy'
                    IsDefault                 = $false
                    QuarantineRetentionPeriod = 15
                })
            }
        }
        It 'Returns Fail with an actionable Set-HostedContentFilterPolicy recommendation' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Recommendation | Should -Match "Set-HostedContentFilterPolicy -Identity 'Contoso Custom Policy' -QuarantineRetentionPeriod 30"
        }
    }

    Context 'Custom policy at 30-day retention' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{
                    Name                     = 'Contoso Custom Policy'
                    HostedContentFilterPolicy = 'Contoso Custom Policy'
                    Priority                 = 1
                    State                    = 'Enabled'
                    SentTo                   = @('user@contoso.com')
                })
            }
            Mock Get-HostedContentFilterPolicy {
                @([PSCustomObject]@{
                    Name                      = 'Contoso Custom Policy'
                    IsDefault                 = $false
                    QuarantineRetentionPeriod = 30
                })
            }
        }
        It 'Returns Pass and the Finding mentions the anti-phish inheritance note' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'anti-phishing quarantine'
        }
    }

    Context 'Tenant default policy with low retention' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy {
                @([PSCustomObject]@{
                    Name                      = 'Default'
                    IsDefault                 = $true
                    QuarantineRetentionPeriod = 15
                })
            }
        }
        It 'Is always evaluated (no assigning rule required) and Fails' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].AffectedObject | Should -Match 'catch-all'
        }
    }

    Context 'Retrieval throws' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
