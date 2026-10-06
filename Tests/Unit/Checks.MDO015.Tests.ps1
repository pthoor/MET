BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METPresetSecurityPolicyTier.ps1"

    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }

    function New-DefaultPolicy {
        param($State, [switch]$Absent)
        $policy = [ordered]@{ Name = 'Default'; IsDefault = $true }
        if (-not $Absent) { $policy.IntraOrgFilterState = $State }
        [PSCustomObject]$policy
    }
}

Describe 'MET-MDO015 Intra-Organization Spam Filtering' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO015-IntraOrgSpamFiltering.ps1'
    }

    Context 'default policy has intra-org filtering Disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy { @(New-DefaultPolicy -State 'Disabled') }
        }

        It 'Returns Fail naming the policy and the fix' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].CheckId | Should -Be 'MET-MDO015'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Name | Should -Be 'Intra-Organization Spam Filtering'
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Match '^Default \['
            $results[0].Finding | Should -Match 'compromised'
            $results[0].Recommendation | Should -Match "Set-HostedContentFilterPolicy -Identity 'Default' -IntraOrgFilterState"
        }
    }

    Context 'default policy is at the Microsoft-recommended Default value' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy { @(New-DefaultPolicy -State 'Default') }
        }

        It 'Returns Pass and states the government-cloud caveat' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'GCC'
        }
    }

    Context 'IntraOrgFilterState arrives as an enum-like object rather than a string' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy {
                $state = [PSCustomObject]@{}
                $state | Add-Member -MemberType ScriptMethod -Name ToString -Value { 'Disabled' } -Force
                @([PSCustomObject]@{ Name = 'Default'; IsDefault = $true; IntraOrgFilterState = $state })
            }
        }

        It 'Compares on the string form' {
            (& $checkFile)[0].Result | Should -Be 'Fail'
        }
    }

    Context 'custom enabled policy filters all spam and phish internally' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{ Name = 'Finance'; HostedContentFilterPolicy = 'Finance'; Priority = 0; State = 'Enabled'; SentToMemberOf = @('finance@contoso.com') })
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    (New-DefaultPolicy -State 'HighConfidencePhish'),
                    [PSCustomObject]@{ Name = 'Finance'; IsDefault = $false; IntraOrgFilterState = 'Spam' }
                )
            }
        }

        It 'Returns Pass for both policies, with the custom scope in AffectedObject' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results | ForEach-Object { $_.Result | Should -Be 'Pass' }
            ($results | Where-Object AffectedObject -like 'Finance*').AffectedObject | Should -Match 'MemberOf'
        }
    }

    Context 'custom policy whose rule is disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{ Name = 'Old'; HostedContentFilterPolicy = 'Old'; Priority = 0; State = 'Disabled' })
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    (New-DefaultPolicy -State 'Default'),
                    [PSCustomObject]@{ Name = 'Old'; IsDefault = $false; IntraOrgFilterState = 'Disabled' }
                )
            }
        }

        It 'Is not assessed, since it applies to nobody' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].AffectedObject | Should -Match '^Default'
        }
    }

    Context 'preset security policy' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{ Name = 'Strict Preset Security Policy1707729536596'; HostedContentFilterPolicy = 'Strict Preset Security Policy1707729536596'; Priority = 0; State = 'Enabled' })
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    (New-DefaultPolicy -State 'Default'),
                    [PSCustomObject]@{ Name = 'Strict Preset Security Policy1707729536596'; IsDefault = $false; IntraOrgFilterState = 'Default' }
                )
            }
        }

        It 'Is skipped because its value is Microsoft-managed' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].AffectedObject | Should -Not -Match 'Preset'
        }
    }

    Context 'unrecognized value' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy { @(New-DefaultPolicy -State 'SomethingNew') }
        }

        It 'Returns Warning naming the value' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match "'SomethingNew'"
        }
    }

    Context 'IntraOrgFilterState absent from every in-scope policy' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy { @(New-DefaultPolicy -Absent) }
        }

        It 'Returns a single NotApplicable with the reason recorded, never Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Finding | Should -Match 'not established'
            $results[0].Finding | Should -Match 'rather than a pass'
        }
    }

    Context 'IntraOrgFilterState absent on one of two in-scope policies' {
        BeforeAll {
            Mock Get-HostedContentFilterRule {
                @([PSCustomObject]@{ Name = 'Sales'; HostedContentFilterPolicy = 'Sales'; Priority = 0; State = 'Enabled' })
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    (New-DefaultPolicy -State 'Default'),
                    [PSCustomObject]@{ Name = 'Sales'; IsDefault = $false }
                )
            }
        }

        It 'Returns Warning for the policy whose property was absent and Pass for the other' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $sales = $results | Where-Object AffectedObject -like 'Sales*'
            $sales.Result | Should -Be 'Warning'
            $sales.Finding | Should -Match 'not established'
            ($results | Where-Object AffectedObject -like 'Default*').Result | Should -Be 'Pass'
        }
    }

    Context 'Get-HostedContentFilterPolicy throws' {
        BeforeAll {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy { throw 'Access denied' }
        }

        It 'Returns Fail with the error populated' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
