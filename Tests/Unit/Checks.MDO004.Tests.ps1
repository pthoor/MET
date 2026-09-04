BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"

    function Get-AntiPhishPolicy { [CmdletBinding()] param([string]$Identity) }
    function Get-AntiPhishRule   { [CmdletBinding()] param([string]$Identity) }

    function New-CleanPolicy {
        param([string] $Name = 'Office365 AntiPhish Default', [bool] $IsDefault = $true)
        [PSCustomObject]@{
            Name                       = $Name
            IsDefault                  = $IsDefault
            EnableSpoofIntelligence    = $true
            AuthenticationFailAction   = 'Quarantine'
            EnableUnauthenticatedSender = $true
            HonorDmarcPolicy           = $true
        }
    }
}

Describe 'MET-MDO004 Anti-Spoofing' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO004-AntiSpoofing.ps1'
    }

    Context 'The default policy is fully configured' {
        BeforeAll {
            Mock Get-AntiPhishRule   { @() }
            Mock Get-AntiPhishPolicy { New-CleanPolicy }
        }

        It 'Returns a single Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Pass'
            $results[0].CheckId  | Should -Be 'MET-MDO004'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Name     | Should -Be 'Anti-Spoofing'
            $results[0].Severity | Should -Be 'High'
        }

        It 'Labels the default policy as the catch-all scope' {
            $results = @(& $checkFile)
            $results[0].AffectedObject | Should -Match 'Office365 AntiPhish Default'
            $results[0].AffectedObject | Should -Match 'catch-all \(default'
        }
    }

    Context 'Spoof intelligence is explicitly disabled' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.EnableSpoofIntelligence = $false
                $p
            }
        }

        It 'Returns Fail and names spoof intelligence in the finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result  | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Spoof intelligence is disabled'
        }
    }

    Context 'The EnableSpoofIntelligence property is absent' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                [PSCustomObject]@{
                    Name                        = 'Office365 AntiPhish Default'
                    IsDefault                   = $true
                    AuthenticationFailAction    = 'Quarantine'
                    EnableUnauthenticatedSender = $true
                    HonorDmarcPolicy            = $true
                }
            }
        }

        It 'Grades the spoof-intelligence finding as Fail, not Warning' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Finding | Should -Match 'Spoof intelligence is disabled'
            $results[0].Result  | Should -Be 'Fail'
        }
    }

    Context 'The EnableSpoofIntelligence property is null' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.EnableSpoofIntelligence = $null
                $p
            }
        }

        It 'Grades the spoof-intelligence finding as Fail, not Warning' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'Spoof intelligence is disabled'
            $results[0].Result  | Should -Be 'Fail'
        }
    }

    Context 'Spoof intelligence is on but another control is weak' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.HonorDmarcPolicy = $false
                $p
            }
        }

        It 'Returns Warning rather than Fail' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'DMARC policy enforcement is not honored'
            $results[0].Finding | Should -Not -Match 'Spoof intelligence'
        }
    }

    Context "AuthenticationFailAction is 'MoveToJmf'" {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.AuthenticationFailAction = 'MoveToJmf'
                $p
            }
        }

        It 'Returns Warning and recommends Quarantine' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Finding | Should -Match "'MoveToJmf'"
            $results[0].Finding | Should -Match 'Quarantine'
        }
    }

    Context 'AuthenticationFailAction is neither MoveToJmf nor Quarantine' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.AuthenticationFailAction = 'None'
                $p
            }
        }

        It 'Returns Warning and states the action found' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Finding | Should -Match "Authentication failure action is 'None'"
        }
    }

    Context 'Unauthenticated sender indicators are disabled' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                $p = New-CleanPolicy
                $p.EnableUnauthenticatedSender = $false
                $p
            }
        }

        It 'Returns Warning and names the indicators in the finding' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Unauthenticated sender indicators'
        }
    }

    Context 'A custom policy has no rule assigning it' {
        BeforeAll {
            Mock Get-AntiPhishRule { @() }
            Mock Get-AntiPhishPolicy {
                @(
                    New-CleanPolicy
                    New-CleanPolicy -Name 'Unassigned Custom' -IsDefault $false
                )
            }
        }

        It 'Assesses only the default policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].AffectedObject | Should -Match 'Office365 AntiPhish Default'
        }
    }

    Context 'A custom policy is assigned by a disabled rule' {
        BeforeAll {
            Mock Get-AntiPhishRule {
                [PSCustomObject]@{
                    Name = 'Disabled Rule'; AntiPhishPolicy = 'Custom Policy'
                    State = 'Disabled'; Priority = 0; SentTo = @('exec@contoso.com')
                }
            }
            Mock Get-AntiPhishPolicy {
                @(
                    New-CleanPolicy
                    New-CleanPolicy -Name 'Custom Policy' -IsDefault $false
                )
            }
        }

        It 'Skips the policy the disabled rule assigns' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].AffectedObject | Should -Not -Match 'Custom Policy'
        }
    }

    Context 'A custom policy is assigned by an enabled rule' {
        BeforeAll {
            Mock Get-AntiPhishRule {
                [PSCustomObject]@{
                    Name = 'Exec Rule'; AntiPhishPolicy = 'Custom Policy'
                    State = 'Enabled'; Priority = 0; SentTo = @('exec@contoso.com')
                }
            }
            Mock Get-AntiPhishPolicy {
                @(
                    New-CleanPolicy
                    $custom = New-CleanPolicy -Name 'Custom Policy' -IsDefault $false
                    $custom.EnableSpoofIntelligence = $false
                    $custom
                )
            }
        }

        It 'Returns one result per assessed policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
        }

        It 'Labels the custom policy with its rule scope' {
            $results = @(& $checkFile)
            $custom = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $custom.AffectedObject | Should -Match 'Priority 0'
            $custom.AffectedObject | Should -Match 'SentTo: exec@contoso\.com'
            $custom.Result         | Should -Be 'Fail'
        }
    }

    Context 'Retrieving the anti-phish policies fails' {
        BeforeAll {
            Mock Get-AntiPhishRule   { throw 'Access denied' }
            Mock Get-AntiPhishPolicy { New-CleanPolicy }
        }

        It 'Returns a single Fail with the error message populated' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result         | Should -Be 'Fail'
            $results[0].Severity       | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Anti-Phish Policies'
            $results[0].Error          | Should -Match 'Access denied'
        }
    }
}
