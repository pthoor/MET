BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-ExoPhishSimOverrideRule { [CmdletBinding()] param() }
    function Get-ExoSecOpsOverrideRule   { [CmdletBinding()] param() }
}

Describe 'MET-EXO014 Advanced Delivery Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO014-AdvancedDeliveryPolicy.ps1'
    }

    Context 'no override rules' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and reports no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'No enforceable Advanced Delivery'
        }
    }

    Context 'enabled override rule exists' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce' }
            }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and mentions the rule name and count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'KnowBe4Sim'
            $results[0].Finding | Should -Match '1 enforceable'
            $results[0].AffectedObject | Should -Match '1 override rule'
        }
    }

    Context 'only disabled override rules exist' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'OldSim'; Mode = 'PendingDeletion' }
            }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and treats it as no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'No enforceable Advanced Delivery'
        }
    }

    Context 'SecOps override rule exists' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce' }
            }
        }

        It 'Returns Info and identifies the SecOps rule' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'SecOps mailbox: SecOpsOverrideRule'
        }
    }

    Context 'phishing simulation cmdlet throws' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { throw 'Access denied' }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SecOps cmdlet throws' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule { throw 'SecOps unavailable' }
        }

        It 'Returns Fail with the SecOps error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'SecOps unavailable'
        }
    }
}
