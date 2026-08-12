BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-ExoPhishSimOverrideRule { [CmdletBinding()] param() }
}

Describe 'MET-EXO014 Advanced Delivery Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO014-AdvancedDeliveryPolicy.ps1'
    }

    Context 'no override rules' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
        }

        It 'Returns Info and reports no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'No Advanced Delivery'
        }
    }

    Context 'enabled override rule exists' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; State = 'Enabled' }
            }
        }

        It 'Returns Info and mentions the rule name and count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'KnowBe4Sim'
            $results[0].Finding | Should -Match '1 enabled'
            $results[0].AffectedObject | Should -Match '1 override rule'
        }
    }

    Context 'only disabled override rules exist' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'OldSim'; State = 'Disabled' }
            }
        }

        It 'Returns Info and treats it as no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'No Advanced Delivery'
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { throw 'Access denied' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
