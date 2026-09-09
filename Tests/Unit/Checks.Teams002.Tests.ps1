BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-AtpPolicyForO365 { [CmdletBinding()] param() }
}

Describe 'MET-Teams002 Safe Attachments for Teams' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams002-SafeAttachments.ps1'
    }

    Context 'EnableATPForSPOTeamsODB is true' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Pass' }
        }
    }

    Context 'EnableATPForSPOTeamsODB is false' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableATPForSPOTeamsODB = $false }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Fail' }
        }
    }

    Context 'Get-AtpPolicyForO365 throws' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $result = $results | Where-Object CheckId -eq 'MET-Teams002' | Select-Object -First 1
            $result.Result | Should -Be 'Fail'
            $result.Error | Should -Match 'Access denied'
        }
    }

    # MET-MDO002 reads this same property from the same cmdlet and has an explicit
    # NotApplicable branch for it being absent. MET-Teams002 now ports that branch
    # across, so the two checks no longer report opposite verdicts from one cmdlet call
    # in the same run.
    Context 'The global policy omits the EnableATPForSPOTeamsODB property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 { [PSCustomObject]@{ Identity = 'Default' } }
        }

        It 'Does not return Pass on a setting it never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'Global Safe Attachments Settings'
        }

        It 'Reports NotApplicable and states the property was not returned, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Finding | Should -Match 'not established'
            $results[0].Finding | Should -Not -Match 'EnableATPForSPOTeamsODB = \$false'
        }
    }

    # Mutation verification: the absent path is NotApplicable while the present-and-false
    # path stays Fail, with different Findings.
    Context 'Property absent vs. present and false' {
        It 'Produces different Results and different Findings' {
            Mock Get-AtpPolicyForO365 { [PSCustomObject]@{ Identity = 'Default' } }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'NotApplicable'
            $absent.Finding | Should -Match 'not established'
            $absent.Finding | Should -Not -Match 'EnableATPForSPOTeamsODB = \$false'

            Mock Get-AtpPolicyForO365 { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $false } }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'EnableATPForSPOTeamsODB = \$false'
            $present.Finding | Should -Not -Match 'not established'
        }
    }
}
