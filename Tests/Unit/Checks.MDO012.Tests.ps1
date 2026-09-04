BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-AtpPolicyForO365 { [CmdletBinding()] param() }

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO012-SafeDocuments.ps1'
}

Describe 'MET-MDO012 Safe Documents' {
    Context 'Safe Documents is on and click-through is blocked' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-MDO012'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Name     | Should -Be 'Safe Documents'
            $results[0].Result   | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Global MDO Settings'
            $results[0].Finding  | Should -Match 'Safe Documents is enabled and click-through for malicious files is blocked'
            $results[0].Error    | Should -BeNullOrEmpty
        }
    }

    Context 'EnableSafeDocs is false' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $false; AllowSafeDocsOpen = $false }
            }
        }

        It 'Fails naming the scanning gap and not the click-through setting' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Safe Documents is disabled'
            $results[0].Finding  | Should -Match 'Protected View are not scanned'
            $results[0].Finding  | Should -Not -Match 'click through Protected View'
        }

        It 'Recommends the cmdlet that sets both properties' {
            $results = @(& $checkFile)
            $results[0].Recommendation | Should -Match 'Set-AtpPolicyForO365 -EnableSafeDocs \$true -AllowSafeDocsOpen \$false'
        }
    }

    Context 'AllowSafeDocsOpen is true while Safe Documents is enabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $true }
            }
        }

        It 'Fails naming the click-through gap and not the scanning setting' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'allowed to click through Protected View'
            $results[0].Finding  | Should -Match 'identifies the file as malicious'
            $results[0].Finding  | Should -Not -Match 'Safe Documents is disabled'
        }
    }

    Context 'Both settings are wrong' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $false; AllowSafeDocsOpen = $true }
            }
        }

        It 'Fails once, naming both faults in a single Finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result  | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Safe Documents is disabled'
            $results[0].Finding | Should -Match 'allowed to click through Protected View'
            $results[0].Finding | Should -Match ';'
        }
    }

    Context 'Get-AtpPolicyForO365 throws' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 { throw 'Access to the requested object is denied.' }
        }

        It 'Fails once and carries the exception text in Error rather than the Finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Global MDO Settings'
            $results[0].Finding | Should -Match 'Unable to retrieve global MDO policy'
            $results[0].Error   | Should -Match 'Access to the requested object is denied'
            $results[0].Finding | Should -Not -Match 'Access to the requested object is denied'
        }
    }

    Context 'The policy object omits AllowSafeDocsOpen' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true }
            }
        }

        # Pins current behaviour, which is wrong: the check reports click-through as
        # blocked on the strength of a property the service never returned. Per the
        # repo's own rule an absent property must not yield Pass. Left pinned rather
        # than corrected here so the defect is visible and cannot change unnoticed.
        It 'Currently returns Pass on a property that was never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'click-through for malicious files is blocked'
        }
    }

    Context 'The policy object omits EnableSafeDocs' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ Identity = 'Default' }
            }
        }

        It 'Does not return Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
        }

        # Also pins current behaviour: Fail is the safe direction, but the Finding
        # asserts "Safe Documents is disabled" for a value nothing confirmed.
        It 'Currently states the feature is disabled rather than unestablished' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Safe Documents is disabled'
        }
    }

    Context 'Get-AtpPolicyForO365 returns nothing without throwing' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 { }
        }

        It 'Does not return Pass when no policy object came back' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Not -Be 'Pass'
        }
    }
}
