BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"

    $checkFile = Join-Path $root 'Checks' 'EXO' 'MET-EXO004-QuarantinePolicy.ps1'

    function Get-QuarantinePolicy { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
}

Describe 'MET-EXO004 Quarantine Policies' {

    # Both properties absent: -not $null is $true and $null -gt 0 is $false, so the
    # conjunction used to read as false and the policy fell through to the Pass branch,
    # asserting a relationship between two values that were never observed.
    Context 'Custom policy with no ESNEnabled property and no EndUserQuarantinePermissionsValue property' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy' }
            }
        }

        It 'Returns Warning rather than Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
        }

        It 'Does not claim notification settings are consistent with permissions' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Not -Match 'consistent with the permissions'
        }

        It 'Names both properties as not returned' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'ESNEnabled'
            $results[0].Finding | Should -Match 'EndUserQuarantinePermissionsValue'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Error | Should -Match 'ESNEnabled'
            $results[0].Error | Should -Match 'EndUserQuarantinePermissionsValue'
        }

        It 'States why an unconfirmed state is not graded as a pass' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'unassessed rather than a pass'
        }

        It 'Keeps Severity at Medium' {
            $results = @(& $checkFile)
            $results[0].Severity | Should -Be 'Medium'
        }
    }

    Context 'Custom policy with ESNEnabled present but EndUserQuarantinePermissionsValue absent' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $false }
            }
        }

        It 'Returns Warning naming only the missing property' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'EndUserQuarantinePermissionsValue'
            $results[0].Finding | Should -Not -Match 'consistent with the permissions'
        }
    }

    Context 'Custom policy with EndUserQuarantinePermissionsValue present but ESNEnabled present-and-$null' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $null; EndUserQuarantinePermissionsValue = 23 }
            }
        }

        # Present-and-$null is a third state, distinct from absent and from a real value -
        # it must not slip past the property-presence check and be treated as observed.
        It 'Treats a present-but-null ESNEnabled the same as an absent one' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'ESNEnabled'
            $results[0].Finding | Should -Not -Match 'consistent with the permissions'
        }
    }

    Context 'Custom policy with both properties present: notifications off, permissions granted' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $false; EndUserQuarantinePermissionsValue = 3 }
            }
        }

        It 'Returns the existing Warning sentence unchanged' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'never notified that anything is quarantined'
        }
    }

    Context 'Custom policy with both properties present and consistent' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $true; EndUserQuarantinePermissionsValue = 23 }
            }
        }

        It 'Returns the existing Pass sentence unchanged' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Be 'Notification settings are consistent with the permissions granted to end users'
        }
    }

    Context 'Only built-in policies present' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    [PSCustomObject]@{ Name = 'AdminOnlyAccessPolicy'; EndUserQuarantinePermissionsValue = 0; ESNEnabled = $false }
                    [PSCustomObject]@{ Name = 'DefaultFullAccessPolicy'; EndUserQuarantinePermissionsValue = 39; ESNEnabled = $false }
                )
            }
        }

        It 'Returns the existing single Pass result unchanged' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }
}
