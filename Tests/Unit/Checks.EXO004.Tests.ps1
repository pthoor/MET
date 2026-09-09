BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"

    $checkFile = Join-Path $root 'Checks' 'EXO' 'MET-EXO004-QuarantinePolicy.ps1'

    function Get-QuarantinePolicy { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }

    # Get-QuarantinePolicy returns EndUserQuarantinePermissions as a formatted string,
    # never a typed object and never an EndUserQuarantinePermissionsValue integer. Build
    # that exact shape so the mocks match what the cmdlet actually emits on a live tenant.
    function New-METPermString {
        param(
            [bool] $PermissionToRelease        = $false,
            [bool] $PermissionToRequestRelease = $false,
            [bool] $PermissionToDelete         = $false,
            [bool] $PermissionToPreview        = $false,
            [bool] $PermissionToAllowSender    = $false,
            [bool] $PermissionToBlockSender    = $false,
            [bool] $PermissionToDownload       = $false,
            [bool] $PermissionToViewHeader     = $false
        )
        @"
[PermissionToViewHeader: $PermissionToViewHeader
PermissionToDownload: $PermissionToDownload
PermissionToAllowSender: $PermissionToAllowSender
PermissionToBlockSender: $PermissionToBlockSender
PermissionToRequestRelease: $PermissionToRequestRelease
PermissionToRelease: $PermissionToRelease
PermissionToPreview: $PermissionToPreview
PermissionToDelete: $PermissionToDelete]
"@
    }
}

Describe 'MET-EXO004 Quarantine Policies' {

    Context 'Custom policy with no ESNEnabled property and no EndUserQuarantinePermissions property' {
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
            $results[0].Finding | Should -Match 'EndUserQuarantinePermissions'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Error | Should -Match 'ESNEnabled'
            $results[0].Error | Should -Match 'EndUserQuarantinePermissions'
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

    Context 'Custom policy with ESNEnabled present but EndUserQuarantinePermissions absent' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $false }
            }
        }

        It 'Returns Warning naming only the missing property' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'EndUserQuarantinePermissions'
            $results[0].Finding | Should -Not -Match 'consistent with the permissions'
        }
    }

    Context 'Custom policy with EndUserQuarantinePermissions present but ESNEnabled present-and-$null' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoCustomPolicy'
                    ESNEnabled                   = $null
                    EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true -PermissionToDelete $true)
                }
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

    Context 'Custom policy with the real string shape: notifications off, permissions granted' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoCustomPolicy'
                    ESNEnabled                   = $false
                    EndUserQuarantinePermissions = (New-METPermString -PermissionToPreview $true -PermissionToDelete $true)
                }
            }
        }

        It 'Returns the existing Warning sentence unchanged' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'never notified that anything is quarantined'
        }
    }

    Context 'Custom policy with the real string shape: notifications on, permissions granted' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoCustomPolicy'
                    ESNEnabled                   = $true
                    EndUserQuarantinePermissions = (New-METPermString -PermissionToBlockSender $true -PermissionToPreview $true -PermissionToDelete $true)
                }
            }
        }

        It 'Returns the existing Pass sentence unchanged' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Be 'Notification settings are consistent with the permissions granted to end users'
        }
    }

    Context 'Custom policy with the real string shape: no permissions, notifications off' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoNoAccessPolicy'
                    ESNEnabled                   = $false
                    EndUserQuarantinePermissions = (New-METPermString)
                }
            }
        }

        It 'Returns Pass - no access and no notification is not a contradiction' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Only built-in policies present' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    [PSCustomObject]@{ Name = 'AdminOnlyAccessPolicy'; ESNEnabled = $false; EndUserQuarantinePermissions = (New-METPermString) }
                    [PSCustomObject]@{ Name = 'DefaultFullAccessPolicy'; ESNEnabled = $false; EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true) }
                )
            }
        }

        It 'Returns the existing single Pass result unchanged' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Inverted-sense regression guard' {
        # The Warning fires on a conjunction: notifications off AND at least one end-user
        # permission granted. Drop or flip either half and the check flags every policy or
        # none, so all three deciding combinations are pinned against the real string shape.
        It 'Warns only when ESNEnabled is false while end-user permissions are granted' {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $false; EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true) }
            }
            (@(& $checkFile))[0].Result | Should -Be 'Warning'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $true; EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true) }
            }
            (@(& $checkFile))[0].Result | Should -Be 'Pass'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; ESNEnabled = $false; EndUserQuarantinePermissions = (New-METPermString) }
            }
            (@(& $checkFile))[0].Result | Should -Be 'Pass'
        }
    }
}
