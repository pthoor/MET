BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"

    # Stub EXO cmdlets
    function Get-DkimSigningConfig           { [CmdletBinding()] param() }
    function Get-QuarantinePolicy            { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
    function Get-TenantAllowBlockListItems   { [CmdletBinding()] param([string]$ListType,[string]$ListSubType) }
    function Get-ReportSubmissionPolicy      { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule        { [CmdletBinding()] param() }

    # Get-QuarantinePolicy returns EndUserQuarantinePermissions as a formatted string,
    # never a typed object and never an EndUserQuarantinePermissionsValue integer.
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
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO004-QuarantinePolicy.ps1'
    }

    Context 'Only built-in policies present' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    [PSCustomObject]@{
                        Name                         = 'AdminOnlyAccessPolicy'
                        EndUserQuarantinePermissions = (New-METPermString)
                        ESNEnabled                   = $false
                    }
                    [PSCustomObject]@{
                        Name                         = 'DefaultFullAccessPolicy'
                        EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true -PermissionToAllowSender $true)
                        ESNEnabled                   = $false
                    }
                )
            }
        }
        It 'Returns a single Pass result' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }

        It 'Does not flag AdminOnlyAccessPolicy for its by-design zero permissions value' {
            $results = & $checkFile
            ($results | Where-Object { $_.AffectedObject -eq 'AdminOnlyAccessPolicy' }) | Should -BeNullOrEmpty
        }
    }

    Context 'Custom policy with permissions granted but notifications disabled' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoCustomPolicy'
                    EndUserQuarantinePermissions = (New-METPermString -PermissionToBlockSender $true -PermissionToPreview $true -PermissionToDelete $true)
                    ESNEnabled                   = $false
                }
            }
        }
        It 'Returns Warning' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'notif'
        }
    }

    Context 'Custom policy with permissions granted and notifications enabled' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoCustomPolicy'
                    EndUserQuarantinePermissions = (New-METPermString -PermissionToBlockSender $true -PermissionToPreview $true -PermissionToDelete $true)
                    ESNEnabled                   = $true
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Custom policy with no permissions and notifications disabled' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                         = 'ContosoNoAccessPolicy'
                    EndUserQuarantinePermissions = (New-METPermString)
                    ESNEnabled                   = $false
                }
            }
        }
        It 'Returns Pass - no access and no notification is not a contradiction' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Get-QuarantinePolicy throws' {
        BeforeAll {
            Mock Get-QuarantinePolicy { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # A reduced Get-QuarantinePolicy object omits both properties this check reads.
    # -not $null is $true, so the policy used to fall through to the else branch and be
    # graded on values that were never read. Fixed: absence on either side is now checked
    # structurally before the "permission granted" test runs.
    Context 'A custom quarantine policy omits ESNEnabled and EndUserQuarantinePermissions' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy' }
            }
        }

        It 'Returns Warning naming the properties that were never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Be 'ContosoCustomPolicy'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Not -Match 'Notification settings are consistent'
        }
    }

    # The Warning fires on a conjunction of a negative and a positive: notifications off
    # AND end-user permissions granted. Dropping or flipping either half turns the check
    # into one that flags every policy or no policy, so all three combinations that
    # decide the verdict are pinned.
    Context 'Inverted-sense regression guard' {
        It 'Warns only when ESNEnabled is false while end-user permissions are granted' {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true); ESNEnabled = $false }
            }
            (& $checkFile)[0].Result | Should -Be 'Warning'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissions = (New-METPermString -PermissionToRelease $true); ESNEnabled = $true }
            }
            (& $checkFile)[0].Result | Should -Be 'Pass'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissions = (New-METPermString); ESNEnabled = $false }
            }
            (& $checkFile)[0].Result | Should -Be 'Pass'
        }
    }
}

Describe 'MET-EXO005 Tenant Allow/Block List' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO005-TenantAllowBlockList.ps1'
    }

    # These dates are fixed rather than relative to Get-Date: entries built from the
    # current clock are never older than the check's 90-day cutoff, so the stale-allow
    # branch would never run.
    Context 'Allow entries are past their expiration date or untouched for over 90 days' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'legacy@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = ([datetime]::new(2020, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)) }
                            [PSCustomObject]@{ Action = 'Block'; Value = 'bad@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    'Url' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'https://expired.vendor.com'; ExpirationDate = ([datetime]::new(2021, 6, 1, 0, 0, 0, [System.DateTimeKind]::Utc)); LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = 'Block'; Value = 'https://bad.vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Returns Warning counting both stale allow entries' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Warning'
            $mainResult.Severity | Should -Be 'Low'
            $mainResult.AffectedObject | Should -Be 'TABL (2 allows, 2 blocks)'
            $mainResult.Finding | Should -Match '2 allow entry\(ies\) are stale'
        }

        It 'Does not attribute the Warning to wildcards or to the allow/block ratio' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Not -Match 'wildcard'
            $mainResult.Finding | Should -Not -Match 'significantly outnumber'
            $mainResult.Finding | Should -Not -Match 'no corresponding block entries'
        }
    }

    Context 'Advanced Delivery URL allow entries present alongside a well-maintained TABL' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'good@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = 'Block'; Value = 'bad@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } {
                @(
                    [PSCustomObject]@{ Action = 'Allow'; Value = '*.fabrikam.com' }
                    [PSCustomObject]@{ Action = 'Allow'; Value = '*.contoso-sim.com' }
                )
            }
        }

        It 'Reports Advanced Delivery entries as a separate Info result' {
            $results = & $checkFile
            $advResult = $results | Where-Object { $_.AffectedObject -match 'Advanced Delivery' }
            $advResult | Should -Not -BeNullOrEmpty
            $advResult.Result | Should -Be 'Info'
            $advResult.Severity | Should -Be 'Informational'
            $advResult.Finding | Should -Match 'fabrikam'
            $advResult.ReferenceUrl | Should -Match 'advanced-delivery-policy-configure'
        }

        It 'Does not change the main TABL Pass verdict' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Advanced Delivery lookup throws' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Url' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = '*.contoso.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { throw 'Access denied' }
        }

        It 'Still completes the main TABL logic and returns a Warning for the wildcard allow' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Warning'
            $mainResult.Finding | Should -Match 'wildcard'
        }

        It 'Still emits an Advanced Delivery result carrying the retrieval error' {
            $results = & $checkFile
            $advResult = $results | Where-Object { $_.AffectedObject -match 'Advanced Delivery' }
            $advResult | Should -Not -BeNullOrEmpty
            $advResult.Result | Should -Not -Be 'Pass'
            $advResult.Error | Should -Match 'Access denied'
            $advResult.Finding | Should -Not -Match 'No Advanced Delivery URL allow entries are configured'
        }
    }

    Context 'Every Tenant Allow/Block List type fails to read' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } { throw 'Access denied' }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Returns Warning with the retrieval error rather than an empty-list Info result' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match 'Tenant Allow/Block List' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Warning'
            $mainResult.Error | Should -Match 'Access denied'
            $mainResult.Finding | Should -Not -Match 'No entries found'
        }
    }

    Context 'Sender list type fails while the other list types succeed' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' { throw 'Access denied' }
                    default {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'https://good.example.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = 'Block'; Value = 'https://bad.example.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Names the unreadable list type and does not return Pass' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Error | Should -Match 'Sender'
            $mainResult.Finding | Should -Match 'Sender'
        }
    }

    Context 'The unreadable list type is the one holding the block entries' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Url' { throw 'Access denied' }
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'partner@fabrikam.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Does not claim the tenant has allow entries with no corresponding blocks' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Finding | Should -Not -Match 'no corresponding block entries'
            $mainResult.Finding | Should -Not -Match 'significantly outnumber'
        }

        It 'Reports the partial coverage and does not return Pass' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Error | Should -Match 'Url'
            $mainResult.Finding | Should -Match 'Url'
        }
    }

    # An entry whose Action property is absent matches neither the Allow filter nor the
    # Block filter, so an entry the check did read was counted as neither. Fixed: an
    # unclassifiable entry is now tallied separately and stops the clean/well-maintained
    # verdict from being reached.
    Context 'Tenant Allow/Block List entries omit the Action property' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Value = 'legacy@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Does not return Pass and names the entry it could not classify' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Finding | Should -Not -Match 'appear well-maintained'
            $mainResult.Finding | Should -Match '1 entry'
        }
    }
}
