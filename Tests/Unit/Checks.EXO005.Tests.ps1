BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    $checkFile = Join-Path $root 'Checks' 'EXO' 'MET-EXO005-TenantAllowBlockList.ps1'

    function Get-TenantAllowBlockListItems { [CmdletBinding()] param([string]$ListType,[string]$ListSubType) }
}

Describe 'MET-EXO005 Tenant Allow/Block List - unclassified entries' {

    # An entry whose Action is absent matches neither the 'Allow' filter nor the 'Block'
    # filter and used to vanish from both counts, letting the summary report the
    # remaining totals as if they were the whole list.
    Context 'One Allow, one Block, and one entry with no Action property' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'good@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = 'Block'; Value = 'bad@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Value = 'unknown@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Does not return the clean/well-maintained verdict' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Finding | Should -Not -Match 'appear well-maintained'
        }

        It 'Counts and names the one entry that could not be classified' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Match '1 entry\(ies\) did not return a usable Action value'
            $mainResult.Error | Should -Match 'Get-TenantAllowBlockListItems'
        }

        It 'States the allow/block counts describe only part of the list' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Match 'describe only part of the list'
        }

        It 'States why an unconfirmed state is not graded as a pass' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Match 'unassessed rather than a pass'
        }

        It 'Keeps Severity at Low' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Severity | Should -Be 'Low'
        }
    }

    Context 'Every entry lacks the Action property' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Value = 'legacy@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Value = 'other@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Is not a clean Info/Pass result' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Result | Should -Not -Be 'Info'
        }

        It 'States that nothing could be classified' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Match '2 entry\(ies\) did not return a usable Action value'
            $mainResult.Finding | Should -Match 'could not be classified'
        }
    }

    Context 'An entry has an Action value that is neither Allow nor Block' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Review'; Value = 'unknown@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Treats the unrecognised Action value as unclassified rather than silently dropping it' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Finding | Should -Match '1 entry\(ies\) did not return a usable Action value'
        }
    }

    Context 'An entry has the Action property present but set to $null' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'good@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = $null; Value = 'unknown@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        # Present-and-$null is a third state, distinct from absent and from a real value -
        # it must not slip past a $_.Action property-presence test and count as classified.
        It 'Treats a present-but-null Action the same as an absent one' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Not -Be 'Pass'
            $mainResult.Finding | Should -Match '1 entry\(ies\) did not return a usable Action value'
        }
    }

    Context 'An unclassified entry is present alongside enough allow entries to normally trigger the ratio finding' {
        BeforeAll {
            Mock Get-TenantAllowBlockListItems -ParameterFilter { -not $ListSubType } {
                switch ($ListType) {
                    'Sender' {
                        @(
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'a1@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Action = 'Allow'; Value = 'a2@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                            [PSCustomObject]@{ Value = 'unknown@vendor.com'; ExpirationDate = $null; LastModifiedDateTime = (Get-Date).ToUniversalTime() }
                        )
                    }
                    default { @() }
                }
            }
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        # The earlier partial-data tranche already gates the ratio findings behind
        # $failedListTypes.Count -eq 0; this asserts the same gate now also excludes the
        # unclassified-entry case, so the ratio is not computed over a partial count.
        It 'Does not compute the allow/block ratio finding over the partial counts' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult.Finding | Should -Not -Match 'no corresponding block entries'
            $mainResult.Finding | Should -Not -Match 'significantly outnumber'
        }
    }
}

Describe 'MET-EXO005 Tenant Allow/Block List - normal Allow/Block list regression guard' {
    Context 'Every entry classifies cleanly as Allow or Block, none stale or wildcarded' {
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
            Mock Get-TenantAllowBlockListItems -ParameterFilter { $ListSubType -eq 'AdvancedDelivery' } { @() }
        }

        It 'Still returns the existing well-maintained Pass verdict unchanged' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Pass'
            $mainResult.AffectedObject | Should -Be 'TABL (1 allows, 1 blocks)'
            $mainResult.Finding | Should -Be 'Tenant Allow/Block List entries appear well-maintained'
        }
    }
}
