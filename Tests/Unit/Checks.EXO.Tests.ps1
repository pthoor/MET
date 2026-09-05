BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"

    # Stub EXO cmdlets
    function Get-DkimSigningConfig           { [CmdletBinding()] param() }
    function Get-QuarantinePolicy            { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
    function Get-TenantAllowBlockListItems   { [CmdletBinding()] param([string]$ListType,[string]$ListSubType) }
    function Get-ReportSubmissionPolicy      { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule        { [CmdletBinding()] param() }
}

Describe 'MET-EXO002 DKIM' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO002-DKIM.ps1'
    }

    # Get-DkimSigningConfig reports key size per selector (Selector1KeySize /
    # Selector2KeySize) and never as a flat KeySize property - KeySize exists only as an
    # input parameter on New-/Rotate-DkimSigningConfig. These mocks previously invented a
    # flat KeySize, so the key-length assertion passed in CI against a branch that could
    # never fire against a real tenant.
    Context 'DKIM enabled with 2048-bit key and Valid status' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'DKIM is disabled' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'The active selector still holds a 1024-bit key' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 1024; Selector2KeySize = 1024
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail and mentions key size' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match '1024'
        }
    }

    Context 'A domain mid key-rotation has a 2048-bit active selector and a 1024-bit inactive one' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 1024; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector2'; SelectorAfterRotateOnDate = 'selector1'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Passes on the active selector and notes the pending one rather than failing a correct rotation' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match '2048-bit key on the active selector'
            $results[0].Finding | Should -Match 'selector1 is 1024-bit'
        }
    }

    Context 'Neither selector reports a key size' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2' }
            }
        }
        It 'Returns Warning rather than Pass, because the key length went unverified' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'could not be verified'
        }
    }

    Context 'DKIM status is not Valid' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'CnameMissing'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail and names the CNAME problem' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'CNAME records are not published'
        }
    }

    Context 'DKIM has no keypair generated' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; Status = 'NoDKIMKeys' }
            }
        }
        It 'Reports the missing keypair rather than a CNAME problem' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'No DKIM keypair'
        }
    }

    Context 'No DKIM configs found' {
        BeforeAll { Mock Get-DkimSigningConfig { @() } }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'Get-DkimSigningConfig throws' {
        BeforeAll { Mock Get-DkimSigningConfig { throw 'Unauthorized' } }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # Get-DkimSigningConfig omits Enabled on service or module versions that do not
    # return it. The check reads it with -not, which collapses an absent property into
    # $false, so the domain is graded on a signing state that was never observed.
    Context 'The DKIM config object omits the Enabled property' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }

        It 'Does not return Pass on a signing state it never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'contoso.com'
        }

        # Pins current behaviour, whose wording is wrong: the check reports DKIM signing
        # as disabled for this domain on the strength of a property Exchange Online never
        # returned. The verdict is fail-closed and safe, but the sentence states an
        # observation that was not made. Left pinned rather than corrected here so the
        # defect is visible and cannot change unnoticed.
        It 'Currently states signing is disabled rather than that the property was not returned' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'DKIM signing is disabled for this domain'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
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
                        Name                              = 'AdminOnlyAccessPolicy'
                        EndUserQuarantinePermissionsValue = 0
                        ESNEnabled                         = $false
                    }
                    [PSCustomObject]@{
                        Name                              = 'DefaultFullAccessPolicy'
                        EndUserQuarantinePermissionsValue = 39
                        ESNEnabled                         = $false
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
                    Name                              = 'ContosoCustomPolicy'
                    EndUserQuarantinePermissionsValue = 23
                    ESNEnabled                         = $false
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
                    Name                              = 'ContosoCustomPolicy'
                    EndUserQuarantinePermissionsValue = 23
                    ESNEnabled                         = $true
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
                    Name                              = 'ContosoNoAccessPolicy'
                    EndUserQuarantinePermissionsValue = 0
                    ESNEnabled                         = $false
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
    # -not $null is $true and $null -gt 0 is $false, so the policy falls through to the
    # else branch and is graded on two values that were never read.
    Context 'A custom quarantine policy omits ESNEnabled and EndUserQuarantinePermissionsValue' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy' }
            }
        }

        # Pins current behaviour, which is wrong: the check reports the notification
        # settings as consistent with the permissions granted to end users when it read
        # neither the notification setting nor the permissions. Per the repo's own rule
        # an absent property must not yield Pass. Left pinned rather than corrected here
        # so the defect is visible and cannot change unnoticed.
        It 'Currently returns Pass on two properties that were never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'ContosoCustomPolicy'
            $results[0].Finding | Should -Match 'Notification settings are consistent'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }

    # The Warning fires on a conjunction of a negative and a positive: notifications off
    # AND end-user permissions granted. Dropping or flipping either half turns the check
    # into one that flags every policy or no policy, so all three combinations that
    # decide the verdict are pinned.
    Context 'Inverted-sense regression guard' {
        It 'Warns only when ESNEnabled is false while end-user permissions are granted' {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissionsValue = 23; ESNEnabled = $false }
            }
            (& $checkFile)[0].Result | Should -Be 'Warning'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissionsValue = 23; ESNEnabled = $true }
            }
            (& $checkFile)[0].Result | Should -Be 'Pass'

            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ Name = 'ContosoCustomPolicy'; EndUserQuarantinePermissionsValue = 0; ESNEnabled = $false }
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
    # Block filter, so an entry the check did read is counted as neither.
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

        # Pins current behaviour, which is wrong: the list is reported as well-maintained
        # on a count of zero allows and zero blocks, when the one entry that was returned
        # simply carried no Action to classify it by. Per the repo's own rule an absent
        # property must not yield Pass. Left pinned rather than corrected here so the
        # defect is visible and cannot change unnoticed.
        It 'Currently returns Pass and counts an entry it did read as neither allow nor block' {
            $results = & $checkFile
            $mainResult = $results | Where-Object { $_.AffectedObject -match '^TABL' }
            $mainResult | Should -Not -BeNullOrEmpty
            $mainResult.Result | Should -Be 'Pass'
            $mainResult.AffectedObject | Should -Be 'TABL (0 allows, 0 blocks)'
            $mainResult.Finding | Should -Match 'appear well-maintained'
        }
    }
}

Describe 'MET-EXO006 Submission Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO006-SubmissionPolicy.ps1'
    }

    Context 'Reporting to Microsoft enabled with submission mailbox' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule {
                [PSCustomObject]@{ SentTo = 'secops@contoso.com' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Reporting to Microsoft disabled' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $false; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'No submission mailbox configured' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Warning and mentions mailbox' {
            $results = & $checkFile
            $mailboxResult = $results | Where-Object { $_.Name -match 'SecOps Mailbox' }
            $mailboxResult | Should -Not -BeNullOrEmpty
            $mailboxResult.Result | Should -Be 'Warning'
            $mailboxResult.Finding | Should -Match 'mailbox'
        }
    }

    Context 'Rule and policy addresses agree' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = 'secops@contoso.com' } }
        }
        It 'Returns Pass for address consistency' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Rule and policy addresses drift' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'old-secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = 'secops@contoso.com' } }
        }
        It 'Returns Warning identifying the mismatched report type and stale address' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Warning'
            $consistencyResult.Finding | Should -Match 'Junk reports go to'
            $consistencyResult.Finding | Should -Match 'old-secops@contoso.com'
        }
    }

    Context 'Rule routes reports to more than one address' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops@contoso.com', 'soc@contoso.com') } }
        }
        It 'Never renders the addresses space-joined' {
            $results = & $checkFile
            foreach ($result in $results) {
                $result.AffectedObject | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
                $result.Finding | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
            }
        }
        It 'Compares the policy addresses against the first address only' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Pass'
        }
        It 'Names the first address as the SecOps mailbox and surfaces the additional one' {
            $results = & $checkFile
            $mailboxResult = $results | Where-Object { $_.Name -match 'SecOps Mailbox' }
            $mailboxResult | Should -Not -BeNullOrEmpty
            $mailboxResult.AffectedObject | Should -Be 'Report Submission Policy (secops@contoso.com)'
            $mailboxResult.Finding | Should -Match "'secops@contoso\.com'"
            $mailboxResult.Finding | Should -Match 'soc@contoso\.com'
        }
    }

    Context 'Rule routes to more than one address and the policy has drifted' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'old-secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops@contoso.com', 'soc@contoso.com') } }
        }
        It 'Still detects the drift against the first address' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Warning'
            $consistencyResult.Finding | Should -Match 'Junk reports go to'
            $consistencyResult.Finding | Should -Match 'old-secops@contoso.com'
            $consistencyResult.Finding | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
        }
    }

    # A report submission policy object that returns none of the reporting flags leaves
    # every -eq $true comparison false, which is indistinguishable here from a tenant
    # that has genuinely switched reporting off.
    Context 'The report submission policy omits every reporting property' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ Identity = 'DefaultReportSubmissionPolicy' }
            }
            Mock Get-ReportSubmissionRule { $null }
        }

        It 'Does not return Pass on a reporting configuration it never observed' {
            $results = @(& $checkFile)
            ($results | Where-Object { $_.Result -eq 'Pass' }) | Should -BeNullOrEmpty
        }

        # Pins current behaviour, whose wording is wrong: the check reports user
        # reporting as completely disabled on the strength of properties the service
        # never returned. The verdict is fail-closed and safe, but the sentence states an
        # observation that was not made. Left pinned rather than corrected here so the
        # defect is visible and cannot change unnoticed.
        It 'Currently states reporting is completely disabled rather than that the properties were not returned' {
            $results = @(& $checkFile)
            $buttonResult = $results | Where-Object { $_.Name -match 'Report Button' }
            $buttonResult | Should -Not -BeNullOrEmpty
            $buttonResult.Result | Should -Be 'Fail'
            $buttonResult.AffectedObject | Should -Be 'Report Submission Policy'
            $buttonResult.Finding | Should -Match 'completely disabled'
            $buttonResult.Finding | Should -Not -Match 'not returned'
        }
    }
}
