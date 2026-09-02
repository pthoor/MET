BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"

    # Stub EXO/DNS cmdlets
    function Get-AcceptedDomain              { [CmdletBinding()] param() }
    function Resolve-DnsName                 { [CmdletBinding()] param([string]$Name,[string]$Type,[switch]$DnsOnly,[switch]$ErrorAction) }
    function Resolve-METDnsName             { [CmdletBinding()] param([string]$Name,[string]$Type) }
    function Get-DkimSigningConfig           { [CmdletBinding()] param() }
    function Get-QuarantinePolicy            { [CmdletBinding()] param() }
    function Get-TenantAllowBlockListItems   { [CmdletBinding()] param([string]$ListType,[string]$ListSubType) }
    function Get-ReportSubmissionPolicy      { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule        { [CmdletBinding()] param() }
    function Get-TransportRule               { [CmdletBinding()] param([string]$ResultSize) }
}

Describe 'MET-EXO001 DMARC' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO001-DMARC.ps1'
    }

    Context 'mail.onmicrosoft.com accepted domain' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.mail.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
        }

        It 'Returns NotApplicable' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Informational'
        }
    }

    Context 'onmicrosoft domain without DMARC record' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'DNS name not found' }
        }

        It 'Returns Warning with the lookup error instead of a false Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'DNS lookup failed'
            $results[0].Error | Should -Match 'DNS name not found'
        }
    }
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
}

Describe 'MET-EXO003 SPF' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO003-SPF.ps1'
    }

    Context 'SPF lookup counting includes bare mechanisms and redirect' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }

            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                switch ($Name) {
                    'contoso.com' {
                        return [PSCustomObject]@{
                            Strings = @('v=spf1 a mx include:_spf1.contoso.com include:_spf2.contoso.com include:_spf3.contoso.com include:_spf4.contoso.com include:_spf5.contoso.com redirect=_spf6.contoso.com -all')
                        }
                    }
                    { $_ -match '^_spf[1-6]\.contoso\.com$' } {
                        return [PSCustomObject]@{ Strings = @('v=spf1 a mx -all') }
                    }
                    default {
                        return @()
                    }
                }
            }
        }

        It 'Returns Warning for more than 10 lookups' {
            $results = & $checkFile
            $result = $results | Select-Object -First 1
            $result.Result | Should -Be 'Warning'
            $result.Finding | Should -Match 'exceeds 10 DNS lookups'
        }
    }

    Context 'DNS lookup fails' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'resolver unavailable' }
        }

        It 'Returns Warning with the lookup error instead of a false Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'DNS lookup failed'
            $results[0].Error | Should -Match 'resolver unavailable'
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
}

Describe 'MET-EXO005 Tenant Allow/Block List' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO005-TenantAllowBlockList.ps1'
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

        It 'Does not emit an Advanced Delivery result' {
            $results = & $checkFile
            $advResult = $results | Where-Object { $_.AffectedObject -match 'Advanced Delivery' }
            $advResult | Should -BeNullOrEmpty
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
}
