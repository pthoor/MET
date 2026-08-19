BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlet needed by Teams009
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
}

Describe 'MET-Teams009 Trial Tenant Federation Exposure' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams009-TrialTenantFederation.ps1'
    }

    Context 'trial tenant access allowed' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    ExternalAccessWithTrialTenants = 'Allowed'
                    AllowedTrialTenantDomains       = @()
                }
            }
        }
        It 'Returns Fail and Finding mentions trial tenants' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'trial'
        }
    }

    Context 'trial tenant access blocked' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    ExternalAccessWithTrialTenants = 'Blocked'
                    AllowedTrialTenantDomains       = @()
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'trial tenant access blocked with an explicit allow-list of trial domains' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    ExternalAccessWithTrialTenants = 'Blocked'
                    AllowedTrialTenantDomains       = @('trusted-trial.onmicrosoft.com')
                }
            }
        }
        It 'Returns Pass and Finding mentions the allowed trial domains' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'trusted-trial.onmicrosoft.com'
        }
    }

    Context 'unrecognized or null value' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    ExternalAccessWithTrialTenants = $null
                    AllowedTrialTenantDomains       = @()
                }
            }
        }
        It 'Returns Warning' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'unrecognized|missing'
        }
    }

    Context 'cmdlet throws (module absent)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Teams federation configuration unavailable' }
        }
        It 'Returns Fail with ErrorMessage populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Teams federation configuration unavailable'
        }
    }
}
