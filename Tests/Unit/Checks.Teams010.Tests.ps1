BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlet needed by Teams010
    function Get-CsExternalAccessPolicy { [CmdletBinding()] param() }
}

Describe 'MET-Teams010 Per-User External Access Policy Drift' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams010-ExternalAccessPolicyDrift.ps1'
    }

    Context 'only the Global policy exists and is restrictive' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                 = 'Global'
                        EnableFederationAccess    = $false
                        EnablePublicCloudAccess   = $false
                    }
                )
            }
        }
        It 'Returns a single Pass result' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'one non-Global policy re-opens federation access' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                = 'Global'
                        EnableFederationAccess   = $false
                        EnablePublicCloudAccess  = $false
                    },
                    [PSCustomObject]@{
                        Identity                = 'ContosoSales'
                        EnableFederationAccess   = $true
                        EnablePublicCloudAccess  = $false
                    }
                )
            }
        }
        It 'Returns one Warning result naming the flagged policy' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Be 'ContosoSales'
            $results[0].Finding | Should -Match 'ContosoSales'
        }
    }

    Context 'multiple non-Global policies re-open access' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                = 'Global'
                        EnableFederationAccess   = $false
                        EnablePublicCloudAccess  = $false
                    },
                    [PSCustomObject]@{
                        Identity                = 'SalesTeam'
                        EnableFederationAccess   = $true
                        EnablePublicCloudAccess  = $false
                    },
                    [PSCustomObject]@{
                        Identity                = 'ExecTeam'
                        EnableFederationAccess   = $false
                        EnablePublicCloudAccess  = $true
                    }
                )
            }
        }
        It 'Returns one Warning result per flagged policy' {
            $results = & $checkFile
            $results.Count | Should -Be 2
            $results | ForEach-Object { $_.Result | Should -Be 'Warning' }
            ($results.AffectedObject) | Should -Contain 'SalesTeam'
            ($results.AffectedObject) | Should -Contain 'ExecTeam'
        }
    }

    Context 'no policies returned' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy { @() }
        }
        It 'Returns a single Pass result' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'cmdlet throws (module absent)' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy { throw 'External access policy unavailable' }
        }
        It 'Returns Fail with ErrorMessage populated' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'External access policy unavailable'
        }
    }
}
