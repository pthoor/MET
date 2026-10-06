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
                        Identity                   = 'Global'
                        EnableFederationAccess     = $false
                        EnablePublicCloudAccess    = $false
                        EnableTeamsConsumerAccess  = $true
                        EnableTeamsConsumerInbound = $true
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

    Context 'multiple non-Global policies re-open federation the Global policy closes' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'SalesTeam'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'ExecTeam'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns one Warning result per flagged policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results | ForEach-Object { $_.Result | Should -Be 'Warning' }
            ($results.AffectedObject) | Should -Contain 'SalesTeam'
            ($results.AffectedObject) | Should -Contain 'ExecTeam'
        }
    }

    # Regression guard: with Global EnableFederationAccess = $true, custom policies with the
    # same value used to be warned as "undoing any tenant-wide federation restriction set on
    # the Global policy" - a restriction that did not exist.
    Context 'Global leaves federation open and a custom policy matches it' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'FederationOnly'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'NoFederation'; EnableFederationAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns a single Pass - matching an open baseline is not drift' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Global closes federation but a custom policy does not return EnableFederationAccess' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'Tag:Legacy'; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns Warning stating federation drift was not established' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'EnableFederationAccess'
            $results[0].Finding | Should -Match 'not established'
        }
    }

    Context 'Global does not return EnableFederationAccess while custom policies exist' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'Tag:Any'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Reports the federation baseline as NotApplicable rather than passing it' {
            $na = @(& $checkFile) | Where-Object Result -eq 'NotApplicable'
            $na.AffectedObject | Should -Be 'Global'
            $na.Finding | Should -Match 'EnableFederationAccess'
            $na.Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'no Global policy is returned while custom policies exist' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @([PSCustomObject]@{ Identity = 'Tag:Any'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true })
            }
        }
        It 'Reports the baseline as NotApplicable and never Passes silently' {
            $results = @(& $checkFile)
            ($results | Where-Object Result -eq 'NotApplicable').Count | Should -Be 1
        }
    }

    # EnablePublicCloudAccess is not on the current Set-CsExternalAccessPolicy syntax and was
    # not returned by MicrosoftTeams 7.9.0; it is no longer read.
    Context 'a custom policy carries the retired EnablePublicCloudAccess property' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'OldSkype'; EnableFederationAccess = $false; EnablePublicCloudAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Does not flag it' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'EnablePublicCloudAccess'
        }
    }

    Context 'Global closes unmanaged-account access and a custom policy re-opens it' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Recruiters'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns Warning naming both consumer properties and the inbound exposure' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Tag:Recruiters'
            $results[0].Finding | Should -Match 'EnableTeamsConsumerAccess'
            $results[0].Finding | Should -Match 'EnableTeamsConsumerInbound'
            $results[0].Finding | Should -Match 'unmanaged'
            $results[0].Finding | Should -Match 'AllowTeamsConsumer'
            $results[0].Recommendation | Should -Match "Set-CsExternalAccessPolicy -Identity 'Tag:Recruiters'"
        }
        It 'Does not describe the policy as re-opening federation' {
            (@(& $checkFile))[0].Finding | Should -Not -Match 'EnableFederationAccess'
        }
    }

    Context 'Global closes unmanaged-account access and the custom policy keeps it closed' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Finance'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns Pass - inbound alone does nothing while access itself is off' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Global allows outbound unmanaged-account chat but blocks inbound, and a custom policy opens inbound' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Support'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns Warning naming only the inbound property' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'EnableTeamsConsumerInbound'
            $results[0].Finding | Should -Not -Match 'EnableTeamsConsumerAccess enabled|\(EnableTeamsConsumerAccess'
        }
    }

    Context 'Global leaves unmanaged-account access open' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true },
                    [PSCustomObject]@{ Identity = 'Tag:Any'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                )
            }
        }
        It 'Returns Pass - a custom policy matching an open baseline is not drift' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Global closes unmanaged-account access but a custom policy does not return the property' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Legacy'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false }
                )
            }
        }
        It 'Returns Warning stating the drift was not established, rather than Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Be 'Tag:Legacy'
            $results[0].Finding | Should -Match 'not established'
        }
    }

    Context 'Global does not return the unmanaged-account properties while custom policies exist' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Any'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true }
                )
            }
        }
        It 'Flags the exposed policy by name instead of silently passing it alongside the NotApplicable baseline' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $na = $results | Where-Object Result -eq 'NotApplicable'
            $na.AffectedObject | Should -Be 'Global'
            $na.Finding | Should -Match 'not established'
            $na.Finding | Should -Match 'rather than a pass'
            $na.Error | Should -Not -BeNullOrEmpty
            # Tag:Any's own EnableTeamsConsumerAccess is $true while Global never returns it -
            # that must be named here, not folded into a silent Pass (the bug the aggregation
            # fix in Invoke-METAssessment and this per-policy loop both close).
            $warn = $results | Where-Object Result -eq 'Warning'
            $warn.AffectedObject | Should -Be 'Tag:Any'
            $warn.Finding | Should -Match 'EnableTeamsConsumerAccess'
            $warn.Finding | Should -Match 'not established'
            ($results | Where-Object Result -eq 'Pass') | Should -BeNullOrEmpty
        }
    }

    Context 'a custom policy re-opens both federation and unmanaged-account access' {
        BeforeAll {
            Mock Get-CsExternalAccessPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; EnableFederationAccess = $false; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $false },
                    [PSCustomObject]@{ Identity = 'Tag:Wide'; EnableFederationAccess = $true; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $false }
                )
            }
        }
        It 'Returns one Warning for the policy covering both' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Finding | Should -Match 'EnableFederationAccess'
            $results[0].Finding | Should -Match 'EnableTeamsConsumerAccess'
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
