BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlet needed by Teams008
    function Get-CsTeamsAppPermissionPolicy { [CmdletBinding()] param() }
}

Describe 'MET-Teams008 App Permission Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams008-AppPermissionPolicy.ps1'
    }

    Context 'Global policy fully restricted to allow-lists' {
        BeforeAll {
            Mock Get-CsTeamsAppPermissionPolicy {
                [PSCustomObject]@{
                    Identity                = 'Global'
                    GlobalCatalogAppsType   = 'AllowedAppList'
                    DefaultCatalogAppsType  = 'AllowedAppList'
                    PrivateCatalogAppsType  = 'AllowedAppList'
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Global policy has an unrestricted catalog' {
        BeforeAll {
            Mock Get-CsTeamsAppPermissionPolicy {
                [PSCustomObject]@{
                    Identity                = 'Global'
                    GlobalCatalogAppsType   = 'AllowAllApps'
                    DefaultCatalogAppsType  = 'AllowedAppList'
                    PrivateCatalogAppsType  = 'AllowedAppList'
                }
            }
        }
        It 'Returns Warning and mentions the unrestricted property' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match "GlobalCatalogAppsType is 'AllowAllApps'"
        }
    }

    Context 'multiple policies, one custom policy unrestricted' {
        BeforeAll {
            Mock Get-CsTeamsAppPermissionPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                = 'Global'
                        GlobalCatalogAppsType   = 'AllowedAppList'
                        DefaultCatalogAppsType  = 'AllowedAppList'
                        PrivateCatalogAppsType  = 'AllowedAppList'
                    },
                    [PSCustomObject]@{
                        Identity                = 'Sales'
                        GlobalCatalogAppsType   = 'AllowedAppList'
                        DefaultCatalogAppsType  = 'AllowAllApps'
                        PrivateCatalogAppsType  = 'AllowedAppList'
                    }
                )
            }
        }
        It 'Returns Warning and mentions the Sales policy' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match "Policy 'Sales'"
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-CsTeamsAppPermissionPolicy { throw 'Teams app permission policy unavailable' }
        }
        It 'Returns Warning instead of an unhandled error' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Could not retrieve'
        }
    }
}
