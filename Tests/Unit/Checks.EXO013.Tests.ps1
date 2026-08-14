BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-TenantAllowBlockListSpoofItems { [CmdletBinding()] param([string]$Action) }
}

Describe 'MET-EXO013 Spoof Intelligence Allow-List' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO013-SpoofIntelligenceAllowList.ps1'
    }

    Context 'no allow entries' {
        BeforeAll {
            Mock Get-TenantAllowBlockListSpoofItems { @() }
        }

        It 'Returns Info with Low severity' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'No spoof intelligence allow entries found'
        }
    }

    Context 'allow entries exist, mix of Internal and External' {
        BeforeAll {
            Mock Get-TenantAllowBlockListSpoofItems {
                @(
                    [PSCustomObject]@{ SpoofedUser = 'ceo@contoso.com'; SendingInfrastructure = 'mail.evil-example.com'; SpoofType = 'External'; Action = 'Allow' }
                    [PSCustomObject]@{ SpoofedUser = 'noreply@contoso.com'; SendingInfrastructure = 'contoso.com'; SpoofType = 'Internal'; Action = 'Allow' }
                )
            }
        }

        It 'Returns Warning with High severity and mentions both entries' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Spoof Intelligence Allow List (2 entries)'
            $results[0].Finding | Should -Match 'ceo@contoso.com via mail.evil-example.com \(External\)'
            $results[0].Finding | Should -Match 'noreply@contoso.com via contoso.com \(Internal\)'
            $results[0].Finding | Should -Match '2 spoof intelligence allow entry\(ies\) found \(1 External\)'
        }
    }

    Context 'more than 10 entries' {
        BeforeAll {
            Mock Get-TenantAllowBlockListSpoofItems {
                1..12 | ForEach-Object {
                    [PSCustomObject]@{
                        SpoofedUser           = "user$_@contoso.com"
                        SendingInfrastructure = "sender$_.example.com"
                        SpoofType             = if ($_ % 2 -eq 0) { 'External' } else { 'Internal' }
                        Action                = 'Allow'
                    }
                }
            }
        }

        It 'Truncates the Finding sample list and appends the overflow count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'and 2 more'
            $results[0].Finding | Should -Not -Match 'user11@contoso.com'
            $results[0].Finding | Should -Not -Match 'user12@contoso.com'
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-TenantAllowBlockListSpoofItems { throw 'Access denied' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
