BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-SharingPolicy { [CmdletBinding()] param() }
}

Describe 'MET-EXO022 Calendar and Contact Sharing Policies' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO022-SharingPolicy.ps1'
    }

    Context 'Wildcard entry shares only simple free/busy' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Default Sharing Policy'
                    Enabled = $true
                    Default = $true
                    Domains = @('*:CalendarSharingFreeBusySimple')
                }
            }
        }

        It 'Returns Pass and says so explicitly' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].CheckId | Should -Be 'MET-EXO022'
            $results[0].AffectedObject | Should -Be 'Default Sharing Policy (default)'
            $results[0].Finding | Should -Match 'share simple free/busy only'
        }
    }

    Context 'Wildcard entry shares calendar detail' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Default Sharing Policy'
                    Enabled = $true
                    Default = $true
                    Domains = @('*:CalendarSharingFreeBusyDetail')
                }
            }
        }

        It 'Returns Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'CalendarSharingFreeBusyDetail'
            $results[0].Finding | Should -Match 'internal-impersonation phish'
            $results[0].Metadata.PermissiveEntryCount | Should -Be 1
        }
    }

    Context 'Anonymous entry grants reviewer access' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Anon Policy'
                    Enabled = $true
                    Default = $false
                    Domains = @('Anonymous:CalendarSharingFreeBusyReviewer')
                }
            }
        }

        It 'Returns Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Be 'Anon Policy'
            $results[0].Finding | Should -Match 'Anonymous:CalendarSharingFreeBusyReviewer'
        }
    }

    Context 'Wildcard entry carries comma-joined actions including contacts sharing' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Combo Policy'
                    Enabled = $true
                    Default = $false
                    Domains = @('*:CalendarSharingFreeBusySimple,ContactsSharing')
                }
            }
        }

        It 'Returns Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'ContactsSharing'
        }
    }

    Context 'Sharing is scoped to named partner domains' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Partner Policy'
                    Enabled = $true
                    Default = $false
                    Domains = @('contoso.com:ContactsSharing', 'fabrikam.com:CalendarSharingFreeBusyDetail')
                }
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'no wildcard or anonymous entries'
            $results[0].Metadata.DomainEntryCount | Should -Be 2
        }
    }

    Context 'Policy is disabled' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Old Policy'
                    Enabled = $false
                    Default = $false
                    Domains = @('*:ContactsSharing')
                }
            }
        }

        It 'Returns Info rather than Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'exists but is disabled'
        }
    }

    Context 'Domains is missing or null' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{ Name = 'Bare Policy'; Enabled = $true }
            }
        }

        It 'Treats missing Domains as empty and returns Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Error | Should -BeNullOrEmpty
            $results[0].Finding | Should -Match 'no sharing domain entries'
        }
    }

    Context 'Domains contains empty and separator-less entries' {
        BeforeAll {
            Mock Get-SharingPolicy {
                [PSCustomObject]@{
                    Name    = 'Odd Policy'
                    Enabled = $true
                    Default = $false
                    Domains = @('', '   ', '*')
                }
            }
        }

        It 'Treats a bare wildcard with no action as free/busy only' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Error | Should -BeNullOrEmpty
            $results[0].Metadata.DomainEntryCount | Should -Be 1
        }
    }

    Context 'Multiple policies' {
        BeforeAll {
            Mock Get-SharingPolicy {
                @(
                    [PSCustomObject]@{ Name = 'Default Sharing Policy'; Enabled = $true; Default = $true; Domains = @('*:CalendarSharingFreeBusySimple') }
                    [PSCustomObject]@{ Name = 'Loose Policy'; Enabled = $true; Default = $false; Domains = @('*:ContactsSharing') }
                )
            }
        }

        It 'Emits one result per policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results[0].Result | Should -Be 'Pass'
            $results[1].Result | Should -Be 'Warning'
            $results[1].AffectedObject | Should -Be 'Loose Policy'
        }
    }

    Context 'No sharing policies exist' {
        BeforeAll {
            Mock Get-SharingPolicy { @() }
        }

        It 'Returns a single Info result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'No sharing policies are configured'
        }
    }

    Context 'Get-SharingPolicy throws' {
        BeforeAll {
            Mock Get-SharingPolicy { throw 'Access denied' }
        }

        It 'Returns Fail with error message populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].CheckId | Should -Be 'MET-EXO022'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
