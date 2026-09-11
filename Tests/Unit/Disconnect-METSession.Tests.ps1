BeforeAll {
    $script:ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Import-Module (Join-Path $script:ModuleRoot 'MET.psd1') -Force -ErrorAction Stop

    & (Get-Module MET) {
        Set-Item -Path 'function:script:Get-ConnectionInformation' -Value { }
        Set-Item -Path 'function:script:Disconnect-ExchangeOnline' -Value { }
        Set-Item -Path 'function:script:Get-MgContext' -Value { }
        Set-Item -Path 'function:script:Disconnect-MgGraph' -Value { }
        Set-Item -Path 'function:script:Get-CsTenant' -Value { }
        Set-Item -Path 'function:script:Disconnect-MicrosoftTeams' -Value { }
    }
}

Describe 'Disconnect-METSession Teams classification' {
    # The real not-connected error is 'Session is not established, run
    # Connect-MicrosoftTeams...'. Only CommandNotFoundException was classified as
    # never-connected, so this hit the fail-closed throw, $script:METConnection was
    # never cleared, and the next Connect-METSession -DelegatedOrganization customerB
    # threw 'Run Disconnect-METSession first' - advice that could never succeed.
    # Triggered by every -SkipTeams run.
    It 'treats "session is not established" as not connected' {
        InModuleScope 'MET' {
            $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
            $script:METSessionInfo = @{ ServicesConnected = @('ExchangeOnline') }

            Mock -CommandName 'Get-CsTenant' -MockWith {
                throw 'Session is not established, run Connect-MicrosoftTeams before running this cmdlet.'
            }

            Disconnect-METSession -WarningAction SilentlyContinue

            $script:METConnection | Should -BeNullOrEmpty
        }
    }

    It 'skips the probe entirely when Teams was never connected this session' {
        InModuleScope 'MET' {
            $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
            $script:METSessionInfo = @{ ServicesConnected = @('ExchangeOnline') }

            Mock -CommandName 'Get-CsTenant' -MockWith { throw 'should not be called' }

            Disconnect-METSession -WarningAction SilentlyContinue

            Should -Invoke -CommandName 'Get-CsTenant' -Times 0
            $script:METConnection | Should -BeNullOrEmpty
        }
    }

    # ServicesConnected is rebuilt fresh on every Connect-METSession call, so a second
    # connect for the same tenant/org with -SkipTeams (permitted - no guard fires) drops
    # 'Teams' from the list while the Teams session from the first call is still live.
    # Gating the probe on ServicesConnected alone then skipped it, recorded no failure and
    # cleared the tracking with Teams still authenticated to customer A.
    It 'still probes when ServicesConnected omits Teams but the module is loaded' {
        InModuleScope 'MET' {
            $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
            $script:METSessionInfo = @{ ServicesConnected = @('ExchangeOnline') }

            Mock -CommandName 'Get-Module' -ParameterFilter { $Name -eq 'MicrosoftTeams' } -MockWith {
                [PSCustomObject]@{ Name = 'MicrosoftTeams'; Version = [version]'7.9.0' }
            }
            Mock -CommandName 'Get-CsTenant' -MockWith { [PSCustomObject]@{ TenantId = 'aaaa' } }
            Mock -CommandName 'Disconnect-MicrosoftTeams' -MockWith { }

            Disconnect-METSession -WarningAction SilentlyContinue

            Should -Invoke -CommandName 'Get-CsTenant' -Times 1 -Exactly
            Should -Invoke -CommandName 'Disconnect-MicrosoftTeams' -Times 1 -Exactly
            $script:METConnection | Should -BeNullOrEmpty
        }
    }

    # The fail-closed intent is correct and must survive: an ambiguous failure while a
    # session may still be live must not clear the tracking the reuse guard depends on.
    It 'still fails closed on a genuinely ambiguous probe failure' {
        InModuleScope 'MET' {
            $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
            $script:METSessionInfo = @{ ServicesConnected = @('ExchangeOnline','Teams') }

            Mock -CommandName 'Get-CsTenant' -MockWith { throw 'The remote server returned an error: (503) Server Unavailable.' }

            Disconnect-METSession -WarningAction SilentlyContinue

            $script:METConnection | Should -Not -BeNullOrEmpty
        }
    }
}
