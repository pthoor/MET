BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . (Join-Path $root 'Public' 'Test-METPrerequisites.ps1')
    . (Join-Path $root 'Private' 'Get-METGraphScope.ps1')
    . (Join-Path $root 'Private' 'Get-METAssemblyFileVersion.ps1')
    . (Join-Path $root 'Private' 'Get-METModuleMsalVersion.ps1')
    . (Join-Path $root 'Private' 'Test-METAssemblyLoadConflict.ps1')

    function Get-ConnectionInformation { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-MgContext { [CmdletBinding()] param() }
    function Get-MgGroup { [CmdletBinding()] param([string]$Filter,[int]$Top) }
    function Get-MgPolicyAuthorizationPolicy { [CmdletBinding()] param() }
    function Get-MgPolicyCrossTenantAccessPolicyDefault { [CmdletBinding()] param() }
    function Get-CsTenant { [CmdletBinding()] param() }
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }

    $script:Row = {
        param($Results, $Component)
        $Results | Where-Object { $_.Component -eq $Component }
    }
}

Describe 'Test-METPrerequisites -TestConnection' {
    BeforeEach {
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Module {
            switch ($Name) {
                'ExchangeOnlineManagement'         { [PSCustomObject]@{ Version = [version]'3.7.2' } }
                'Microsoft.Graph.Identity.SignIns' { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                'Microsoft.Graph.Groups'           { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                'MicrosoftTeams'                   { [PSCustomObject]@{ Version = [version]'6.0.0' } }
            }
        } -ParameterFilter { $ListAvailable }
        Mock Get-Module { $null } -ParameterFilter { -not $ListAvailable }

        Mock Get-ConnectionInformation {
            [PSCustomObject]@{ State = 'Connected'; Organization = 'contoso.onmicrosoft.com'; UserPrincipalName = 'admin@contoso.com' }
        }
        Mock Get-HostedContentFilterPolicy { [PSCustomObject]@{ Name = 'Default' } }
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account  = 'admin@contoso.com'
                TenantId = '00000000-0000-0000-0000-000000000001'
                AuthType = 'Delegated'
                Scopes   = @('Policy.Read.All', 'Group.Read.All', 'openid')
            }
        }
        Mock Get-MgGroup {}
        Mock Get-MgPolicyAuthorizationPolicy { [PSCustomObject]@{ Id = 'authorizationPolicy' } }
        Mock Get-MgPolicyCrossTenantAccessPolicyDefault { [PSCustomObject]@{ Id = 'default' } }
        Mock Get-CsTenant { [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000001'; DisplayName = 'Contoso' } }
        Mock Get-CsTenantFederationConfiguration { [PSCustomObject]@{ Identity = 'Global' } }
    }

    It 'does not probe any service without -TestConnection' {
        Test-METPrerequisites -PassThru | Out-Null

        Should -Invoke Get-ConnectionInformation -Times 0 -Exactly
        Should -Invoke Get-MgContext -Times 0 -Exactly
        Should -Invoke Get-CsTenant -Times 0 -Exactly
    }

    It 'reports every connection row as OK when every leg is connected and readable' {
        $results = Test-METPrerequisites -TestConnection -PassThru
        $connectionRows = @($results | Where-Object { $_.Component -like 'Exchange Online*' -or $_.Component -like 'Microsoft Graph*' -or $_.Component -like 'Microsoft Teams*' })

        $connectionRows.Count | Should -Be 8
        $connectionRows | ForEach-Object { $_.Status | Should -Be 'OK' -Because $_.Component }
        Test-METPrerequisites -TestConnection -Quiet | Should -BeTrue
    }

    Context 'Exchange Online' {
        It 'fails the required Exchange Online session row and skips its read probe when not connected' {
            Mock Get-ConnectionInformation { [PSCustomObject]@{ State = 'Disconnected'; Organization = 'contoso.onmicrosoft.com' } }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $session = & $script:Row $results 'Exchange Online session'
            $session.Optional | Should -BeFalse
            $session.Status | Should -BeLike 'Fail*'
            $session.Notes | Should -Match 'Connect-METSession'
            (& $script:Row $results 'Exchange Online read access').Status | Should -Be 'Skipped - not connected'
            Should -Invoke Get-HostedContentFilterPolicy -Times 0 -Exactly
            Test-METPrerequisites -TestConnection -Quiet | Should -BeFalse
        }

        It 'fails when Exchange Online is connected to more than one organization' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = 'contoso.onmicrosoft.com'; UserPrincipalName = 'admin@contoso.com' }
                [PSCustomObject]@{ State = 'Connected'; Organization = 'partner.onmicrosoft.com'; DelegatedOrganization = 'fabrikam.onmicrosoft.com'; UserPrincipalName = 'admin@partner.com' }
            }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $session = & $script:Row $results 'Exchange Online session'
            $session.Status | Should -Be 'Fail - multiple organizations'
            $session.Notes | Should -Match 'contoso\.onmicrosoft\.com'
            $session.Notes | Should -Match 'fabrikam\.onmicrosoft\.com'
            $session.Notes | Should -Match 'Disconnect-METSession'
            (& $script:Row $results 'Exchange Online read access').Status | Should -Be 'Skipped - multiple organizations'
            Should -Invoke Get-HostedContentFilterPolicy -Times 0 -Exactly
            Test-METPrerequisites -TestConnection -Quiet | Should -BeFalse
        }

        It 'names the delegated organization a session is connected to' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = 'partner.onmicrosoft.com'; DelegatedOrganization = 'fabrikam.onmicrosoft.com'; UserPrincipalName = 'admin@partner.com' }
            }

            (& $script:Row (Test-METPrerequisites -TestConnection -PassThru) 'Exchange Online session').Installed |
                Should -Match 'fabrikam\.onmicrosoft\.com'
        }

        It 'fails the read access row when the account has no Exchange role' {
            Mock Get-HostedContentFilterPolicy { throw "The term 'Get-HostedContentFilterPolicy' is not recognized as a name of a cmdlet" }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $read = & $script:Row $results 'Exchange Online read access'
            $read.Status | Should -BeLike 'Fail*'
            $read.Notes | Should -Match 'Global Reader|Security Reader'
            Test-METPrerequisites -TestConnection -Quiet | Should -BeFalse
        }
    }

    Context 'Microsoft Graph' {
        It 'reports Graph as not connected (optional) and names the AADSTS50105 enterprise-app cause' {
            Mock Get-MgContext { $null }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $session = & $script:Row $results 'Microsoft Graph session'
            $session.Optional | Should -BeTrue
            $session.Status | Should -Be 'Not connected (optional)'
            $session.Notes | Should -Match 'Microsoft Graph Command Line Tools'
            $session.Notes | Should -Match 'MET-Teams014'
            Should -Invoke Get-MgGroup -Times 0 -Exactly
            Test-METPrerequisites -TestConnection -Quiet | Should -BeTrue
        }

        It 'lists the scopes the session was not granted' {
            Mock Get-MgContext {
                [PSCustomObject]@{ Account = 'admin@contoso.com'; AuthType = 'Delegated'; Scopes = @('Group.Read.All') }
            }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $scopes = & $script:Row $results 'Microsoft Graph scopes'
            $scopes.Status | Should -Be 'Missing scopes (optional)'
            $scopes.Installed | Should -Match 'Policy.Read.All'
            $scopes.Installed | Should -Not -Match 'Group.Read.All'
            $scopes.Notes | Should -Match 'Policy\.Read\.All' -Because 'the console table prints Notes, not Installed'
        }

        It 'accepts a broader scope that covers a requested one' {
            Mock Get-MgContext {
                [PSCustomObject]@{ Account = 'admin@contoso.com'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All') }
            }

            $results = Test-METPrerequisites -TestConnection -PassThru

            (& $script:Row $results 'Microsoft Graph scopes').Status | Should -Be 'OK'
        }

        It 'reports a denied group read without failing the required prerequisites' {
            Mock Get-MgGroup { throw 'Insufficient privileges to complete the operation. Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied' }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $groups = & $script:Row $results 'Microsoft Graph read (groups)'
            $groups.Status | Should -Be 'Access denied (optional)'
            $groups.Notes | Should -Match 'Authorization_RequestDenied'
            $groups.Notes | Should -Match 'Exchange Online'
            Test-METPrerequisites -TestConnection -Quiet | Should -BeTrue
        }

        It 'reports a denied policy read as affecting MET-Teams014' {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault { throw 'Status: 403 (Forbidden)' }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $policy = & $script:Row $results 'Microsoft Graph read (policies)'
            $policy.Status | Should -Be 'Access denied (optional)'
            $policy.Notes | Should -Match 'MET-Teams014'
        }
    }

    Context 'Microsoft Teams' {
        It 'reports Teams as not connected when Get-CsTenant has no session' {
            Mock Get-CsTenant { throw 'Run Connect-MicrosoftTeams before running cmdlets.' }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $session = & $script:Row $results 'Microsoft Teams session'
            $session.Optional | Should -BeTrue
            $session.Status | Should -Be 'Not connected (optional)'
            (& $script:Row $results 'Microsoft Teams read access').Status | Should -Be 'Skipped - not connected'
            Should -Invoke Get-CsTenantFederationConfiguration -Times 0 -Exactly
        }

        It 'reports Access Denied from Get-CsTenant as a missing role, not a missing session' {
            Mock Get-CsTenant { throw 'Access Denied.' }

            $results = Test-METPrerequisites -TestConnection -PassThru

            $read = & $script:Row $results 'Microsoft Teams read access'
            $read.Status | Should -Be 'Access denied (optional)'
            $read.Notes | Should -Match 'Global Reader'
        }

        It 'reports a denied Teams settings read' {
            Mock Get-CsTenantFederationConfiguration { throw 'Access Denied.' }

            $results = Test-METPrerequisites -TestConnection -PassThru

            (& $script:Row $results 'Microsoft Teams session').Status | Should -Be 'OK'
            (& $script:Row $results 'Microsoft Teams read access').Status | Should -Be 'Access denied (optional)'
        }
    }
}
