BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Public/Test-METPrerequisites.ps1"
    . "$root/Private/Get-METAssemblyFileVersion.ps1"
    . "$root/Private/Get-METModuleMsalVersion.ps1"
    . "$root/Private/Test-METAssemblyLoadConflict.ps1"

    $script:Row = {
        param($Results, $Component)
        $Results | Where-Object { $_.Component -eq $Component }
    }

    $script:Installed = @{
        'ExchangeOnlineManagement'         = '3.10.1'
        'Microsoft.Graph.Authentication'   = '2.41.1'
        'Microsoft.Graph.Identity.SignIns' = '2.41.1'
        'Microsoft.Graph.Groups'           = '2.41.1'
        'MicrosoftTeams'                   = '7.9.0'
    }
    $script:Msal = @{
        'ExchangeOnlineManagement'       = '4.83.1.0'
        'Microsoft.Graph.Authentication' = '4.90.0.0'
        'MicrosoftTeams'                 = '4.82.0.0'
    }
}

Describe 'Test-METPrerequisites module compatibility' {
    BeforeEach {
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Module {
            $moduleName = @($Name)[0]
            $version = $script:Installed[$moduleName]
            if ($version) {
                [PSCustomObject]@{ Name = $moduleName; Version = [version]$version; ModuleBase = "/fake/$moduleName/$version" }
            }
        } -ParameterFilter { $ListAvailable }
        Mock Get-Module { $null } -ParameterFilter { -not $ListAvailable }
        Mock Get-METModuleMsalVersion {
            $name = ($ModuleBase -split '/')[2]
            if ($script:Msal[$name]) { [version]$script:Msal[$name] }
        }
        Mock Test-METAssemblyLoadConflict { $null }
    }

    It 'Checks Microsoft.Graph.Authentication as its own optional row' {
        $auth = & $script:Row (Test-METPrerequisites -PassThru) 'Microsoft.Graph.Authentication'

        $auth.Optional | Should -BeTrue
        $auth.Status | Should -Be 'OK'
    }

    It 'Reports both compatibility rows as OK for Graph 2.41.1, Exchange Online 3.10.1 and Teams 7.9.0' {
        $results = Test-METPrerequisites -PassThru

        (& $script:Row $results 'Graph and Exchange Online (MSAL)').Status | Should -Be 'OK'
        (& $script:Row $results 'Teams and Exchange Online (MSAL)').Status | Should -Be 'OK'
        (& $script:Row $results 'MSAL loaded in this session').Status | Should -Be 'OK'
    }

    Context 'Graph before 2.41.0 with a different MSAL than Exchange Online' {
        BeforeEach {
            $script:Installed['Microsoft.Graph.Authentication'] = '2.39.0'
            $script:Installed['Microsoft.Graph.Groups'] = '2.39.0'
            $script:Installed['Microsoft.Graph.Identity.SignIns'] = '2.39.0'
            $script:Msal['Microsoft.Graph.Authentication'] = '4.82.1.0'
        }
        AfterEach {
            $script:Installed['Microsoft.Graph.Authentication'] = '2.41.1'
            $script:Installed['Microsoft.Graph.Groups'] = '2.41.1'
            $script:Installed['Microsoft.Graph.Identity.SignIns'] = '2.41.1'
            $script:Msal['Microsoft.Graph.Authentication'] = '4.90.0.0'
        }

        It 'Flags the combination as incompatible, names both MSAL builds, and gives the upgrade for every Graph module' {
            $graph = & $script:Row (Test-METPrerequisites -PassThru) 'Graph and Exchange Online (MSAL)'

            $graph.Optional | Should -BeTrue
            $graph.Status | Should -Be 'Incompatible (optional)'
            $graph.Installed | Should -Match '4\.82\.1\.0'
            $graph.Installed | Should -Match '4\.83\.1\.0'
            $graph.Notes | Should -Match '''Microsoft\.Graph\.Authentication'', ''Microsoft\.Graph\.Groups'', ''Microsoft\.Graph\.Identity\.SignIns'' \| ForEach-Object \{ Install-Module -Name \$_ -MinimumVersion 2\.41\.0'
            $graph.Notes | Should -Not -Match 'Install-Module [\w.]+, '
        }

        It 'Does not fail the required prerequisites' {
            Test-METPrerequisites -Quiet | Should -BeTrue
        }

        It 'Reports Graph before 2.41.0 as OK when its MSAL matches Exchange Online exactly' {
            $script:Msal['Microsoft.Graph.Authentication'] = '4.83.1.0'

            (& $script:Row (Test-METPrerequisites -PassThru) 'Graph and Exchange Online (MSAL)').Status | Should -Be 'OK'
        }
    }

    Context 'Graph submodules on a different version than Microsoft.Graph.Authentication' {
        BeforeEach { $script:Installed['Microsoft.Graph.Groups'] = '2.39.0' }
        AfterEach { $script:Installed['Microsoft.Graph.Groups'] = '2.41.1' }

        It 'Flags the submodule, because each one pins Microsoft.Graph.Authentication to its own version' {
            $results = Test-METPrerequisites -PassThru

            $groups = & $script:Row $results 'Microsoft.Graph.Groups'
            $groups.Status | Should -Be 'Version mismatch (optional)'
            $groups.Notes | Should -Match '2\.41\.1'
            $groups.Notes | Should -Match 'ForEach-Object \{ Install-Module -Name \$_'
            $groups.Notes | Should -Not -Match 'Install-Module [\w.]+, '
            (& $script:Row $results 'Microsoft.Graph.Identity.SignIns').Status | Should -Be 'OK'
        }
    }

    Context 'Teams bundles a newer MSAL than Exchange Online' {
        BeforeEach { $script:Msal['MicrosoftTeams'] = '4.84.0.0' }
        AfterEach { $script:Msal['MicrosoftTeams'] = '4.82.0.0' }

        It 'Flags the combination as incompatible' {
            $teams = & $script:Row (Test-METPrerequisites -PassThru) 'Teams and Exchange Online (MSAL)'

            $teams.Status | Should -Be 'Incompatible (optional)'
            $teams.Notes | Should -Match 'Exchange Online first'
        }
    }

    Context 'An older MSAL than Exchange Online needs is already loaded in this session' {
        It 'Fails the required prerequisites and says to restart PowerShell' {
            Mock Test-METAssemblyLoadConflict { 'An older version of Microsoft.Identity.Client (4.82.0.0) is already active in this PowerShell session.' }

            $results = Test-METPrerequisites -PassThru

            $session = & $script:Row $results 'MSAL loaded in this session'
            $session.Optional | Should -BeFalse
            $session.Status | Should -Be 'Fail - restart PowerShell'
            $session.Notes | Should -Match 'Exchange Online cannot connect'
            Test-METPrerequisites -Quiet | Should -BeFalse
        }
    }

    Context 'A module is already loaded at an older version than is installed' {
        It 'Judges the loaded version and says a restart picks up the newer one' {
            Mock Get-Module {
                [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.39.0'; ModuleBase = '/fake/Microsoft.Graph.Authentication/2.39.0' }
            } -ParameterFilter { -not $ListAvailable -and $Name -eq 'Microsoft.Graph.Authentication' }

            $auth = & $script:Row (Test-METPrerequisites -PassThru) 'Microsoft.Graph.Authentication'

            $auth.Installed | Should -Be '2.39.0'
            $auth.Notes | Should -Match 'loaded in this session'
            $auth.Notes | Should -Match '2\.41\.1'
        }

        It 'Tells the submodules to restart PowerShell, not to reinstall what is already installed' {
            Mock Get-Module {
                [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.39.0'; ModuleBase = '/fake/Microsoft.Graph.Authentication/2.39.0' }
            } -ParameterFilter { -not $ListAvailable -and $Name -eq 'Microsoft.Graph.Authentication' }

            $groups = & $script:Row (Test-METPrerequisites -PassThru) 'Microsoft.Graph.Groups'

            $groups.Status | Should -Be 'Version mismatch (optional)'
            $groups.Notes | Should -Match 'Restart PowerShell'
            $groups.Notes | Should -Not -Match 'Install-Module'
        }
    }

    Context 'A bundled MSAL version cannot be read' {
        It 'Reports the compatibility as not determined rather than OK' {
            Mock Get-METModuleMsalVersion { $null }

            (& $script:Row (Test-METPrerequisites -PassThru) 'Teams and Exchange Online (MSAL)').Status |
                Should -Be 'Not determined (optional)'
        }
    }

    Context 'A module is not installed' {
        BeforeEach { $script:Installed.Remove('MicrosoftTeams') }
        AfterEach { $script:Installed['MicrosoftTeams'] = '7.9.0' }

        It 'Skips the compatibility row for it' {
            & $script:Row (Test-METPrerequisites -PassThru) 'Teams and Exchange Online (MSAL)' | Should -BeNullOrEmpty
        }
    }
}
