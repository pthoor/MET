BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Test-METAssemblyLoadConflict.ps1"

    function New-FakeLoadedAssembly {
        param(
            [string] $Name,
            [string] $Version,
            [string] $Location
        )

        $nameObject = [PSCustomObject]@{ Name = $Name; Version = [version]$Version }
        $fake = [PSCustomObject]@{ Location = $Location }
        $fake | Add-Member -MemberType ScriptMethod -Name GetName -Value { $nameObject }.GetNewClosure()
        $fake
    }
}

Describe 'Test-METAssemblyLoadConflict' {
    Context 'No matching assembly loaded' {
        It 'Returns $null when the assembly name is not loaded at all' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'System.Private.CoreLib' -Version '8.0.0.0' -Location '/fake/corelib.dll'
            )

            Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.83.1.0' -LoadedAssemblies $loaded |
                Should -BeNullOrEmpty
        }
    }

    Context 'Matching assembly loaded at the required version' {
        It 'Returns $null when the loaded version matches the required version' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.83.1.0' -Location '/exo/Microsoft.Identity.Client.dll'
            )

            Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.83.1.0' -LoadedAssemblies $loaded |
                Should -BeNullOrEmpty
        }
    }

    Context 'A newer version than required is already loaded' {
        It 'Returns $null - .NET resolves an older version request against a newer loaded assembly' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.83.1.0' -Location '/exo/Microsoft.Identity.Client.dll'
            )

            Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.82.1.0' -LoadedAssemblies $loaded |
                Should -BeNullOrEmpty
        }
    }

    Context 'An older version than required is already loaded' {
        It 'Returns a diagnostic message naming the loaded version and its source path' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.82.0.0' -Location '/teams/Microsoft.Identity.Client.dll'
            )

            $result = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.83.1.0' -LoadedAssemblies $loaded

            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match '4\.82\.0\.0'
            $result | Should -Match '/teams/Microsoft\.Identity\.Client\.dll'
            $result | Should -Match 'Restart PowerShell'
        }

        It 'Returns a diagnostic message for a lower loaded version (4.80.0.0 vs required 4.82.1.0)' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.80.0.0' -Location '/graph/Microsoft.Identity.Client.dll'
            )

            $result = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.82.1.0' -LoadedAssemblies $loaded

            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match '4\.80\.0\.0'
        }
    }
}
