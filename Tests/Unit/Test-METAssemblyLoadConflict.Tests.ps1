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

    Context 'Default assembly source' {
        # Microsoft.Graph.Authentication 2.41.0+ loads its own MSAL into a private
        # AssemblyLoadContext. AppDomain.GetAssemblies() returns assemblies from every context,
        # so a private copy could mask, or be mistaken for, the default-context build that
        # Exchange Online and Teams actually bind to.
        It 'Ignores an assembly loaded only into a private AssemblyLoadContext' {
            $dll = Join-Path $TestDrive 'MET.AlcProbe.dll'
            Add-Type -TypeDefinition '[assembly: System.Reflection.AssemblyVersion("1.0.0.0")] namespace METAlcProbe { public class Probe {} }' `
                -OutputAssembly $dll -OutputType Library
            $context = [System.Runtime.Loader.AssemblyLoadContext]::new('MET.AlcProbe', $true)
            try {
                # Loaded from bytes, not the path: Windows keeps a file loaded by path locked
                # until the collectible context finishes unloading, which happens after this test,
                # and TestDrive cleanup then fails. Add-Type gives the compiled assembly a
                # generated name, so read it back.
                $stream = [System.IO.MemoryStream]::new([System.IO.File]::ReadAllBytes($dll))
                try { $assemblyName = $context.LoadFromStream($stream).GetName().Name }
                finally { $stream.Dispose() }
                @([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $assemblyName }).Count |
                    Should -Be 1 -Because 'the probe assembly is visible through AppDomain.GetAssemblies()'

                Test-METAssemblyLoadConflict -AssemblyName $assemblyName -RequiredVersion '2.0.0.0' | Should -BeNullOrEmpty
            }
            finally {
                $context.Unload()
            }
        }
    }

    Context '-RequireExactVersion' {
        It 'Reports a newer loaded version as a conflict' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.83.1.0' -Location '/exo/Microsoft.Identity.Client.dll'
            )

            $result = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.82.1.0' -LoadedAssemblies $loaded -RequireExactVersion

            $result | Should -Match 'newer version'
            $result | Should -Match '4\.83\.1\.0'
            $result | Should -Match '4\.82\.1\.0'
            $result | Should -Match '/exo/Microsoft\.Identity\.Client\.dll'
        }

        It 'Still reports an older loaded version as a conflict' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.74.1.0' -Location '/exo/Microsoft.Identity.Client.dll'
            )

            Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.82.1.0' -LoadedAssemblies $loaded -RequireExactVersion |
                Should -Match 'older version'
        }

        It 'Returns $null when the loaded version is exactly the required one' {
            $loaded = @(
                New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' -Version '4.82.1.0' -Location '/graph/Microsoft.Identity.Client.dll'
            )

            Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion '4.82.1.0' -LoadedAssemblies $loaded -RequireExactVersion |
                Should -BeNullOrEmpty
        }
    }
}
