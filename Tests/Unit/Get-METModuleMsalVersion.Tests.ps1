BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Get-METAssemblyFileVersion.ps1"
    . "$root/Private/Get-METModuleMsalVersion.ps1"
}

Describe 'Get-METModuleMsalVersion' {
    BeforeEach {
        $script:moduleBase = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:moduleBase | Out-Null
    }

    It 'Reads the PowerShell 7 build from <Folder>' -ForEach @(
        @{ Folder = 'netCore' }
        @{ Folder = 'Dependencies/Core' }
        @{ Folder = 'netcoreapp3.1' }
    ) {
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' } -ParameterFilter {
            $Path -eq (Join-Path $script:moduleBase $Folder 'Microsoft.Identity.Client.dll')
        }
        Mock Get-METAssemblyFileVersion { $null }

        Get-METModuleMsalVersion -ModuleBase $script:moduleBase | Should -Be ([version]'4.83.1.0')
    }

    It 'Falls back to searching the module, skipping .NET Framework builds' {
        foreach ($folder in 'net472', 'lib/net8.0') {
            $dir = Join-Path $script:moduleBase $folder
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -Path (Join-Path $dir 'Microsoft.Identity.Client.dll') -Value ''
        }
        Mock Get-METAssemblyFileVersion { [version]'4.90.0.0' } -ParameterFilter { $Path -like '*net8.0*' }
        Mock Get-METAssemblyFileVersion { [version]'4.10.0.0' } -ParameterFilter { $Path -like '*net472*' }
        Mock Get-METAssemblyFileVersion { $null }

        Get-METModuleMsalVersion -ModuleBase $script:moduleBase | Should -Be ([version]'4.90.0.0')
    }

    It 'Returns $null when the module bundles no MSAL' {
        Get-METModuleMsalVersion -ModuleBase $script:moduleBase | Should -BeNullOrEmpty
    }
}
