BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Get-METAssemblyFileVersion.ps1"
}

Describe 'Get-METAssemblyFileVersion' {
    Context 'Path does not exist' {
        It 'Returns $null without throwing' {
            Get-METAssemblyFileVersion -Path (Join-Path $TestDrive 'does-not-exist.dll') | Should -BeNullOrEmpty
        }
    }

    Context 'Path is a real, already-loaded .NET assembly' {
        It 'Returns the assembly version read from disk' {
            $realAssemblyPath = [psobject].Assembly.Location
            $expected = [System.Reflection.AssemblyName]::GetAssemblyName($realAssemblyPath).Version

            Get-METAssemblyFileVersion -Path $realAssemblyPath | Should -Be $expected
        }
    }
}
