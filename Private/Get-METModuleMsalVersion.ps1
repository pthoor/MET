function Get-METModuleMsalVersion {
    # Returns the version of the Microsoft.Identity.Client (MSAL) build a module loads on
    # PowerShell 7, read from the file without loading it. Each Microsoft 365 module keeps that
    # build in a different folder, so the known ones are tried first and the module is searched
    # as a fallback, skipping the .NET Framework builds Windows PowerShell would load instead.
    [CmdletBinding()]
    [OutputType([version])]
    param(
        [Parameter(Mandatory)]
        [string] $ModuleBase
    )

    foreach ($folder in @('netCore', (Join-Path 'Dependencies' 'Core'), 'netcoreapp3.1')) {
        $version = Get-METAssemblyFileVersion -Path (Join-Path $ModuleBase $folder 'Microsoft.Identity.Client.dll')
        if ($version) {
            return $version
        }
    }

    $candidates = Get-ChildItem -LiteralPath $ModuleBase -Recurse -File -Filter 'Microsoft.Identity.Client.dll' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](net4\d*|netFramework|Desktop)[\\/]' }
    foreach ($candidate in $candidates) {
        $version = Get-METAssemblyFileVersion -Path $candidate.FullName
        if ($version) {
            return $version
        }
    }

    $null
}
