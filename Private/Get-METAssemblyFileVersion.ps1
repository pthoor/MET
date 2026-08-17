function Get-METAssemblyFileVersion {
    [CmdletBinding()]
    [OutputType([version])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    [System.Reflection.AssemblyName]::GetAssemblyName($Path).Version
}
