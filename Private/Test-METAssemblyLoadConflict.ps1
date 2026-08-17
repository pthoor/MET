function Test-METAssemblyLoadConflict {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $AssemblyName,

        [Parameter(Mandatory)]
        [version] $RequiredVersion,

        [Parameter()]
        [object[]] $LoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    )

    $loaded = $LoadedAssemblies | Where-Object { $_.GetName().Name -eq $AssemblyName } | Select-Object -First 1

    if (-not $loaded -or $loaded.GetName().Version -eq $RequiredVersion) {
        return $null
    }

    "A different version of $AssemblyName ($($loaded.GetName().Version), loaded from '$($loaded.Location)') is already active in this PowerShell session and cannot be reconciled with the version required here ($RequiredVersion). .NET cannot unload or replace an assembly once a process has loaded it. This is typically caused by an earlier Import-Module or Connect- call to MicrosoftTeams, Microsoft.Graph, or Az in the same session. Restart PowerShell, then run Connect-METSession again before touching any other Microsoft 365 module."
}
