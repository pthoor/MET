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

    # Only a downgrade is a genuine conflict. .NET resolves a request for an
    # older or equal assembly version against an already-loaded newer one, but
    # never the reverse - so an equal or higher loaded version is fine.
    if (-not $loaded -or $loaded.GetName().Version -ge $RequiredVersion) {
        return $null
    }

    "An older version of $AssemblyName ($($loaded.GetName().Version), loaded from '$($loaded.Location)') is already active in this PowerShell session and cannot be reconciled with the newer version required here ($RequiredVersion). .NET cannot unload or replace an assembly once a process has loaded it. This is typically caused by an earlier Import-Module or Connect- call to MicrosoftTeams, Microsoft.Graph, or Az in the same session. Restart PowerShell, then run Connect-METSession again before touching any other Microsoft 365 module."
}
