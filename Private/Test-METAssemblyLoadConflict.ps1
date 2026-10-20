function Test-METAssemblyLoadConflict {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $AssemblyName,

        [Parameter(Mandatory)]
        [version] $RequiredVersion,

        [Parameter()]
        [object[]] $LoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies(),

        # .NET resolves a request for an older assembly version against an already-loaded
        # newer one, so by default only a downgrade is a conflict. That is not enough for
        # code compiled against one exact build: Microsoft.Graph.Authentication before 2.41.0
        # calls MSAL methods whose signatures changed in later builds, so a newer loaded MSAL
        # fails with MissingMethodException. Set this to treat any difference as a conflict.
        [Parameter()]
        [switch] $RequireExactVersion
    )

    $loaded = $LoadedAssemblies | Where-Object { $_.GetName().Name -eq $AssemblyName } | Select-Object -First 1
    if (-not $loaded) {
        return $null
    }

    $loadedVersion = $loaded.GetName().Version
    if ($loadedVersion -eq $RequiredVersion -or ($loadedVersion -gt $RequiredVersion -and -not $RequireExactVersion)) {
        return $null
    }

    if ($loadedVersion -gt $RequiredVersion) {
        return "A newer version of $AssemblyName ($loadedVersion, loaded from '$($loaded.Location)') is already active in this PowerShell session, and the module being loaded was built against $AssemblyName $RequiredVersion exactly, which is not compatible with it. .NET cannot load a second version of the assembly into the same context."
    }

    "An older version of $AssemblyName ($loadedVersion, loaded from '$($loaded.Location)') is already active in this PowerShell session and cannot be reconciled with the newer version required here ($RequiredVersion). .NET cannot unload or replace an assembly once a process has loaded it. This is typically caused by an earlier Import-Module or Connect- call to MicrosoftTeams, Microsoft.Graph, or Az in the same session. Restart PowerShell, then run Connect-METSession again before touching any other Microsoft 365 module."
}
