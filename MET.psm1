$Private = Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -ErrorAction SilentlyContinue
$Public  = Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1"  -ErrorAction SilentlyContinue

foreach ($file in @($Private)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Warning "Failed to import $($file.FullName): $_"
    }
}

# A Public/ failure is fatal. Export-ModuleMember below publishes every BaseName in
# Public/ whether or not its dot-source succeeded, so warning here produced a module
# that imported cleanly and was missing a command at call time, far from the cause.
foreach ($file in @($Public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to import $($file.FullName): $_"
    }
}

# Public function names are the file BaseNames. Aliases are declared here rather than
# with New-Alias inside each file so the manifest and the loader have one shared list;
# MET.Module.Tests.ps1 asserts the two agree in both directions.
$Aliases = @{
    'Invoke-METTriage' = 'Invoke-METAssessment'
}

foreach ($alias in $Aliases.GetEnumerator()) {
    Set-Alias -Name $alias.Key -Value $alias.Value -Scope Script
}

Export-ModuleMember -Function ($Public | Select-Object -ExpandProperty BaseName) `
                    -Alias $Aliases.Keys
