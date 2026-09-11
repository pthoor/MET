function Get-METCheck {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType('MET.CheckInfo')]
    param(
        [Parameter()]
        [string[]] $CheckId,

        [Parameter()]
        [ValidateSet('MDO','EXO','Teams')]
        [string[]] $Category,

        [Parameter()]
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string[]] $Severity
    )

    $checksRoot = Join-Path $PSScriptRoot '..' 'Checks'

    # Discovered exactly the way Invoke-METAssessment discovers them (:66-67), so the
    # dry-run listing and the real run can never disagree about what exists or what order
    # it runs in.
    $checks = Get-ChildItem -LiteralPath $checksRoot -Recurse -Filter 'MET-*.ps1' |
        Sort-Object Name |
        ForEach-Object { Get-METCheckMetadata -Path $_.FullName }

    if ($Category) { $checks = $checks | Where-Object { $Category -contains $_.Category } }
    if ($CheckId)  { $checks = $checks | Where-Object { $CheckId  -contains $_.CheckId  } }
    if ($Severity) { $checks = $checks | Where-Object { $Severity -contains $_.Severity } }

    $checks
}
