function Get-METCheck {
    <#
    .SYNOPSIS
        Lists the checks MET can run, with their category, severity, and description - without connecting to anything.

    .DESCRIPTION
        Discovers check scripts from Checks/<Category>/*.ps1 on disk, the same way
        Invoke-METAssessment discovers them, and reads each one's declared $METCheckInfo header
        (Name, Severity, Description, RequiresModule) via static AST parsing rather than
        executing the check. This means Get-METCheck runs with no Exchange Online module loaded
        and no live session at all - it is what a user runs to decide whether to connect in the
        first place, so it must not need what it is describing.

        Invoke-METAssessment -ListChecks delegates to this function, so the dry-run listing and
        the real run can never disagree about what checks exist or what order they run in.

    .PARAMETER CheckId
        Restricts the listing to specific check IDs (e.g. 'MET-MDO001'), including the 'MET-'
        prefix. An ID that matches nothing simply returns nothing, rather than throwing.

    .PARAMETER Category
        Restricts the listing to one or more categories: MDO, EXO, or Teams.

    .PARAMETER Severity
        Restricts the listing to checks whose declared severity is one or more of Critical,
        High, Medium, Low, or Informational. A check's severity is the worst severity it can
        emit - several checks emit more than one Result/Severity pair across the objects they
        return (for example, once per domain or per policy), and the value shown here is that
        check's ceiling, not necessarily what any single run will observe.

    .OUTPUTS
        MET.CheckInfo[]. One object per matching check, carrying CheckId, Category, Name,
        Severity, Description, RequiresModule, Script and Path.

    .EXAMPLE
        Get-METCheck

        Lists every check MET can run, in the same order Invoke-METAssessment executes them.

    .EXAMPLE
        Get-METCheck -Category EXO

        Lists only the EXO-category checks - useful for deciding whether -Category EXO is the
        right scope before running Invoke-METAssessment -Category EXO.

    .EXAMPLE
        Get-METCheck -Severity Critical, High

        Lists every check whose worst possible severity is Critical or High, to prioritise which
        checks matter most before a time-boxed assessment run.

    .EXAMPLE
        Get-METCheck -CheckId MET-EXO001, MET-MDO009

        Looks up two specific checks by ID, to confirm what they assess before including or
        excluding them with Invoke-METAssessment -CheckId / -ExcludeCheckId.
    #>
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
        ForEach-Object {
            $checkFile = $_
            try {
                Get-METCheckMetadata -Path $checkFile.FullName
            } catch {
                Write-Warning "Skipping check file '$($checkFile.FullName)' - failed to read its metadata: $($_.Exception.Message)"
            }
        }

    if ($Category) { $checks = $checks | Where-Object { $Category -contains $_.Category } }
    if ($CheckId)  { $checks = $checks | Where-Object { $CheckId  -contains $_.CheckId  } }
    if ($Severity) { $checks = $checks | Where-Object { $Severity -contains $_.Severity } }

    $checks
}
