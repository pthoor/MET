function Get-METCheckMetadata {
    [CmdletBinding()]
    [OutputType('MET.CheckInfo')]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    $file = Get-Item -LiteralPath $Path

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref] $tokens, [ref] $parseErrors)

    if ($parseErrors) {
        throw "Failed to parse check script '$($file.FullName)': $($parseErrors[0].Message)"
    }

    $parts = $file.BaseName -split '-', 3

    $name           = $null
    $severity       = $null
    $description    = $null
    $requiresModule = @()

    # Top-level only. A $METCheckInfo assigned inside a function or a nested scriptblock is
    # not the file's header, and treating it as one would let a check advertise metadata
    # that only exists down some branch.
    $assignment = @($ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'METCheckInfo'
        },
        $false)) | Select-Object -First 1

    if ($assignment) {
        $hashtable = $assignment.Right.Find(
            { param($node) $node -is [System.Management.Automation.Language.HashtableAst] },
            $false)

        if ($hashtable) {
            foreach ($pair in $hashtable.KeyValuePairs) {
                $key = $pair.Item1.Extent.Text.Trim(("'", '"'))

                # Every legal value shape here - 'x', @('x'), 'x','y', @('x','y') - reduces
                # to its string constants. Reading them off the subtree rather than matching
                # one AST class per shape means a new-but-equivalent literal shape does not
                # silently read as empty.
                $constants = @($pair.Item2.FindAll(
                    { param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] },
                    $true) | ForEach-Object { $_.Value })

                switch ($key) {
                    'Name'           { $name           = $constants | Select-Object -First 1 }
                    'Severity'       { $severity       = $constants | Select-Object -First 1 }
                    'Description'    { $description    = $constants | Select-Object -First 1 }
                    'RequiresModule' { $requiresModule = $constants }
                }
            }
        }
    }

    [PSCustomObject]@{
        PSTypeName     = 'MET.CheckInfo'
        CheckId        = "$($parts[0])-$($parts[1])"
        Category       = $file.Directory.Name
        Name           = $name
        Severity       = $severity
        Description    = $description
        RequiresModule = $requiresModule
        Script         = $file.Name
        Path           = $file.FullName
    }
}
