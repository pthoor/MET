function Get-METReportGlossaryTerms {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    # Same discovery path Invoke-METAssessment/Get-METCheck use - resolved fresh every call
    # so a dropped-in check's cmdlets/properties are picked up with no separate list to
    # maintain. Missing entirely (a broken install) degrades to an empty glossary rather
    # than failing report generation - the HTML report has no hard dependency on this.
    $checksRoot = Join-Path -Path $PSScriptRoot -ChildPath '../Checks'
    if (-not (Test-Path -LiteralPath $checksRoot)) {
        return @()
    }
    $checkFiles = Get-ChildItem -Path $checksRoot -Recurse -Filter 'MET-*.ps1' -ErrorAction SilentlyContinue

    # A single capitalized word (Identity, Path, Force, OneDrive, SharePoint) reads as
    # ordinary English prose, not a code identifier - only a multi-segment PascalCase run
    # (RejectDirectSend, EnableSafeList) is unambiguous. The 6-character floor drops short
    # category/protocol acronyms (MDO, EXO, SPF, DKIM) that happen to satisfy the segment
    # shape but read fine as plain text. Matched with -cmatch, not -match: PowerShell's
    # default case-insensitive comparison collapses [A-Z] and [a-z0-9] into the same
    # character class, and running that against the long, multi-hundred-character prose
    # blobs in -Finding/-Recommendation text (which this same AST walk also visits, since
    # they're StringConstantExpressionAst nodes too) is catastrophic backtracking - it
    # hung indefinitely on MET-Teams006 in testing. The 80-character ceiling is belt-and-
    # suspenders: no real identifier here approaches that length, so it bounds the regex
    # engine's worst case on any prose string that slips past first.
    $pascalMultiSegment = '^([A-Z][a-z0-9]*){2,}$'
    $minLength = 6
    $maxLength = 80

    # PowerShell's own common parameters carry generic English meanings (Confirm, Force,
    # Verbose...) that would otherwise get coded wherever they happen to appear in prose.
    $commonParameters = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable',
            'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable'
        ),
        [System.StringComparer]::Ordinal)

    $terms = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($file in $checkFiles) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName, [ref] $tokens, [ref] $parseErrors)

        if ($parseErrors) {
            continue
        }

        # Cmdlets the check actually invokes (Get-EXOMailbox, Set-TransportConfig, ...) -
        # rendered as code wherever they're mentioned in Finding/Recommendation text, not
        # only right after "Run:".
        foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $cmdName = $cmd.GetCommandName()
            if ($cmdName -and $cmdName.Length -le $maxLength -and $cmdName -cmatch '^[A-Z][a-zA-Z0-9]*-[A-Z][a-zA-Z0-9]*$') {
                [void]$terms.Add($cmdName)
            }
        }

        # Named parameters passed to those cmdlets (-RejectDirectSend $true).
        foreach ($param in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandParameterAst] }, $true)) {
            $pname = $param.ParameterName
            if ($pname -and $pname.Length -ge $minLength -and $pname.Length -le $maxLength -and $pname -cmatch $pascalMultiSegment -and -not $commonParameters.Contains($pname)) {
                [void]$terms.Add($pname)
            }
        }

        # Every other identifier-shaped string constant - covers property access read via
        # $obj.PSObject.Properties['Name'] (the absent-property-safe pattern this codebase
        # uses throughout), direct .MemberAccess, hashtable keys, and quoted built-in policy
        # names (AdminOnlyAccessPolicy, DefaultFullAccessWithNotificationPolicy, ...). A
        # multi-word prose sentence never matches - the anchored pattern requires the whole
        # string to be one unbroken PascalCase run with no spaces or punctuation.
        foreach ($str in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
            $val = $str.Value
            if ($val -and $val.Length -ge $minLength -and $val.Length -le $maxLength -and $val -cmatch $pascalMultiSegment -and -not $commonParameters.Contains($val)) {
                [void]$terms.Add($val)
            }
        }
    }

    $terms | Sort-Object
}
