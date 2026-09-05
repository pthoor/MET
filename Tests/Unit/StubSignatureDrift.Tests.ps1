BeforeDiscovery {
    # Every test file declares its own service-cmdlet stubs - that is the documented
    # convention, and it is what keeps a new check from having to touch shared state.
    # What it does not survive on its own is drift: PowerShell binds by name, so a
    # stub declared [CmdletBinding()] without a parameter the production code actually
    # passes throws a ParameterBindingException, and every EXO/Graph/Teams call site in
    # this codebase sits inside a try/catch that turns an exception into a benign
    # default. The test then goes green having never reached the logic it names.
    # This guard keeps the stubs distributed but makes a mismatch fail loudly.
    #
    # Discovery-time, because the per-stub cases below are generated with -ForEach.

    $root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

    $commonParameters = @(
        [System.Management.Automation.PSCmdlet]::CommonParameters +
        [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
    ) | Sort-Object -Unique

    function Get-METParsedAst {
        param([string] $Path)
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
    }

    # Which named parameters does production actually pass to each command?
    $productionCalls = @{}
    $productionFiles = Get-ChildItem -Recurse -Filter '*.ps1' -Path @(
        (Join-Path $root 'Checks')
        (Join-Path $root 'Public')
        (Join-Path $root 'Private')
    )
    foreach ($file in $productionFiles) {
        $ast = Get-METParsedAst -Path $file.FullName
        $commands = $ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true)

        foreach ($command in $commands) {
            $name = $command.GetCommandName()
            if (-not $name) { continue }

            foreach ($element in $command.CommandElements) {
                if ($element -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                if ($element.ParameterName -in $commonParameters) { continue }

                if (-not $productionCalls.ContainsKey($name)) { $productionCalls[$name] = @{} }
                $productionCalls[$name][$element.ParameterName] =
                    "$($file.Name):$($command.Extent.StartLineNumber)"
            }
        }
    }

    # Every stub a test file declares for one of those commands.
    $stubCases = @(
        foreach ($file in (Get-ChildItem -Path (Join-Path $root 'Tests') -Recurse -Filter '*.Tests.ps1')) {
            $ast = Get-METParsedAst -Path $file.FullName
            $functions = $ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true)

            foreach ($function in $functions) {
                if (-not $productionCalls.ContainsKey($function.Name)) { continue }

                $parameterBlock = $function.Body.ParamBlock
                $declared = @()
                if ($function.Parameters) {
                    $declared = @($function.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
                }
                elseif ($parameterBlock) {
                    $declared = @($parameterBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
                }

                # A stub with neither [CmdletBinding()] nor a [Parameter()] attribute is
                # not an advanced function: unmatched named arguments land in $args and
                # bind harmlessly, so it cannot drift. Only advanced stubs throw on an
                # unknown parameter name, and only those are worth guarding.
                $attributeNames = @()
                if ($parameterBlock) {
                    $attributeNames = @($parameterBlock.Attributes | ForEach-Object { $_.TypeName.Name })
                }
                $hasParameterAttribute = $function.Body.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AttributeAst] -and
                    $node.TypeName.Name -eq 'Parameter'
                }, $true).Count -gt 0
                if (-not (($attributeNames -contains 'CmdletBinding') -or $hasParameterAttribute)) { continue }

                $required = @($productionCalls[$function.Name].Keys | Sort-Object)

                @{
                    Command   = $function.Name
                    Declared  = $declared
                    Required  = $required
                    CallSites = $productionCalls[$function.Name]
                    File      = $file.FullName.Replace($root, '').TrimStart([char]'/', [char]'\')
                    Line      = $function.Extent.StartLineNumber
                }
            }
        }
    ) | Sort-Object { $_.Command }, { $_.File }

    # Same command stubbed two different ways in two different files is how the gap
    # above gets introduced: whichever file is behind binds a subset and goes quietly
    # green. Reported as one case rather than per-file so the message names every variant.
    $driftedCommands = @(
        $stubCases |
            Group-Object { $_.Command } |
            Where-Object {
                @($_.Group | Group-Object { ($_.Declared | Sort-Object) -join ',' }).Count -gt 1
            } |
            ForEach-Object {
                $variants = $_.Group | ForEach-Object { "        $($_.File):$($_.Line) -> [$($_.Declared -join ', ')]" }
                "    $($_.Name):`n$($variants -join "`n")"
            }
    )

    $inventoryCases = @(@{ StubCount = @($stubCases).Count; Drifted = $driftedCommands })
}

Describe 'Test-fixture cmdlet stubs' {

    It 'Finds advanced stubs to check at all' -ForEach $inventoryCases {
        # Guards the guard: an AST or layout change that stopped matching stubs would
        # make every generated case below vacuously true.
        $StubCount | Should -BeGreaterThan 20
    }

    It 'Stubs <Command> with every parameter production passes to it (<File>)' -ForEach $stubCases {
        $missing = @($Required | Where-Object { $Declared -notcontains $_ })

        $detail = ($missing | ForEach-Object { "-$_ (passed at $($CallSites[$_]))" }) -join ', '
        $missing | Should -BeNullOrEmpty -Because @"

$File`:$Line declares $Command as an advanced function but not $detail.
Production passes that parameter, so the call throws a ParameterBindingException that
the calling try/catch swallows - the test passes without ever reaching the logic it
asserts on. Add the parameter to the stub.
"@
    }

    It 'Declares one signature per command across every test file' -ForEach $inventoryCases {
        $Drifted | Should -BeNullOrEmpty -Because "these commands are stubbed with incompatible signatures:`n$($Drifted -join "`n")`n"
    }
}
