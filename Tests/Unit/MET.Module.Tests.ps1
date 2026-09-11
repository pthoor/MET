# The rest of the unit suite dot-sources Private/*.ps1 and Checks/*.ps1 directly, which
# means MET.psm1 and MET.psd1 are never exercised by it: a function dropped from the
# loader glob, or a manifest that exports a name nothing defines, leaves every other
# file in Tests/Unit green while `Import-Module MET` ships broken. This file is the only
# place the packaged module contract itself is asserted.
BeforeAll {
    $script:ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $script:ManifestPath = Join-Path $script:ModuleRoot 'MET.psd1'
    $script:RootModulePath = Join-Path $script:ModuleRoot 'MET.psm1'

    $script:ManifestData = Import-PowerShellDataFile -Path $script:ManifestPath

    Import-Module $script:ManifestPath -Force -ErrorAction Stop
    $script:Module = Get-Module -Name 'MET'

    # Top-level function definitions declared by a script file. Nested script blocks are
    # deliberately not searched - a helper defined inside another function is not a
    # command the loader is expected to publish into module scope.
    function Get-METDeclaredFunctionName {
        param([string] $Path)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
        if ($errors) {
            throw "Failed to parse $Path : $($errors[0].Message)"
        }

        $ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
            $false
        ) | ForEach-Object { $_.Name }
    }

    function Test-METFunctionInModuleScope {
        param([string] $Name)

        & $script:Module {
            param($FunctionName)
            [bool] (Get-Command -Name $FunctionName -CommandType Function -ErrorAction SilentlyContinue)
        } $Name
    }
}

Describe 'MET module import' {
    It 'imports from the manifest without an error or a warning' {
        # Stream redirection, not -WarningVariable: a warning written by the module's own
        # loader during Import-Module does not land in the cmdlet's WarningVariable, so
        # the obvious spelling of this assertion silently passes through a broken loader.
        $errors = @()
        $emitted = @(Import-Module $script:ManifestPath -Force -ErrorAction Stop -ErrorVariable errors 3>&1)

        # MET.psm1 catches a dot-source failure and reports it as a warning rather than
        # rethrowing, so an import that emits any warning has silently lost a file.
        $warnings = @($emitted | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $warnings | Should -BeNullOrEmpty -Because 'MET.psm1 warns once per file it failed to dot-source'
        $errors | Should -BeNullOrEmpty
        Get-Module -Name 'MET' | Should -Not -BeNullOrEmpty
    }

    It 'imports cleanly into a session that has never seen the module' {
        # -Force in the line above re-imports into a runspace where every Private function
        # is already defined from the other unit files, which can mask a load-order fault.
        $pwshPath = (Get-Process -Id $PID).Path
        $script = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$($script:ManifestPath)' -ErrorAction Stop -WarningVariable w
if (`$w) { Write-Output ('WARNING:' + (`$w -join '; ')) }
Write-Output ('EXPORTS:' + ((Get-Module MET).ExportedFunctions.Keys | Sort-Object) -join ',')
"@
        $output = & $pwshPath -NoProfile -NonInteractive -Command $script 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join [Environment]::NewLine)
        ($output -join "`n") | Should -Not -Match 'WARNING:'
        ($output -join "`n") | Should -Match 'EXPORTS:'
    }
}

Describe 'MET module manifest' {
    It 'passes Test-ModuleManifest' {
        $manifest = Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop
        $manifest.Name | Should -Be 'MET'
    }

    It 'declares MET.psm1 as the root module and ships it' {
        $script:ManifestData.RootModule | Should -Be 'MET.psm1'
        Test-Path -Path $script:RootModulePath | Should -BeTrue
    }

    It 'carries a well-formed three-part module version' {
        $script:ManifestData.ModuleVersion | Should -Match '^\d+\.\d+\.\d+$'
        { [version] $script:ManifestData.ModuleVersion } | Should -Not -Throw
        ([version] $script:ManifestData.ModuleVersion) | Should -BeGreaterThan ([version] '0.0.0')
        (Get-Module -Name 'MET').Version | Should -Be ([version] $script:ManifestData.ModuleVersion)
    }

    It 'leaves RequiredModules empty on purpose' {
        # Deliberate, and load-bearing: declaring ExchangeOnlineManagement/Graph/Teams here
        # turns a missing dependency into a hard import failure, which is exactly the case
        # Test-METPrerequisites exists to detect and guide the user through. It cannot run
        # if the module it lives in refuses to import. Do not "fix" this to a populated list.
        $script:ManifestData.RequiredModules | Should -BeNullOrEmpty
    }

    It 'exports no cmdlets or variables' {
        # Aliases are deliberately non-empty - see the 'Exported aliases' Describe block,
        # which asserts the manifest and the loader agree on exactly what is declared.
        $script:ManifestData.CmdletsToExport | Should -BeNullOrEmpty
        $script:ManifestData.VariablesToExport | Should -BeNullOrEmpty
    }

    It 'requires the PowerShell version the module is written against' {
        $script:ManifestData.PowerShellVersion | Should -Be '7.4'
    }
}

Describe 'MET exported surface' {
    It 'exports every function the manifest declares, and each one is callable' {
        $exported = (Get-Module -Name 'MET').ExportedFunctions.Keys

        foreach ($name in $script:ManifestData.FunctionsToExport) {
            $exported | Should -Contain $name -Because "the manifest declares $name"
            $command = Get-Command -Name $name -Module 'MET' -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty -Because "$name must resolve as a command after import"
            $command.CommandType | Should -Be 'Function'
        }
    }

    It 'exports nothing the manifest does not declare' {
        $exported = @((Get-Module -Name 'MET').ExportedFunctions.Keys) | Sort-Object
        $declared = @($script:ManifestData.FunctionsToExport) | Sort-Object

        $exported | Should -Be $declared
        (Get-Module -Name 'MET').ExportedCmdlets.Keys | Should -BeNullOrEmpty

        # Aliases are asserted against the manifest, not required to be empty - see the
        # 'Exported aliases' Describe block.
        $exportedAliases = @((Get-Module -Name 'MET').ExportedAliases.Keys) | Sort-Object
        $declaredAliases = @($script:ManifestData.AliasesToExport) | Sort-Object
        $exportedAliases | Should -Be $declaredAliases
    }

    It 'declares every command file under Public/ as exported' {
        # A new Public/ command that never reaches FunctionsToExport is invisible to a
        # consumer who installed the module from the gallery, however well it is tested.
        # Keyed on the file name, not on every function the file declares: a Public file
        # may also carry a file-private helper (Get-METReport.ps1 defines Get-METModuleVersion,
        # Invoke-METAssessment.ps1 defines Get-METAggregationNoun) which is deliberately unexported.
        $publicFiles = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1'

        $publicFiles | Should -Not -BeNullOrEmpty
        foreach ($file in $publicFiles) {
            $script:ManifestData.FunctionsToExport |
                Should -Contain $file.BaseName -Because "Public/$($file.Name) is a public command"
        }
    }

    It 'keeps every Private/ function out of the exported surface' {
        $exported = (Get-Module -Name 'MET').ExportedFunctions.Keys

        $privateFunctions = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' |
            ForEach-Object { Get-METDeclaredFunctionName -Path $_.FullName }

        $privateFunctions | Should -Not -BeNullOrEmpty
        foreach ($name in $privateFunctions) {
            $exported | Should -Not -Contain $name -Because "Private/$name.ps1 is an internal helper"
        }
    }
}

Describe 'MET.psm1 loader coverage' {
    # This is the assertion that catches a file silently dropped from the loader: the
    # loader globs Private/*.ps1 and Public/*.ps1, so a file that is renamed, moved to a
    # subfolder, or given a non-.ps1 extension stops being loaded with no error anywhere.
    It 'loads every function defined under Private/ into module scope' {
        $files = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1'
        $files | Should -Not -BeNullOrEmpty

        foreach ($file in $files) {
            foreach ($name in (Get-METDeclaredFunctionName -Path $file.FullName)) {
                Test-METFunctionInModuleScope -Name $name |
                    Should -BeTrue -Because "$($file.Name) defines $name, so MET.psm1 must load it"
            }
        }
    }

    It 'loads every function defined under Public/ into module scope' {
        $files = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1'
        $files | Should -Not -BeNullOrEmpty

        foreach ($file in $files) {
            foreach ($name in (Get-METDeclaredFunctionName -Path $file.FullName)) {
                Test-METFunctionInModuleScope -Name $name |
                    Should -BeTrue -Because "$($file.Name) defines $name, so MET.psm1 must load it"
            }
        }
    }

    It 'finds no .ps1 under Public/ or Private/ outside the loader globs' {
        # The globs are non-recursive. A helper parked in Private/Helpers/ would be dot-sourced
        # by nothing and fail only at runtime, in whichever check happened to call it first.
        foreach ($folder in @('Public', 'Private')) {
            $nested = Get-ChildItem -Path (Join-Path $script:ModuleRoot $folder) -Filter '*.ps1' -Recurse |
                Where-Object { $_.DirectoryName -ne (Join-Path $script:ModuleRoot $folder) }
            $nested | Should -BeNullOrEmpty -Because "MET.psm1 globs $folder/*.ps1 without -Recurse"
        }
    }

    It 'names every Private/ and Public/ file after a function it defines' {
        foreach ($folder in @('Public', 'Private')) {
            foreach ($file in Get-ChildItem -Path (Join-Path $script:ModuleRoot $folder) -Filter '*.ps1') {
                $declared = @(Get-METDeclaredFunctionName -Path $file.FullName)
                $declared | Should -Contain $file.BaseName -Because "$folder/$($file.Name) should define $($file.BaseName)"
            }
        }
    }
}

Describe 'Exported aliases' {
    It 'exports Invoke-METAssessment as a function' {
        $script:Module.ExportedFunctions.Keys | Should -Contain 'Invoke-METAssessment'
    }

    It 'keeps Invoke-METTriage working as an exported alias' {
        $script:Module.ExportedAliases.Keys | Should -Contain 'Invoke-METTriage'
        (Get-Alias -Name 'Invoke-METTriage').ResolvedCommandName |
            Should -Be 'Invoke-METAssessment'
    }

    It 'declares every exported alias in the manifest' {
        foreach ($alias in $script:Module.ExportedAliases.Keys) {
            $script:ManifestData.AliasesToExport | Should -Contain $alias
        }
    }

    It 'exports every alias the manifest declares' {
        foreach ($alias in @($script:ManifestData.AliasesToExport)) {
            $script:Module.ExportedAliases.Keys | Should -Contain $alias
        }
    }
}

Describe 'Parameter binding conventions' {
    # CLAUDE.md: "No positional parameters on public functions". Invoke-METTriage
    # MET-MDO001 previously bound to -Category and threw a ValidateSet error naming
    # a parameter the caller never mentioned, which is worse than not binding at all.
    It 'declares no positional parameters on <_>' -ForEach @(
        'Connect-METSession'
        'Disconnect-METSession'
        'Invoke-METAssessment'
        'Get-METReport'
        'Test-METPrerequisites'
    ) {
        $command = Get-Command -Name $_ -Module 'MET'
        $positional = $command.Parameters.Values |
            Where-Object {
                $_.Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Position -ge 0 }
            } |
            ForEach-Object { $_.Name }

        $positional | Should -BeNullOrEmpty -Because "$_ must be called with named parameters only"
    }

    It 'keeps Get-METReport -InputObject bound from the pipeline' {
        $inputObject = (Get-Command -Name 'Get-METReport' -Module 'MET').Parameters['InputObject']
        $attribute = $inputObject.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            Select-Object -First 1

        $attribute.ValueFromPipeline | Should -BeTrue
    }
}

Describe 'Loader failure handling' {
    # A dot-source failure in Public/ only warned, yet Export-ModuleMember still
    # published the failed file's BaseName - so Import-Module "succeeded" and the
    # command was missing at call time, far from the cause.
    It 'throws when a Public/ script fails to dot-source' {
        $sandbox = Join-Path $TestDrive 'brokenmodule'
        Copy-Item -LiteralPath $script:ModuleRoot -Destination $sandbox -Recurse -Force

        $brokenPath = Join-Path $sandbox 'Public' 'Get-METBroken.ps1'
        Set-Content -LiteralPath $brokenPath -Value 'throw "deliberate load failure"'

        { Import-Module (Join-Path $sandbox 'MET.psd1') -Force -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*Get-METBroken.ps1*'

        Remove-Module 'MET' -Force -ErrorAction SilentlyContinue
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
        $script:Module = Get-Module -Name 'MET'
    }
}

Describe 'about_MET conceptual help' {

    It 'Ships an about topic' {
        $topic = Join-Path $script:ModuleRoot 'en-US' 'about_MET.help.txt'
        Test-Path -LiteralPath $topic | Should -BeTrue
    }

    It 'Uses the header shape Get-Help requires to find it' {
        # A topic file whose first non-blank line is not TOPIC is silently not found by
        # Get-Help, which fails exactly like having written nothing at all.
        $topic = Get-Content (Join-Path $script:ModuleRoot 'en-US' 'about_MET.help.txt') -Raw
        $topic | Should -Match '(?m)^TOPIC\s*$'
        $topic | Should -Match '(?m)^\s+about_MET\s*$'
        $topic | Should -Match '(?m)^SHORT DESCRIPTION\s*$'
        $topic | Should -Match '(?m)^LONG DESCRIPTION\s*$'
    }

    It 'Covers the five subjects that exist nowhere a PSGallery installer can see' {
        $topic = Get-Content (Join-Path $script:ModuleRoot 'en-US' 'about_MET.help.txt') -Raw
        foreach ($subject in @('Managed Identity', 'Microsoft.Identity.Client', 'posture score', '-Detailed', 'DelegatedOrganization')) {
            $topic | Should -BeLike "*$subject*" -Because "about_MET must cover $subject"
        }
    }
}
