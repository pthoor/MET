# A metadata header that merely sits at the top of a file is a comment: it starts true and
# drifts. These assertions re-derive each field from the check's own code, so a check that
# gains a Critical branch, is renamed, or starts calling a Teams cmdlet fails here until
# its header is corrected. That is what lets Get-METCheck, -ListChecks and the HTML report's
# CONTROLS_META all be generated from one source instead of hand-maintained three times.
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'Get-METCheckMetadata.ps1')
    . (Join-Path $script:Root 'Private' 'Get-METCheckWeight.ps1')

    $script:CheckFiles = @(Get-ChildItem -Path (Join-Path $script:Root 'Checks') -Recurse -Filter 'MET-*.ps1' |
        Sort-Object Name)

    $script:PrivateFiles = @{}
    Get-ChildItem -Path (Join-Path $script:Root 'Private') -Filter '*.ps1' | ForEach-Object {
        $script:PrivateFiles[$_.BaseName] = $_.FullName
    }

    # Commands that are PowerShell built-ins or ship with the OS. None of them implies an
    # MET dependency, and Resolve-DnsName in particular is DnsClient, not Exchange Online.
    $script:IgnoredCommands = @(
        'Get-Command','Get-Module','Get-Item','Get-ChildItem','Get-Content','Get-Date',
        'Where-Object','ForEach-Object','Select-Object','Sort-Object','Group-Object',
        'Measure-Object','Compare-Object','New-Object','New-TimeSpan','Write-Verbose',
        'Write-Warning','Write-Error','Out-Null','Out-String','ConvertTo-Json',
        'ConvertFrom-Json','Join-Path','Split-Path','Test-Path','Resolve-Path',
        'Resolve-DnsName','Invoke-RestMethod','Invoke-WebRequest','Set-Content',
        'Add-Member','Start-Process'
    )

    function Get-METInvokedCommandName {
        param([string] $Path)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
        if ($errors) { throw "Failed to parse $Path : $($errors[0].Message)" }
        @($ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ } | Sort-Object -Unique)
    }

    # MET-prefixed helpers are expanded into the commands they themselves call, because a
    # check that reaches Exchange Online only through Resolve-METSafeLinksEffectivePolicy
    # depends on Exchange Online just as hard as one that calls Get-SafeLinksPolicy itself.
    function Get-METReachedCommandName {
        param([string] $Path, [System.Collections.Generic.HashSet[string]] $Visited)
        if (-not $Visited) { $Visited = [System.Collections.Generic.HashSet[string]]::new() }
        $reached = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($command in Get-METInvokedCommandName -Path $Path) {
            if ($command -match '^[A-Za-z]+-MET') {
                $helperName = $command
                if ($Visited.Add($helperName) -and $script:PrivateFiles.ContainsKey($helperName)) {
                    foreach ($inner in (Get-METReachedCommandName -Path $script:PrivateFiles[$helperName] -Visited $Visited)) {
                        $null = $reached.Add($inner)
                    }
                }
                continue
            }
            $null = $reached.Add($command)
        }
        @($reached)
    }

    function Get-METDerivedRequiresModule {
        param([string] $Path)
        $modules = [System.Collections.Generic.HashSet[string]]::new()

        # Microsoft.Graph is attributed on DIRECT calls only. Expand-METGroupMembership is
        # the codebase's other Graph call site and it degrades to Exchange Online cmdlets
        # when Graph is absent, so reaching Graph through it is not a dependency.
        foreach ($command in (Get-METInvokedCommandName -Path $Path)) {
            if ($command -match '^[A-Za-z]+-Mg') { $null = $modules.Add('Microsoft.Graph') }
        }

        foreach ($command in (Get-METReachedCommandName -Path $Path)) {
            if ($command -in $script:IgnoredCommands) { continue }
            if ($command -match '^[A-Za-z]+-Mg') { continue }
            if ($command -match '^[A-Za-z]+-Cs')  { $null = $modules.Add('MicrosoftTeams'); continue }
            $null = $modules.Add('ExchangeOnlineManagement')
        }

        # A check that reaches no external command at all (it only calls MET helpers that
        # call nothing) would derive an empty set and contradict the "at least one
        # RequiresModule" assertion in the same test. Exchange Online is the floor: every
        # MDO and EXO check needs it, Invoke-METAssessment refuses to run without it, and
        # the three Teams checks that look module-free call Exchange-hosted cmdlets.
        if ($modules.Count -eq 0) { $null = $modules.Add('ExchangeOnlineManagement') }

        @($modules | Sort-Object)
    }

    function Get-METDeclaredSeverityArgument {
        param([string] $Path)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object {
                $elements = $_.CommandElements
                for ($i = 0; $i -lt $elements.Count - 1; $i++) {
                    if ($elements[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elements[$i].ParameterName -eq 'Severity' -and
                        $elements[$i + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        $elements[$i + 1].Value
                    }
                }
            } | Where-Object { $_ } | Sort-Object -Unique)
    }

    function Get-METDeclaredNameArgument {
        param([string] $Path)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object {
                $elements = $_.CommandElements
                for ($i = 0; $i -lt $elements.Count - 1; $i++) {
                    if ($elements[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elements[$i].ParameterName -eq 'Name' -and
                        $elements[$i + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        $elements[$i + 1].Value
                    }
                }
            } | Where-Object { $_ } | Sort-Object -Unique)
    }
}

Describe 'Check metadata header' {

    It 'Covers every check script and no others' {
        $script:CheckFiles.Count | Should -Be 51
    }

    Context 'Per check' {

        # -ForEach over the file list gives one failing test per offending check rather than
        # one failure naming 51 files, so the header-adding work can be driven file by file.
        It 'MET check <Script> declares a complete, valid header' -ForEach @(
            Get-ChildItem -Path (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path 'Checks') `
                -Recurse -Filter 'MET-*.ps1' | Sort-Object Name |
                ForEach-Object { @{ Script = $_.Name; Path = $_.FullName } }
        ) {
            $info = Get-METCheckMetadata -Path $Path

            $info.Name        | Should -Not -BeNullOrEmpty -Because "$Script must declare Name in `$METCheckInfo"
            $info.Description | Should -Not -BeNullOrEmpty -Because "$Script must declare Description in `$METCheckInfo"
            $info.Severity    | Should -BeIn @('Critical','High','Medium','Low','Informational') -Because "$Script must declare a Severity in New-METCheckResult's ValidateSet"
            @($info.RequiresModule) | Should -Not -BeNullOrEmpty -Because "$Script must declare at least one RequiresModule"
            foreach ($module in $info.RequiresModule) {
                $module | Should -BeIn @('ExchangeOnlineManagement','MicrosoftTeams','Microsoft.Graph')
            }

            # Severity means the worst this check can score. Nine checks emit more than one
            # severity - MET-MDO014 emits High, Medium and Informational - so a scalar can
            # only honestly mean the maximum, which is the semantics -Severity filters on.
            $emitted = Get-METDeclaredSeverityArgument -Path $Path
            if ($emitted) {
                $worst = $emitted | Sort-Object { Get-METCheckWeight -Severity $_ } -Descending | Select-Object -First 1
                $info.Severity | Should -Be $worst -Because "$Script emits $($emitted -join ', '); the header must name the worst of them"
            }

            # Name is the family name. Four checks emit differently-named sub-results
            # (e.g. 'Preset Policy Coverage - EOP Gap'), so the header must match one of
            # the emitted names rather than all of them.
            $names = Get-METDeclaredNameArgument -Path $Path
            if ($names) {
                $names | Should -Contain $info.Name -Because "$Script emits $($names -join ' | '); the header's Name must be one of them"
            }

            # Closes D-6 structurally: the MicrosoftTeams dependency was understated by five
            # checks in the README precisely because nothing derived it from the code.
            $derived = Get-METDerivedRequiresModule -Path $Path
            @($info.RequiresModule | Sort-Object) | Should -Be $derived -Because "$Script reaches $($derived -join ', ')"
        }
    }
}
