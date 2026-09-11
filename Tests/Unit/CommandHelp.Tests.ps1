# A parameter added without help is invisible to Get-Help forever after, because nothing
# else in the suite reads help. This file is the thing that notices.
#
# The module is also imported here, at top level, outside any Describe/BeforeAll. Pester's
# Discovery pass evaluates each It's -ForEach argument below immediately as it reads the
# Describe body - before BeforeAll ever runs, since BeforeAll is deferred to the later Run
# pass. Without an import that Discovery can see, `Get-Command -Module MET` inside -ForEach
# resolves to nothing and the whole file fails to discover any tests, rather than failing
# each command's help checks the way it is meant to. The BeforeAll below still exists
# because Run does not re-execute this top-level code - It bodies need their own copy.
$script:DiscoveryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
Import-Module (Join-Path $script:DiscoveryRoot 'MET.psd1') -Force -ErrorAction Stop

Describe 'Comment-based help' {

    BeforeAll {
        $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
        Import-Module (Join-Path $script:Root 'MET.psd1') -Force -ErrorAction Stop
        $script:Commands = @(Get-Command -Module MET -CommandType Function)
    }

    It 'Covers all seven exported commands' {
        $script:Commands.Count | Should -Be 7
    }

    It '<Name> documents itself' -ForEach @(
        (Get-Command -Module MET -CommandType Function | ForEach-Object { @{ Name = $_.Name } })
    ) {
        $help = Get-Help -Name $Name -Full

        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Be $Name -Because 'PowerShell falls back to the command name when no .SYNOPSIS exists'

        ($help.Description | Out-String).Trim() | Should -Not -BeNullOrEmpty
        ($help.returnValues | Out-String).Trim()  | Should -Not -BeNullOrEmpty -Because "$Name must declare .OUTPUTS"

        @($help.Examples.Example).Count | Should -BeGreaterOrEqual 3 -Because "$Name must carry at least three .EXAMPLE blocks"

        foreach ($example in $help.Examples.Example) {
            ($example.remarks | Out-String).Trim() | Should -Not -BeNullOrEmpty -Because "every example for $Name must explain itself, not just show a command line"
        }
    }

    It '<Name> documents every parameter it declares' -ForEach @(
        (Get-Command -Module MET -CommandType Function | ForEach-Object { @{ Name = $_.Name } })
    ) {
        $command = Get-Command -Name $Name
        $help = Get-Help -Name $Name -Full

        $common = [System.Management.Automation.PSCmdlet]::CommonParameters +
                  [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $declared = @($command.Parameters.Keys | Where-Object { $_ -notin $common })
        $documented = @($help.parameters.parameter.name)

        $missing = @($declared | Where-Object { $_ -notin $documented })
        $missing | Should -BeNullOrEmpty -Because "these parameters of $Name have no .PARAMETER block: $($missing -join ', ')"

        foreach ($parameter in $help.parameters.parameter) {
            ($parameter.description | Out-String).Trim() | Should -Not -BeNullOrEmpty -Because "$Name's -$($parameter.name) has an empty .PARAMETER block"
        }
    }

    # Get-Help merges two sources: the real .PARAMETER blocks in the comment-based help, and -
    # as a fallback, for whichever parameter it did not find one for - a plain '#' comment
    # sitting directly above that parameter's declaration in param(). Several parameters in
    # this codebase already carry such a comment for an unrelated reason (explaining a design
    # decision inline, e.g. DisableWAM, Quiet, TenantId), so the Get-Help-based assertions
    # above cannot tell "has a real .PARAMETER block" apart from "merely sits under a code
    # comment" - a parameter could ship with no .PARAMETER block at all and still pass them.
    # This test bypasses Get-Help and reads the AST's own CommentHelpInfo directly, which is
    # populated only from genuine .PARAMETER entries inside the function's comment-based help
    # block - never from an unrelated inline comment in param().
    It '<Name> has a genuine .PARAMETER block (not just an adjacent code comment) for every parameter' -ForEach @(
        (Get-Command -Module MET -CommandType Function | ForEach-Object { @{ Name = $_.Name } })
    ) {
        $command = Get-Command -Name $Name
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters +
                  [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $declared = @($command.Parameters.Keys | Where-Object { $_ -notin $common })

        $sourcePath = $command.ScriptBlock.File
        $sourcePath | Should -Not -BeNullOrEmpty -Because "$Name must be backed by a script file to locate its source"

        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref] $tokens, [ref] $parseErrors)
        $parseErrors | Should -BeNullOrEmpty -Because "$sourcePath must parse cleanly"

        $functionAst = $ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name },
            $true
        ) | Select-Object -First 1
        $functionAst | Should -Not -BeNullOrEmpty -Because "$Name's function definition must be found in $sourcePath"

        $helpContent = $functionAst.GetHelpContent()
        $helpContent | Should -Not -BeNullOrEmpty -Because "$Name must carry a comment-based help block at all"

        # .Parameters is keyed by parameter name in upper-case.
        $documentedInSource = @($helpContent.Parameters.Keys)
        $missing = @($declared | Where-Object { $_.ToUpperInvariant() -notin $documentedInSource })
        $missing | Should -BeNullOrEmpty -Because "these parameters of $Name have no genuine .PARAMETER block in the source - a nearby code comment is not a substitute: $($missing -join ', ')"
    }
}
