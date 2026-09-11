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
}
