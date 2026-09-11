BeforeAll {
    . (Join-Path $PSScriptRoot '..' '..' 'Public' 'Test-METPrerequisites.ps1')
}

Describe 'Test-METPrerequisites' {
    Context 'non-Windows DNS prerequisites without local resolver tools' -Skip:$IsWindows {
        BeforeAll {
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Get-Command { $null } -ParameterFilter {
                $Name -in @('dig', 'nslookup') -and $CommandType -eq 'Application'
            }
            Mock Get-Module {
                switch ($Name) {
                    'ExchangeOnlineManagement'         { [PSCustomObject]@{ Version = [version]'3.7.2' } }
                    'Microsoft.Graph.Identity.SignIns' { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                    'Microsoft.Graph.Groups'           { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                    'MicrosoftTeams'                   { [PSCustomObject]@{ Version = [version]'6.0.0' } }
                    'Pester'                           { [PSCustomObject]@{ Version = [version]'5.0.0' } }
                }
            } -ParameterFilter { $ListAvailable }
        }

        It 'reports the DNS-over-HTTPS fallback as satisfied' {
            $results = Test-METPrerequisites -PassThru
            $dnsCheck = $results | Where-Object { $_.Component -eq 'Platform (DNS)' }

            $dnsCheck.Status | Should -Be 'OK'
            $dnsCheck.Installed | Should -Be 'DNS-over-HTTPS fallback'
            $dnsCheck.Notes | Should -Match 'DNS-over-HTTPS'
        }
    }

    Context 'Microsoft Graph modules are not installed' {
        BeforeAll {
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Get-Module {
                switch ($Name) {
                    'ExchangeOnlineManagement' { [PSCustomObject]@{ Version = [version]'3.7.2' } }
                    'MicrosoftTeams'           { [PSCustomObject]@{ Version = [version]'6.0.0' } }
                    'Pester'                   { [PSCustomObject]@{ Version = [version]'5.0.0' } }
                }
            } -ParameterFilter { $ListAvailable }
        }

        It 'marks Graph as optional rather than a required failure' {
            $results = Test-METPrerequisites -PassThru
            $graph = @($results | Where-Object { $_.Component -like 'Microsoft.Graph.*' })

            $graph.Count | Should -Be 2
            $graph | ForEach-Object {
                $_.Optional | Should -BeTrue
                $_.Status | Should -Be 'Not installed (optional)'
            }
        }

        It 'does not warn about unmet required prerequisites' {
            Test-METPrerequisites | Out-Null
            Should -Invoke Write-Warning -Times 0 -Exactly
        }
    }
}

Describe 'Test-METPrerequisites output contract' {
    BeforeAll {
        # PowerShell's non-success-stream redirection (2>&1, 3>&1, 6>&1) re-wraps ErrorRecord /
        # WarningRecord / InformationRecord in a bare PSObject as they cross the merge, which
        # makes `-is [PSCustomObject]` true for them too - they must be excluded explicitly, or
        # Write-Host's own InformationRecord output (captured here via 6>&1) is misidentified as
        # a real check object.
        $script:IsRealCheckObject = {
            $_ -is [PSCustomObject] -and $_ -isnot [System.Management.Automation.InformationRecord]
        }
    }

    # :119 returned $checks in addition to printing, so the user got the nice formatted
    # display followed by seven raw Format-List blocks of the same data.
    It 'returns nothing by default' {
        (Test-METPrerequisites 6>&1 | Where-Object $script:IsRealCheckObject) |
            Should -BeNullOrEmpty
    }

    It 'returns the check objects with -PassThru' {
        $checks = Test-METPrerequisites -PassThru 6>&1 | Where-Object $script:IsRealCheckObject
        @($checks).Count | Should -BeGreaterThan 0
        @($checks)[0].PSObject.Properties.Name | Should -Contain 'Component'
    }

    # A Test- verb should answer a yes/no question. Without this,
    # if (Test-METPrerequisites) {...} was always true, because a non-empty array is truthy.
    It 'returns a boolean with -Quiet' {
        $result = Test-METPrerequisites -Quiet 6>&1 | Where-Object { $_ -is [bool] }
        $result | Should -BeOfType [bool]
    }

    It 'does not list Pester as a user prerequisite' {
        $checks = Test-METPrerequisites -PassThru 6>&1 | Where-Object $script:IsRealCheckObject
        @($checks | ForEach-Object { $_.Component }) | Should -Not -Contain 'Pester'
    }

    It 'enforces the derived Exchange Online floor' {
        $checks = Test-METPrerequisites -PassThru 6>&1 | Where-Object $script:IsRealCheckObject
        $exo = $checks | Where-Object { $_.Component -eq 'ExchangeOnlineManagement' }
        $exo.Required | Should -Be '3.7.2+'
    }
}
