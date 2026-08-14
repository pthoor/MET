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
                    'ExchangeOnlineManagement'         { [PSCustomObject]@{ Version = [version]'3.0.0' } }
                    'Microsoft.Graph.Identity.SignIns' { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                    'Microsoft.Graph.Groups'           { [PSCustomObject]@{ Version = [version]'2.0.0' } }
                    'MicrosoftTeams'                   { [PSCustomObject]@{ Version = [version]'6.0.0' } }
                    'Pester'                           { [PSCustomObject]@{ Version = [version]'5.0.0' } }
                }
            } -ParameterFilter { $ListAvailable }
        }

        It 'reports the DNS-over-HTTPS fallback as satisfied' {
            $results = Test-METPrerequisites
            $dnsCheck = $results | Where-Object { $_.Component -eq 'Platform (DNS)' }

            $dnsCheck.Status | Should -Be 'OK'
            $dnsCheck.Installed | Should -Be 'DNS-over-HTTPS fallback'
            $dnsCheck.Notes | Should -Match 'DNS-over-HTTPS'
        }
    }
}
