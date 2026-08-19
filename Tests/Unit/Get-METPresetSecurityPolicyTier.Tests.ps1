BeforeAll {
    . "$PSScriptRoot/../../Private/Get-METPresetSecurityPolicyTier.ps1"
}

Describe 'Get-METPresetSecurityPolicyTier' {
    It 'returns Strict for a Strict preset policy name with a numeric suffix' {
        Get-METPresetSecurityPolicyTier -Name 'Strict Preset Security Policy1707729536596' | Should -Be 'Strict'
    }
    It 'returns Standard for a Standard preset policy name with a numeric suffix' {
        Get-METPresetSecurityPolicyTier -Name 'Standard Preset Security Policy1746689410544' | Should -Be 'Standard'
    }
    It 'returns null for a custom policy name' {
        Get-METPresetSecurityPolicyTier -Name 'Research Department' | Should -BeNullOrEmpty
    }
    It 'returns null for an empty name' {
        Get-METPresetSecurityPolicyTier -Name '' | Should -BeNullOrEmpty
    }
}
