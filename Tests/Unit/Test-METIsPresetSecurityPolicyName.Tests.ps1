BeforeAll {
    . "$PSScriptRoot/../../Private/Get-METPresetSecurityPolicyTier.ps1"
    . "$PSScriptRoot/../../Private/Test-METIsPresetSecurityPolicyName.ps1"
}

Describe 'Test-METIsPresetSecurityPolicyName' {
    It 'returns true for a Strict preset policy name with a numeric suffix' {
        Test-METIsPresetSecurityPolicyName -Name 'Strict Preset Security Policy1707729536596' | Should -BeTrue
    }
    It 'returns true for a Standard preset policy name with a numeric suffix' {
        Test-METIsPresetSecurityPolicyName -Name 'Standard Preset Security Policy1746689410544' | Should -BeTrue
    }
    It 'returns false for a custom policy name' {
        Test-METIsPresetSecurityPolicyName -Name 'Research Department' | Should -BeFalse
    }
    It 'returns false for the tenant default policy' {
        Test-METIsPresetSecurityPolicyName -Name 'Default' | Should -BeFalse
    }
    It 'returns false for an empty name' {
        Test-METIsPresetSecurityPolicyName -Name '' | Should -BeFalse
    }
}
