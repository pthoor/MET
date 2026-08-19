BeforeAll {
    . "$PSScriptRoot/../../Private/Test-METIsBuiltInQuarantinePolicyName.ps1"
}

Describe 'Test-METIsBuiltInQuarantinePolicyName' {
    It 'returns true for each of the four built-in quarantine policy names' {
        Test-METIsBuiltInQuarantinePolicyName -Name 'AdminOnlyAccessPolicy' | Should -BeTrue
        Test-METIsBuiltInQuarantinePolicyName -Name 'DefaultFullAccessPolicy' | Should -BeTrue
        Test-METIsBuiltInQuarantinePolicyName -Name 'DefaultFullAccessWithNotificationPolicy' | Should -BeTrue
        Test-METIsBuiltInQuarantinePolicyName -Name 'NotificationEnabledPolicy' | Should -BeTrue
    }
    It 'returns false for a custom quarantine policy name' {
        Test-METIsBuiltInQuarantinePolicyName -Name 'ContosoNoAccess' | Should -BeFalse
    }
    It 'returns false for an empty name' {
        Test-METIsBuiltInQuarantinePolicyName -Name '' | Should -BeFalse
    }
}
