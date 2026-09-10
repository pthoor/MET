BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"

    # The exact shape Get-QuarantinePolicy returns: a formatted System.String, wrapped in
    # brackets, one "Name: True/False" token per line. Captured from a live tenant
    # (ExchangeOnlineManagement 3.9.x).
    $script:RealString = @'
[PermissionToBlockSender: True
PermissionToDelete: True
PermissionToDownload: False
PermissionToPreview: False
PermissionToRelease: False
PermissionToRequestRelease: True
PermissionToViewHeader: False
PermissionToAllowSender: False]
'@
}

Describe 'Get-METEndUserQuarantinePermission' {

    Context 'the real Get-QuarantinePolicy string shape' {
        It 'parses every permission token off the string' {
            $policy = [PSCustomObject]@{ Name = 'Contoso'; EndUserQuarantinePermissions = $script:RealString }
            $result = Get-METEndUserQuarantinePermission -QuarantinePolicy $policy

            $result.PermissionToRelease        | Should -BeExactly $false
            $result.PermissionToRequestRelease | Should -BeExactly $true
            $result.PermissionToDelete         | Should -BeExactly $true
            $result.PermissionToBlockSender    | Should -BeExactly $true
            $result.PermissionToAllowSender    | Should -BeExactly $false
        }

        It 'reads PermissionToRelease True when the token says True' {
            $s = $script:RealString -replace 'PermissionToRelease: False', 'PermissionToRelease: True'
            $policy = [PSCustomObject]@{ EndUserQuarantinePermissions = $s }
            (Get-METEndUserQuarantinePermission -QuarantinePolicy $policy).PermissionToRelease | Should -BeExactly $true
        }

        It 'tolerates a single-line comma-separated rendering' {
            $s = '[PermissionToRelease: False, PermissionToDelete: True, PermissionToPreview: True]'
            $policy = [PSCustomObject]@{ EndUserQuarantinePermissions = $s }
            $result = Get-METEndUserQuarantinePermission -QuarantinePolicy $policy
            $result.PermissionToRelease | Should -BeExactly $false
            $result.PermissionToDelete  | Should -BeExactly $true
        }
    }

    Context 'a typed object (in case a future module version changes the shape)' {
        It 'reads the boolean members directly' {
            $policy = [PSCustomObject]@{
                EndUserQuarantinePermissions = [PSCustomObject]@{ PermissionToRelease = $true; PermissionToDelete = $false }
            }
            $result = Get-METEndUserQuarantinePermission -QuarantinePolicy $policy
            $result.PermissionToRelease | Should -BeExactly $true
            $result.PermissionToDelete  | Should -BeExactly $false
        }
    }

    Context 'nothing to read' {
        It 'returns $null when the policy object is $null' {
            Get-METEndUserQuarantinePermission -QuarantinePolicy $null | Should -BeNullOrEmpty
        }

        It 'returns $null when the property is absent' {
            $policy = [PSCustomObject]@{ Name = 'Contoso' }
            Get-METEndUserQuarantinePermission -QuarantinePolicy $policy | Should -BeNullOrEmpty
        }

        It 'returns $null when the property is present but $null' {
            $policy = [PSCustomObject]@{ EndUserQuarantinePermissions = $null }
            Get-METEndUserQuarantinePermission -QuarantinePolicy $policy | Should -BeNullOrEmpty
        }

        It 'returns $null when the string carries no permission token' {
            $policy = [PSCustomObject]@{ EndUserQuarantinePermissions = '[]' }
            Get-METEndUserQuarantinePermission -QuarantinePolicy $policy | Should -BeNullOrEmpty
        }
    }

    Context 'a partial string' {
        It 'reads the tokens that are present and leaves the rest $null' {
            $policy = [PSCustomObject]@{ EndUserQuarantinePermissions = '[PermissionToRelease: True]' }
            $result = Get-METEndUserQuarantinePermission -QuarantinePolicy $policy
            $result.PermissionToRelease | Should -BeExactly $true
            $result.PermissionToDelete  | Should -BeNullOrEmpty
        }
    }
}
