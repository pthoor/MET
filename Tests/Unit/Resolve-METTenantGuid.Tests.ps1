BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Resolve-METTenantGuid.ps1"
}

Describe 'Resolve-METTenantGuid input handling' {
    Context 'A well-formed GUID' {
        It 'Returns it without any network call' {
            Mock Invoke-RestMethod { throw 'must not be called' }
            Resolve-METTenantGuid -TenantId '00000000-1111-2222-3333-444444444444' |
                Should -Be '00000000-1111-2222-3333-444444444444'
            Should -Invoke Invoke-RestMethod -Exactly 0
        }
    }

    Context 'A value that is neither a GUID nor a DNS name' {
        BeforeAll { Mock Invoke-RestMethod { throw 'must not be called' } }

        It 'Returns null without reaching the network' -ForEach @(
            @{ Value = '../../evil' }
            @{ Value = 'contoso.com/../../steal' }
            @{ Value = 'contoso.com?x=y' }
            @{ Value = 'contoso.com#frag' }
            @{ Value = 'has space.com' }
            @{ Value = '' }
        ) {
            Resolve-METTenantGuid -TenantId $Value | Should -BeNullOrEmpty
            Should -Invoke Invoke-RestMethod -Exactly 0
        }
    }

    Context 'A valid domain' {
        BeforeAll {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ issuer = 'https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0' }
            }
        }

        It 'Resolves the GUID from the discovery document' {
            Resolve-METTenantGuid -TenantId 'contoso.onmicrosoft.com' |
                Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }

        It 'Bounds the call with a timeout' {
            Resolve-METTenantGuid -TenantId 'contoso.onmicrosoft.com' | Out-Null
            Should -Invoke Invoke-RestMethod -ParameterFilter { $TimeoutSec -eq 15 }
        }

        It 'Accepts hyphenated tenant labels' {
            Resolve-METTenantGuid -TenantId 'my-tenant.onmicrosoft.com' |
                Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }

        It 'Constructs the discovery URI from the escaped tenant value' {
            Resolve-METTenantGuid -TenantId 'contoso.onmicrosoft.com' | Out-Null
            Should -Invoke Invoke-RestMethod -ParameterFilter {
                $Uri -eq 'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration'
            }
        }
    }
}
