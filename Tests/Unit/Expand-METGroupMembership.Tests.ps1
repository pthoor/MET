BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Expand-METGroupMembership.ps1"

    function Get-MgGroup                 { [CmdletBinding()] param([string]$Filter,[int]$Top) }
    function Get-MgGroupTransitiveMember { [CmdletBinding()] param([string]$GroupId,[switch]$All) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity,[string]$ResultSize) }
    function Get-UnifiedGroupLinks       { [CmdletBinding()] param([string]$Identity,[string]$LinkType,[string]$ResultSize) }
}

Describe 'Expand-METGroupMembership' {
    BeforeEach {
        Mock Get-MgGroup                 { throw 'Graph not available' }
        Mock Get-MgGroupTransitiveMember { throw 'Graph not available' }
    }

    Context 'Graph unavailable, identity is a distribution group' {
        It 'Resolves members via Get-DistributionGroupMember and never calls Get-UnifiedGroupLinks' {
            Mock Get-DistributionGroupMember {
                @(
                    [PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' }
                    [PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'bob@contoso.com' }
                )
            }
            Mock Get-UnifiedGroupLinks { throw 'should not be called' }

            $result = Expand-METGroupMembership -Identity 'Sales DL' -Cache @{}

            $result | Should -Contain 'alice@contoso.com'
            $result | Should -Contain 'bob@contoso.com'
            Should -Invoke Get-UnifiedGroupLinks -Times 0 -Exactly
        }
    }

    Context 'Graph unavailable, identity is a Microsoft 365 Group (not a valid distribution group)' {
        It 'Falls back to Get-UnifiedGroupLinks and resolves members' {
            Mock Get-DistributionGroupMember { throw 'The recipient "Marketing 365" was not found' }
            Mock Get-UnifiedGroupLinks {
                @(
                    [PSCustomObject]@{ PrimarySmtpAddress = 'carol@contoso.com' }
                    [PSCustomObject]@{ PrimarySmtpAddress = 'dave@contoso.com' }
                )
            }

            $result = Expand-METGroupMembership -Identity 'Marketing 365' -Cache @{}

            $result | Should -Contain 'carol@contoso.com'
            $result | Should -Contain 'dave@contoso.com'
            $result.Count | Should -Be 2
        }
    }

    Context 'Graph, distribution group, and Microsoft 365 Group resolution all fail' {
        It 'Returns an empty array and records a RetrievalError' {
            Mock Get-DistributionGroupMember { throw 'not found as a distribution group' }
            Mock Get-UnifiedGroupLinks { throw 'not found as a unified group either' }

            $errors = [System.Collections.Generic.List[string]]::new()
            $result = Expand-METGroupMembership -Identity 'Ghost Group' -Cache @{} -RetrievalErrors $errors

            $result | Should -BeNullOrEmpty
            $errors.Count | Should -Be 1
            $errors[0] | Should -Match 'Ghost Group'
        }
    }

    Context 'Result is cached' {
        It 'Does not re-query on a second call for the same identity' {
            Mock Get-DistributionGroupMember {
                @([PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' })
            }
            Mock Get-UnifiedGroupLinks { throw 'should not be called' }

            $cache = @{}
            $null = Expand-METGroupMembership -Identity 'Sales DL' -Cache $cache
            $null = Expand-METGroupMembership -Identity 'Sales DL' -Cache $cache

            Should -Invoke Get-DistributionGroupMember -Times 1 -Exactly
        }
    }
}
