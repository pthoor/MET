BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-DkimSigningConfig { [CmdletBinding()] param() }
}

Describe 'MET-EXO002 DKIM' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO002-DKIM.ps1'
    }

    # Get-DkimSigningConfig reports key size per selector (Selector1KeySize /
    # Selector2KeySize) and never as a flat KeySize property - KeySize exists only as an
    # input parameter on New-/Rotate-DkimSigningConfig. These mocks previously invented a
    # flat KeySize, so the key-length assertion passed in CI against a branch that could
    # never fire against a real tenant.
    Context 'DKIM enabled with 2048-bit key and Valid status' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'DKIM is disabled' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'The active selector still holds a 1024-bit key' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 1024; Selector2KeySize = 1024
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail and mentions key size' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match '1024'
        }
    }

    Context 'A domain mid key-rotation has a 2048-bit active selector and a 1024-bit inactive one' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 1024; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector2'; SelectorAfterRotateOnDate = 'selector1'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Passes on the active selector and notes the pending one rather than failing a correct rotation' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match '2048-bit key on the active selector'
            $results[0].Finding | Should -Match 'selector1 is 1024-bit'
        }
    }

    Context 'Both selectors are 2048-bit but the active selector cannot be determined' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                # SelectorBeforeRotateOnDate / SelectorAfterRotateOnDate absent -> the
                # check cannot tell which selector is active. Both keys are compliant.
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048 }
            }
        }
        It 'Passes without claiming either selector signs after the next rotation' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'will sign after the next key rotation'
        }
    }

    Context 'Neither selector reports a key size' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2' }
            }
        }
        It 'Returns Warning rather than Pass, because the key length went unverified' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'could not be verified'
        }
    }

    Context 'DKIM status is not Valid' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'CnameMissing'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }
        It 'Returns Fail and names the CNAME problem' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'CNAME records are not published'
        }
    }

    Context 'DKIM has no keypair generated' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; Status = 'NoDKIMKeys' }
            }
        }
        It 'Reports the missing keypair rather than a CNAME problem' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'No DKIM keypair'
        }
    }

    Context 'No DKIM configs found' {
        BeforeAll { Mock Get-DkimSigningConfig { @() } }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'Get-DkimSigningConfig throws' {
        BeforeAll { Mock Get-DkimSigningConfig { throw 'Unauthorized' } }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # Get-DkimSigningConfig omits Enabled on service or module versions that do not
    # return it. The check now branches on absence structurally before the -not test,
    # so an unobserved signing state is reported as such rather than as "disabled".
    Context 'The DKIM config object omits the Enabled property' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2'
                    RotateOnDate = [datetime]::UtcNow.AddDays(30) }
            }
        }

        It 'Does not return Pass on a signing state it never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'contoso.com'
        }

        It 'States the property was not returned rather than that signing is disabled' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Enabled was not returned for this domain'
            $results[0].Finding | Should -Not -Match 'DKIM signing is disabled for this domain'
        }
    }

    # Mutation verification: absent Enabled and present-false Enabled must both fail
    # closed, with different Findings.
    Context 'Enabled absent vs. present and false' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2' }
            }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'Enabled was not returned for this domain'
            $absent.Finding | Should -Not -Match 'DKIM signing is disabled for this domain'

            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; Status = 'Valid'
                    Selector1KeySize = 2048; Selector2KeySize = 2048
                    SelectorBeforeRotateOnDate = 'selector1'; SelectorAfterRotateOnDate = 'selector2' }
            }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'DKIM signing is disabled for this domain'
            $present.Finding | Should -Not -Match 'Enabled was not returned for this domain'
        }
    }
}
