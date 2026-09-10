BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-TransportRule { [CmdletBinding()] param([string]$ResultSize) }

    $checkFile = Join-Path $root 'Checks' 'EXO' 'MET-EXO007-TransportRuleAudit.ps1'

    function New-METTestTransportRule {
        param(
            [string] $Name,
            [object] $SetSCL = $null,
            [string] $SetHeaderName = $null,
            [string] $HeaderContainsMessageHeader = $null,
            [string] $DeleteHeader = $null
        )
        [PSCustomObject]@{
            Name                        = $Name
            SetSCL                      = $SetSCL
            SetHeaderName               = $SetHeaderName
            HeaderContainsMessageHeader = $HeaderContainsMessageHeader
            DeleteHeader                = $DeleteHeader
        }
    }
}

Describe 'MET-EXO007 Transport Rule Audit' {
    Context 'Rules exist but none bypasses spam filtering or Safe Links' {
        BeforeAll {
            Mock Get-TransportRule {
                @(
                    New-METTestTransportRule -Name 'Append disclaimer'
                    New-METTestTransportRule -Name 'Block executables'
                )
            }
        }

        It 'Reports Info with the rule count assessed' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-EXO007'
            $results[0].Category | Should -Be 'EXO'
            $results[0].Name     | Should -Be 'Transport Rule Audit'
            $results[0].Result   | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Transport Rules (2 total)'
            $results[0].Finding  | Should -Match 'No rules bypassing spam filtering or disabling Safe Links found'
            $results[0].Error    | Should -BeNullOrEmpty
        }
    }

    Context 'A rule bypasses spam filtering with SCL -1' {
        BeforeAll {
            Mock Get-TransportRule {
                @(
                    New-METTestTransportRule -Name 'Allow partner mail' -SetSCL -1
                    New-METTestTransportRule -Name 'Append disclaimer'
                )
            }
        }

        It 'Warns at Medium severity naming the bypassing rule and not the innocent one' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Transport Rules (2 total)'
            $results[0].Finding  | Should -Match '1 rule\(s\) bypass spam filtering \(SCL=-1\): Allow partner mail'
            $results[0].Finding  | Should -Not -Match 'Append disclaimer'
        }

        It 'Recommends narrowing rather than a blanket removal' {
            $results = @(& $checkFile)
            $results[0].Recommendation | Should -Match 'scoped as narrowly as possible'
        }
    }

    Context 'A rule sets the Safe Links skip header' {
        BeforeAll {
            Mock Get-TransportRule {
                @(New-METTestTransportRule -Name 'Skip Safe Links for newsletters' `
                    -SetHeaderName 'X-MS-Exchange-Organization-SkipSafeLinksProcessing')
            }
        }

        It 'Warns naming the rule as disabling Safe Links, not as a spam bypass' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match '1 rule\(s\) appear to disable Safe Links processing: Skip Safe Links for newsletters'
            $results[0].Finding  | Should -Not -Match 'bypass spam filtering'
        }
    }

    Context 'A rule deletes a Safe Links header instead of setting one' {
        BeforeAll {
            Mock Get-TransportRule {
                @(New-METTestTransportRule -Name 'Strip Safe Links stamp' `
                    -HeaderContainsMessageHeader 'X-MS-Exchange-Organization-SafeLinks' `
                    -DeleteHeader 'X-MS-Exchange-Organization-SafeLinksProcessed')
            }
        }

        It 'Warns naming the rule' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'disable Safe Links processing: Strip Safe Links stamp'
        }
    }

    Context 'Both fault classes are present at once' {
        BeforeAll {
            Mock Get-TransportRule {
                @(
                    New-METTestTransportRule -Name 'Allow partner mail' -SetSCL -1
                    New-METTestTransportRule -Name 'Allow vendor mail'  -SetSCL -1
                    New-METTestTransportRule -Name 'Skip Safe Links'    -SetHeaderName 'X-MS-Exchange-Organization-SkipSafeLinksProcessing'
                )
            }
        }

        It 'Warns once, naming both counts and every rule' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result  | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Be 'Transport Rules (3 total)'
            $results[0].Finding | Should -Match '2 rule\(s\) bypass spam filtering \(SCL=-1\): Allow partner mail, Allow vendor mail'
            $results[0].Finding | Should -Match '1 rule\(s\) appear to disable Safe Links processing: Skip Safe Links'
        }
    }

    Context 'A rule sets an SCL value other than -1' {
        BeforeAll {
            Mock Get-TransportRule {
                @(
                    New-METTestTransportRule -Name 'Raise SCL for bulk' -SetSCL 6
                    New-METTestTransportRule -Name 'Append disclaimer'
                )
            }
        }

        It 'Stays Info but records the override as a note rather than a fault' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'No rules bypassing spam filtering or disabling Safe Links found'
            $results[0].Finding  | Should -Match 'Note: 1 rule\(s\) explicitly set SCL \(non-bypass\): Raise SCL for bulk'
        }
    }

    Context 'The tenant has no transport rules' {
        BeforeAll {
            Mock Get-TransportRule { @() }
        }

        It 'Reports Info rather than a verdict on rules that do not exist' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Transport Rules'
            $results[0].Finding  | Should -Be 'No transport rules found'
        }
    }

    Context 'Get-TransportRule throws' {
        BeforeAll {
            Mock Get-TransportRule { throw 'Insufficient access rights to perform the operation.' }
        }

        It 'Fails once, carrying the exception text in Error rather than the Finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Transport Rules'
            $results[0].Finding | Should -Match 'Unable to retrieve transport rules'
            $results[0].Error   | Should -Match 'Insufficient access rights'
            $results[0].Finding | Should -Not -Match 'Insufficient access rights'
        }
    }

    Context 'A rule object omits the properties the check reads' {
        BeforeAll {
            Mock Get-TransportRule {
                @([PSCustomObject]@{ Name = 'Append disclaimer'; State = 'Enabled' })
            }
        }

        It 'Reports Info and never Pass, so an unread property cannot become an all-clear' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].Score  | Should -BeNullOrEmpty
        }
    }
}
