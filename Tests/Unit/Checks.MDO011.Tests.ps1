BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO011-UserTags.ps1'
}

Describe 'MET-MDO011 User Tags' {
    Context 'The control cannot be assessed from an Exchange Online session' {
        It 'Returns a single Informational result rather than a verdict on the tenant' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-MDO011'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Name     | Should -Be 'User Tags'
            $results[0].Result   | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].AffectedObject | Should -Be 'User Tags'
            $results[0].Error    | Should -BeNullOrEmpty
        }

        It 'Scores nothing, so an unassessable control cannot move the posture index' {
            $results = @(& $checkFile)
            $results[0].Score | Should -BeNullOrEmpty
        }

        It 'Says why it cannot assess the control, naming both missing capabilities' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'cannot be assessed via Exchange Online PowerShell'
            $results[0].Finding | Should -Match 'no cmdlets exist for custom tag enumeration'
            $results[0].Finding | Should -Match 'Security and Compliance session'
        }

        It 'Points at the portal location and the one property PowerShell can set' {
            $results = @(& $checkFile)
            $results[0].Recommendation | Should -Match 'Settings > Email & collaboration > User tags'
            $results[0].Recommendation | Should -Match 'Set-User -Identity <UPN> -VIP \$true'
            $results[0].ReferenceUrl   | Should -Be 'https://aka.ms/mdo-usertags'
        }

        It 'Calls no Exchange Online, Graph or Teams cmdlet' {
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $checkFile, [ref]$tokens, [ref]$parseErrors)
            $parseErrors | Should -BeNullOrEmpty
            $commands = $ast.FindAll(
                { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() }
            $commands | Should -Be @('New-METCheckResult')
        }
    }
}
