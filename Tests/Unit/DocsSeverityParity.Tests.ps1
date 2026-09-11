# The check headers are the source of truth for Severity - CheckMetadata.Tests.ps1 re-derives
# each header's Severity from the check's own code, so the header is correct by construction.
# README.md's check inventory table and each docs/checks/*.md front-matter line are copies of
# that fact maintained by hand, and nothing enforced that they stayed in sync - MET-EXO006,
# MET-EXO008, MET-EXO009, MET-EXO017, MET-MDO008, MET-MDO010 and MET-Teams005 had all drifted
# from the header before this file existed. These tests close that gap the same way
# CheckMetadata.Tests.ps1 closed the code side: read the header via Get-METCheck, then assert
# both docs agree with it, per check, so a future drift fails naming the exact CheckId.
#
# The header list is also built here, at top level, outside any Describe/BeforeAll. Pester's
# Discovery pass evaluates each It's -ForEach argument immediately as it reads the Describe
# body - before BeforeAll ever runs, since BeforeAll is deferred to the later Run pass (see
# Tests/Unit/CommandHelp.Tests.ps1 for the same pattern). The BeforeAll below still exists
# because Run does not re-execute this top-level code - the per-check helper functions need
# their own copy for the It bodies that call them.
$script:DiscoveryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
. (Join-Path $script:DiscoveryRoot 'Private' 'Get-METCheckMetadata.ps1')
. (Join-Path $script:DiscoveryRoot 'Public'  'Get-METCheck.ps1')
$script:DiscoveryHeaders = @(Get-METCheck) | Sort-Object CheckId

Describe 'Docs/README severity parity with check headers' {

    BeforeAll {
        $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
        . (Join-Path $script:Root 'Private' 'Get-METCheckMetadata.ps1')
        . (Join-Path $script:Root 'Public'  'Get-METCheck.ps1')

        # Re-fetched here (rather than reusing $script:DiscoveryHeaders) because top-level
        # Discovery-phase variables aren't reliably visible from an It body at Run time once
        # more than one spec file is loaded in the same Pester invocation - only the -ForEach
        # argument list itself (evaluated at Discovery) is guaranteed to have survived.
        $script:Headers = @(Get-METCheck) | Sort-Object CheckId

        $script:ReadmePath = Join-Path $script:Root 'README.md'
        $script:ReadmeContent = Get-Content -LiteralPath $script:ReadmePath -Raw

        function Get-METReadmeSeverity {
            param([Parameter(Mandatory)] [string] $CheckId)

            # Inventory rows look like: | MET-EXO006 | Submission Policy | High | Report-to-... |
            $match = [regex]::Match(
                $script:ReadmeContent,
                "\|\s*$([regex]::Escape($CheckId))\s*\|[^|]+\|\s*(\w+)\s*\|"
            )
            if (-not $match.Success) { return $null }
            $match.Groups[1].Value
        }

        function Get-METDocsCheckSeverity {
            param([Parameter(Mandatory)] [string] $CheckId)

            $docFile = Get-ChildItem -Path (Join-Path $script:Root 'docs' 'checks') -Filter "$CheckId-*.md" |
                Select-Object -First 1
            if (-not $docFile) { return $null }

            $content = Get-Content -LiteralPath $docFile.FullName -Raw
            $match = [regex]::Match($content, '\*\*Severity:\*\*\s*(\w+)')
            if (-not $match.Success) { return $null }
            [PSCustomObject]@{
                Severity = $match.Groups[1].Value
                File     = $docFile.Name
            }
        }
    }

    It 'Has at least 51 checks to compare (sanity check on discovery itself)' {
        $script:Headers.Count | Should -BeGreaterOrEqual 51
    }

    Context 'Per check' {

        It 'README.md lists <CheckId> with the header Severity (<Severity>)' -ForEach @(
            $script:DiscoveryHeaders | ForEach-Object { @{ CheckId = $_.CheckId; Severity = $_.Severity } }
        ) {
            $readmeSeverity = Get-METReadmeSeverity -CheckId $CheckId
            $readmeSeverity | Should -Not -BeNullOrEmpty -Because "README.md's check inventory table must list $CheckId"
            $readmeSeverity | Should -Be $Severity -Because "$CheckId's header declares Severity '$Severity', but README.md's inventory table says '$readmeSeverity'"
        }

        It 'docs/checks/<CheckId>-*.md declares the header Severity (<Severity>)' -ForEach @(
            $script:DiscoveryHeaders | ForEach-Object { @{ CheckId = $_.CheckId; Severity = $_.Severity } }
        ) {
            $doc = Get-METDocsCheckSeverity -CheckId $CheckId
            $doc | Should -Not -BeNullOrEmpty -Because "a docs/checks/*.md file with a **Severity:** line must exist for $CheckId"
            $doc.Severity | Should -Be $Severity -Because "$CheckId's header declares Severity '$Severity', but $($doc.File) says '$($doc.Severity)'"
        }
    }
}
