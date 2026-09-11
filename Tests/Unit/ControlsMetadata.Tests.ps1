# CONTROLS_META used to be 51 descriptions hand-maintained inside the report's client
# script, a second copy of facts the check scripts already state. Two of them had drifted
# into describing properties their check no longer reads (D-7). It is now generated from
# the $METCheckInfo headers, so this file asserts the generation rather than the literal.
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'Get-METCheckMetadata.ps1')
    . (Join-Path $script:Root 'Public'  'Get-METCheck.ps1')

    # Get-METReport is exercised for real below, and it depends on most of Private/.
    # Import the packaged module rather than dot-sourcing its dependency tree by hand.
    Import-Module (Join-Path $script:Root 'MET.psd1') -Force -ErrorAction Stop

    $script:ReportSource = Get-Content (Join-Path $script:Root 'Public' 'Get-METReport.ps1') -Raw
}

Describe 'CONTROLS_META generation' {

    It 'No longer hardcodes a description literal in the report source' {
        # The whole point: a literal here is a copy that can drift. If this fails, someone
        # has reintroduced the duplication D-7 was about.
        $script:ReportSource | Should -Not -Match "'MET-MDO001':\s*'"
    }

    It 'Emits one entry per check into the rendered report' {
        # Get-METReport's -OutputPath always resolves to a fresh timestamped subfolder
        # (even when given a file path with an extension - see :177/:214/:229), so the
        # generated file is located the same way Get-METReport.Html.Tests.ps1 does,
        # rather than read back from the literal path passed in.
        $results = @(
            [PSCustomObject]@{
                PSTypeName = 'MET.CheckResult'
                CheckId = 'MET-MDO001'; Category = 'MDO'; Name = 'Safe Links'
                Result = 'Pass'; Severity = 'High'; Score = 100
                AffectedObject = 'Default'; Finding = 'Fine'; Recommendation = ''
                ReferenceUrl = ''; Timestamp = [datetime]::UtcNow; Error = $null; Metadata = $null
            }
        )
        $folder = Join-Path $TestDrive 'report'
        $results | Get-METReport -Format HTML -OutputPath $folder -NoLaunch | Out-Null
        $generated = Get-ChildItem -Path $folder -Recurse -Filter '*.html' | Select-Object -First 1
        $generated | Should -Not -BeNullOrEmpty
        $html = Get-Content -LiteralPath $generated.FullName -Raw

        foreach ($check in (Get-METCheck)) {
            $html | Should -BeLike "*'$($check.CheckId)':*" -Because "$($check.CheckId) must appear in the generated CONTROLS_META"
        }
    }

    It 'Carries each check description verbatim from its header' {
        $folder = Join-Path $TestDrive 'report2'
        @() | Get-METReport -Format HTML -OutputPath $folder -NoLaunch | Out-Null
        $generated = Get-ChildItem -Path $folder -Recurse -Filter '*.html' | Select-Object -First 1
        $generated | Should -Not -BeNullOrEmpty
        $html = Get-Content -LiteralPath $generated.FullName -Raw

        $sample = Get-METCheck -CheckId 'MET-Teams002'
        $html | Should -BeLike "*$($sample.Description)*"
    }

    It 'Serializes each description with ConvertTo-Json rather than hand-escaping' {
        # CONTROLS_META is emitted as `'CheckId': <json-string>,` - the value comes straight
        # out of ConvertTo-Json, so quotes, backslashes, and newlines in a drop-in check's
        # description can never corrupt the surrounding JS object literal, unlike a
        # hand-built single-quoted-and-escaped string would.
        $script:ReportSource | Should -Match "ConvertTo-Json\s+-Compress"
    }

    It 'Renders the apostrophe in the two descriptions that actually contain one, unescaped inside a JSON string' {
        # 'ConvertTo-Json -Compress' existing in the source (above) only proves a pattern is
        # present - it says nothing about what the rendered HTML actually contains, and
        # 'Carries each check description verbatim' above samples MET-Teams002, which has
        # no apostrophe, so neither test exercises this path. MET-EXO010 ("tenant's")
        # and MET-MDO014 ("rule's") are the only two of the 51 descriptions that contain an
        # apostrophe, so they are the only ones that can prove this. A fresh subfolder is
        # used so this test cannot pick up a stale report from an earlier run/test.
        $folder = Join-Path $TestDrive 'report3'
        @() | Get-METReport -Format HTML -OutputPath $folder -NoLaunch | Out-Null
        $generated = Get-ChildItem -Path $folder -Recurse -Filter '*.html' | Select-Object -First 1
        $generated | Should -Not -BeNullOrEmpty
        $html = Get-Content -LiteralPath $generated.FullName -Raw

        foreach ($id in 'MET-EXO010', 'MET-MDO014') {
            $check = Get-METCheck -CheckId $id
            $check.Description | Should -Match "'" -Because "$id is asserted here specifically because its header description contains an apostrophe"

            $expectedJson = $check.Description | ConvertTo-Json -Compress
            $html | Should -BeLike "*'$($id)': $expectedJson,*" -Because (
                "$id's description must render as a plain JSON string inside its CONTROLS_META " +
                "entry - a JSON string is double-quoted, so its apostrophe needs no escaping and " +
                "cannot terminate the literal")
        }
    }
}
