BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

    # CONTROLS_META lives inside the report's embedded client script, so it is read as text
    # rather than evaluated. The block is a flat JS object literal of 'MET-XXXnnn': '<description>'
    # entries; anything that stops matching that shape stops being covered by this file, so the
    # entry count is asserted below to catch a reshaping that silently empties the parse.
    $reportSource = Get-Content (Join-Path $root 'Public' 'Get-METReport.ps1') -Raw
    $metaStart = $reportSource.IndexOf('const CONTROLS_META = {')
    $metaStart | Should -BeGreaterThan -1 -Because 'the CONTROLS_META block must still exist in Get-METReport.ps1'
    $metaEnd = $reportSource.IndexOf("`n};", $metaStart)
    $metaBlock = $reportSource.Substring($metaStart, $metaEnd - $metaStart)

    $script:ControlsMeta = [ordered]@{}
    foreach ($line in ($metaBlock -split "`n")) {
        if ($line -match "^\s*'(?<id>MET-[A-Za-z]+\d{3})'\s*:\s*'(?<desc>.*)'\s*,?\s*$") {
            $script:ControlsMeta[$Matches.id] = $Matches.desc -replace "\\'", "'"
        }
    }

    # Discovered exactly the way Invoke-METTriage discovers them, so a file this test cannot see
    # is a file the triage run cannot see either.
    $script:CheckFiles = [ordered]@{}
    Get-ChildItem -Path (Join-Path $root 'Checks') -Recurse -Filter 'MET-*.ps1' |
        Sort-Object Name |
        ForEach-Object {
            $id = ($_.BaseName -split '-')[0..1] -join '-'
            $script:CheckFiles[$id] = $_
        }

    # Identifiers a description names - cmdlet names and Pascal/camel-cased property names.
    # A description naming a property the check does not read is the drift D-7 describes, and
    # it is the only part of a free-text description that can be verified mechanically.
    function Get-METDescribedIdentifier {
        param([string] $Description)
        [regex]::Matches(
            $Description,
            '\b[A-Za-z][A-Za-z0-9]*[a-z0-9][A-Z][A-Za-z0-9]*\b|\b(?:Get|Set|New|Test)-[A-Za-z0-9]+\b'
        ) | ForEach-Object { $_.Value } | Sort-Object -Unique
    }

    function Get-METDescriptionDrift {
        $drift = [ordered]@{}
        foreach ($id in $script:ControlsMeta.Keys) {
            if (-not $script:CheckFiles.Contains($id)) { continue }
            $body = Get-Content $script:CheckFiles[$id].FullName -Raw
            $absent = Get-METDescribedIdentifier -Description $script:ControlsMeta[$id] |
                Where-Object { $body -notmatch [regex]::Escape($_) }
            if ($absent) { $drift[$id] = @($absent) }
        }
        $drift
    }
}

Describe 'CONTROLS_META and the Checks directory' {

    It 'Parses every CONTROLS_META entry' {
        # A reshaped block that no longer parses would make every assertion below vacuously
        # pass, so the parse itself is pinned against the current check population.
        $script:ControlsMeta.Count | Should -Be 51
        $script:CheckFiles.Count   | Should -Be 51
    }

    It 'Has a CONTROLS_META entry for every check script' {
        $missing = @($script:CheckFiles.Keys | Where-Object { -not $script:ControlsMeta.Contains($_) })
        $missing | Should -BeNullOrEmpty -Because (
            "these checks ship in the HTML report with no description, falling back to their Name: $($missing -join ', ')")
    }

    It 'Has a check script for every CONTROLS_META entry' {
        $orphaned = @($script:ControlsMeta.Keys | Where-Object { -not $script:CheckFiles.Contains($_) })
        $orphaned | Should -BeNullOrEmpty -Because (
            "these entries describe a check that no longer exists under Checks/: $($orphaned -join ', ')")
    }

    It 'Records each check under the category its directory declares' {
        # CONTROLS_META carries no category field of its own - the category is encoded in the
        # entry key, and the report groups the controls table by the Category the check emits.
        # The key prefix and the check's directory are therefore the two halves that must agree.
        $mismatched = foreach ($id in $script:ControlsMeta.Keys) {
            if (-not $script:CheckFiles.Contains($id)) { continue }
            $directory = $script:CheckFiles[$id].Directory.Name
            $prefix = if ($id -match '^MET-(MDO|EXO|Teams)\d{3}$') { $Matches[1] } else { '<unparseable>' }
            if ($prefix -ne $directory) { "$id keyed as $prefix but lives in Checks/$directory" }
        }
        @($mismatched) | Should -BeNullOrEmpty
    }

    It 'Keys each entry on the CheckId the check script actually emits' {
        # The key match above is only meaningful if the filename prefix is also the CheckId the
        # check passes to New-METCheckResult. A check whose file is named for one ID and reports
        # another would satisfy every key comparison while the report still described it wrongly.
        $wrong = foreach ($id in $script:CheckFiles.Keys) {
            $body = Get-Content $script:CheckFiles[$id].FullName -Raw
            $emitted = @([regex]::Matches($body, '-CheckId\s+[''"](?<id>[^''"]+)[''"]') |
                ForEach-Object { $_.Groups['id'].Value } | Sort-Object -Unique)
            if (-not $emitted) { "$id emits no literal -CheckId" }
            elseif ($emitted.Count -gt 1 -or $emitted[0] -ne $id) { "$id emits $($emitted -join ', ')" }
        }
        @($wrong) | Should -BeNullOrEmpty
    }

    It 'Gives every check a non-empty Name to render beside its description' {
        # CONTROLS_META holds a description only - the report's Name column is read from the live
        # result (CONTROLS_META[c.checkId] || c.name), so there is no stored name to compare a
        # check's Name against. What is verifiable is that each check supplies one at all.
        $nameless = foreach ($id in $script:CheckFiles.Keys) {
            $body = Get-Content $script:CheckFiles[$id].FullName -Raw
            $names = @([regex]::Matches($body, '-Name\s+[''"](?<n>[^''"]+)[''"]') |
                ForEach-Object { $_.Groups['n'].Value } | Sort-Object -Unique)
            if (-not $names) { $id }
        }
        @($nameless) | Should -BeNullOrEmpty
    }

    Context 'Descriptions naming a setting the check does not read' {

        # Pins current content, two entries of which are wrong: each names a property its check
        # no longer reads, so the shipped HTML report describes a control the tenant was never
        # assessed against. Left pinned rather than corrected here so the drift is visible and
        # cannot change unnoticed - correcting the descriptions is its own change.
        #
        #   MET-Teams002 names EnableSafeAttachmentsForTeams. No such property exists on
        #     Get-SafeAttachmentPolicy and the check stopped requiring it; it now grades
        #     EnableATPForSPOTeamsODB alone. Correct description: the global
        #     EnableATPForSPOTeamsODB toggle on Get-AtpPolicyForO365, with the
        #     "EnableSafeAttachmentsForTeams enabled in at least one policy" clause removed.
        #   MET-Teams005 names ReportTeamsMsgEnabled. The check reads
        #     ReportChatMessageEnabled and ReportChatMessageToCustomizedAddressEnabled.
        #     Correct description: those two property names in place of ReportTeamsMsgEnabled.
        BeforeAll {
            $script:PinnedDescriptionDrift = @{
                'MET-Teams002' = @('EnableSafeAttachmentsForTeams')
                'MET-Teams005' = @('ReportTeamsMsgEnabled')
            }
        }

        It 'Currently names two settings that no longer exist in their check, and no others' {
            $drift = Get-METDescriptionDrift
            $unpinned = foreach ($id in $drift.Keys) {
                $expected = $script:PinnedDescriptionDrift[$id]
                $new = @($drift[$id] | Where-Object { $_ -notin $expected })
                if (-not $expected) { "$id : $($drift[$id] -join ', ')" }
                elseif ($new) { "$id : $($new -join ', ')" }
            }
            @($unpinned) | Should -BeNullOrEmpty -Because (
                'a CONTROLS_META description must not name a cmdlet or property its check never reads')
        }

        It 'Still carries the two pinned drifted entries' {
            # The other half of the pin: once a description is corrected this fails, which is the
            # signal to delete its entry from $script:PinnedDescriptionDrift above.
            $drift = Get-METDescriptionDrift
            foreach ($id in $script:PinnedDescriptionDrift.Keys) {
                $drift.Contains($id) | Should -BeTrue -Because "$id is pinned as drifted"
                foreach ($ident in $script:PinnedDescriptionDrift[$id]) {
                    $drift[$id] | Should -Contain $ident
                }
            }
        }
    }
}
