BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force -ErrorAction Stop
}

Describe 'Get-METReport structured metadata' {
    It 'preserves effective policy coverage metadata in JSON and HTML' {
        $output = Join-Path $TestDrive 'reports'
        $result = [PSCustomObject]@{
            CheckId = 'MET-MDO001'; Category = 'MDO'; Name = 'Safe Links Effective Coverage'
            Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'Tenant (2 mailboxes)'
            Finding = 'All recipients meet the baseline.'; Recommendation = ''; ReferenceUrl = 'https://aka.ms/mdo-safelinks'
            Timestamp = [datetime]::UtcNow; Error = $null
            Metadata = @{ DetailType = 'EffectivePolicyCoverage'; ProtectionType = 'Safe Links'; TotalRecipients = 2; OrderingObservations = @(@{ Severity='Warning'; Message='Catch-all shadows a specialized policy' }); CoverageRecommendations=@('Add a compliant catch-all after specialized policies'); Policies = @(@{ PolicyName = 'Strict custom'; EffectiveRecipientCount = 2; OrderingObservations=@('Catch-all shadows a specialized policy') }) }
        }

        $result | Get-METReport -Format All -OutputPath $output -TenantName 'contoso.com' -NoLaunch
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json
        $html = Get-Content (Join-Path $folder.FullName 'MET-report.html') -Raw

        $json.checks | Should -HaveCount 1
        $json.checks[0].metadata.totalRecipients | Should -Be 2
        $json.checks[0].metadata.policies[0].policyName | Should -Be 'Strict custom'
        $json.checks[0].metadata.orderingObservations[0].severity | Should -Be 'Warning'
        $html | Should -Match 'EffectivePolicyCoverage'
        $html | Should -Match 'ProtectionType.*Safe Links'
        $html | Should -Match 'coverage-table'
        $html | Should -Match '<th>Scope</th>'
        $html | Should -Match '<th>Effective recipients</th>'
        $html | Should -Match '<th>Configuration</th>'
        $html | Should -Match '<th>Current impact</th>'
        $html | Should -Match '<th>Ordering observations</th>'
        $html | Should -Match 'Catch-all shadows a specialized policy'
        $html | Should -Match 'Add a compliant catch-all after specialized policies'
        $html | Should -Not -Match ([string][char]0x2014)
    }

    It 'does not double-count results that carry both a Result and a populated Error field' {
        $output = Join-Path $TestDrive 'reports-error-summary'
        $results = @(
            [PSCustomObject]@{
                CheckId = 'MET-Teams009'; Category = 'Teams'; Name = 'Pass check'
                Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'Tenant'
                Finding = 'ok'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-Teams010'; Category = 'Teams'; Name = 'Fail with retrieval error'
                Result = 'Fail'; Severity = 'Medium'; Score = 0; AffectedObject = 'Tenant'
                Finding = 'could not retrieve'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = 'Get-CsExternalAccessPolicy threw'
            },
            [PSCustomObject]@{
                CheckId = 'MET-Teams014'; Category = 'Teams'; Name = 'NotApplicable with error detail'
                Result = 'NotApplicable'; Severity = 'Medium'; Score = $null; AffectedObject = 'Tenant'
                Finding = 'Graph unavailable'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = 'Authentication needed. Please call Connect-MgGraph.'
            }
        )

        $results | Get-METReport -Format JSON -OutputPath $output -TenantName 'contoso.com'
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json

        $json.checks | Should -HaveCount 3
        $total = $json.summary.Pass + $json.summary.Fail + $json.summary.Warning + $json.summary.NotApplicable + $json.summary.Info + $json.summary.Error
        $total | Should -Be 3
        $json.summary.Pass | Should -Be 1
        $json.summary.Fail | Should -Be 0
        $json.summary.NotApplicable | Should -Be 0
        $json.summary.Error | Should -Be 2
    }

    It 'renders an HTML banner that counts an errored check once, under Error only' {
        $output = Join-Path $TestDrive 'reports-error-summary-html'
        $results = @(
            [PSCustomObject]@{
                CheckId = 'MET-Teams010'; Category = 'Teams'; Name = 'Fail with retrieval error'
                Result = 'Fail'; Severity = 'Medium'; Score = 0; AffectedObject = 'Tenant'
                Finding = 'could not retrieve'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = 'Get-CsExternalAccessPolicy threw'
            }
        )

        $results | Get-METReport -Format HTML -OutputPath $output -TenantName 'contoso.com' -NoLaunch
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $html = Get-Content (Join-Path $folder.FullName 'MET-report.html') -Raw

        # Error is its own bucket, mutually exclusive with every Result-based bucket: this
        # result is a Fail that carries an Error, so it belongs to Error and to nothing else.
        # This asserts the server-rendered half of that invariant - the numbers baked into the
        # banner markup. The client half (renderDonut() recomputing the same buckets on load
        # and on every risk-acceptance toggle) is only observable in a rendered document and is
        # asserted at the DOM level in Tests/Html/summary-counters.spec.js.
        $html | Should -Match '(?s)id="sum-err">1<'
        $html | Should -Match '(?s)id="sum-fail">0<'
        $html | Should -Match '(?s)id="sum-warn">0<'
        $html | Should -Match '(?s)id="sum-pass">0<'
        $html | Should -Match '(?s)id="sum-na">0<'
        $html | Should -Match '(?s)id="sum-info">0<'
    }

    It 'counts Info results in the summary and includes them in the console/JSON total' {
        $output = Join-Path $TestDrive 'reports-info-summary'
        $results = @(
            [PSCustomObject]@{
                CheckId = 'MET-EXO016'; Category = 'EXO'; Name = 'ARC Trusted Sealers Review'
                Result = 'Info'; Severity = 'Low'; Score = $null; AffectedObject = 'ARC Trusted Sealers'
                Finding = 'No ARC trusted sealers configured'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-EXO017'; Category = 'EXO'; Name = 'Quarantine Notification Cadence'
                Result = 'Info'; Severity = 'Informational'; Score = $null; AffectedObject = 'Global Quarantine Notification Settings'
                Finding = 'Sent every 4 hours'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-EXO001'; Category = 'EXO'; Name = 'DMARC'
                Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'contoso.com'
                Finding = 'ok'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            }
        )

        $results | Get-METReport -Format JSON -OutputPath $output -TenantName 'contoso.com'
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json

        $json.checks | Should -HaveCount 3
        $json.summary.Info | Should -Be 2
        $json.summary.Pass | Should -Be 1
        $total = $json.summary.Pass + $json.summary.Fail + $json.summary.Warning + $json.summary.NotApplicable + $json.summary.Info + $json.summary.Error
        $total | Should -Be 3
    }
}

Describe 'Get-METReport output path reporting' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' '..' 'Private' 'New-METCheckResult.ps1')
        $script:Sample = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Fail -Severity High -AffectedObject 'Default Policy' -Finding 'Disabled.'
    }

    # The file lands in <OutputPath>/<timestamp>-<tenant>/MET-report.html - a subfolder
    # the user never named and was never told about, because both announcements used
    # Write-Verbose. This is README Quickstart step 5.
    It 'announces the resolved path on the host stream' {
        $output = Join-Path $TestDrive 'q1'
        $hostOutput = @($script:Sample | Get-METReport -Format HTML -OutputPath $output -NoLaunch 6>&1) -join "`n"

        $hostOutput | Should -Match 'MET-report\.html'
        $hostOutput | Should -Match ([regex]::Escape($output))
    }

    It 'returns the written files with -PassThru' {
        $output = Join-Path $TestDrive 'q2'
        $written = $script:Sample | Get-METReport -Format All -OutputPath $output -NoLaunch -PassThru

        @($written).Count | Should -Be 2
        @($written | ForEach-Object { $_.Name }) | Should -Contain 'MET-report.json'
        @($written | ForEach-Object { $_.Name }) | Should -Contain 'MET-report.html'
        foreach ($file in $written) { Test-Path -LiteralPath $file.FullName | Should -BeTrue }
    }

    It 'returns nothing without -PassThru' {
        $output = Join-Path $TestDrive 'q3'
        $written = $script:Sample | Get-METReport -Format JSON -OutputPath $output -NoLaunch

        $written | Should -BeNullOrEmpty
    }

    It 'does not launch a browser with -NoLaunch' {
        Mock -ModuleName 'MET' -CommandName 'Start-Process' -MockWith { }
        $output = Join-Path $TestDrive 'q4'

        $script:Sample | Get-METReport -Format HTML -OutputPath $output -NoLaunch | Out-Null

        Should -Invoke -ModuleName 'MET' -CommandName 'Start-Process' -Times 0
    }
}

Describe 'Get-METReport format and path combinations' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' '..' 'Private' 'New-METCheckResult.ps1')
        $script:Sample = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Fail -Severity High -AffectedObject 'Default Policy' -Finding 'Disabled.'
    }

    # -Format All already errors correctly here. HTML dumped 1178 lines of markup to
    # the console instead. JSON to stdout is left alone - piping it is genuinely useful.
    It 'throws for -Format HTML with no -OutputPath' {
        { $script:Sample | Get-METReport -Format HTML } |
            Should -Throw -ExpectedMessage '*-OutputPath*'
    }

    It 'still allows -Format JSON with no -OutputPath' {
        { $script:Sample | Get-METReport -Format JSON } | Should -Not -Throw
    }

    # -Format All also requires -OutputPath, but $wantsHtml includes 'All' so the HTML
    # guard fired first and told a user who asked for All that '-Format HTML requires
    # -OutputPath' - naming a format they never requested.
    It 'names the format actually requested when -Format All has no -OutputPath' {
        { $script:Sample | Get-METReport -Format All } |
            Should -Throw -ExpectedMessage '*-Format All*'
    }

    It 'still names HTML when -Format HTML has no -OutputPath' {
        { $script:Sample | Get-METReport -Format HTML } |
            Should -Throw -ExpectedMessage '*-Format HTML*'
    }

    It 'warns that -OutputPath is ignored for -Format Console' {
        $warnings = @()
        $script:Sample | Get-METReport -Format Console -OutputPath (Join-Path $TestDrive 'ignored') `
            -WarningVariable warnings -WarningAction SilentlyContinue 6>&1 | Out-Null

        ($warnings -join ' ') | Should -Match 'Console'
        ($warnings -join ' ') | Should -Match 'ignored'
    }

    It 'does not create the directory it was told to ignore' {
        $ignored = Join-Path $TestDrive 'ignored2'
        $script:Sample | Get-METReport -Format Console -OutputPath $ignored `
            -WarningAction SilentlyContinue 6>&1 | Out-Null

        Test-Path -LiteralPath $ignored | Should -BeFalse
    }
}

Describe 'Get-METReport path and input handling' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' '..' 'Private' 'New-METCheckResult.ps1')
        $script:Sample = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Fail -Severity High -AffectedObject 'Default Policy' -Finding 'Disabled.'
    }

    # -Path interprets [ and ] as a wildcard character class, so a customer folder
    # named 'Contoso [2026]' silently resolved to nothing.
    It 'writes to a path containing square brackets' {
        $bracketed = Join-Path $TestDrive 'Contoso [2026]'
        $script:Sample | Get-METReport -Format JSON -OutputPath $bracketed -NoLaunch | Out-Null

        $folder = Get-ChildItem -LiteralPath $bracketed -Directory | Select-Object -First 1
        Test-Path -LiteralPath (Join-Path $folder.FullName 'MET-report.json') | Should -BeTrue
    }

    # Split-Path has no parameter set combining -LiteralPath with -Parent or -Leaf, so
    # converting these two call sites to -LiteralPath made every -OutputPath that names a
    # file throw 'Parameter set cannot be resolved' before writing anything - exactly the
    # two invocations README/CLAUDE.md document. Every other test here passes a directory,
    # which takes the other branch, so 1041 green tests never touched this.
    It 'writes a JSON report when -OutputPath names a file' {
        $target = Join-Path $TestDrive 'named-json' 'custom-name.json'

        { $script:Sample | Get-METReport -Format JSON -OutputPath $target | Out-Null } |
            Should -Not -Throw

        $written = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'named-json') -Recurse -File -Filter 'custom-name.json')
        $written.Count | Should -Be 1
    }

    It 'writes an HTML report when -OutputPath names a file' {
        $target = Join-Path $TestDrive 'named-html' 'custom-name.html'

        { $script:Sample | Get-METReport -Format HTML -OutputPath $target -NoLaunch | Out-Null } |
            Should -Not -Throw

        $written = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'named-html') -Recurse -File -Filter 'custom-name.html')
        $written.Count | Should -Be 1
    }

    # The named file still lands inside the per-run <timestamp>-<tenant> subfolder, which is
    # the behavior that shipped before the -LiteralPath regression. Asserted so a future
    # change to that layout is a deliberate one.
    It 'keeps a named output file inside the per-run assessment folder' {
        $target = Join-Path $TestDrive 'named-layout' 'custom-name.json'

        $script:Sample | Get-METReport -Format JSON -OutputPath $target | Out-Null

        $runFolder = Get-ChildItem -LiteralPath (Join-Path $TestDrive 'named-layout') -Directory | Select-Object -First 1
        $runFolder | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $runFolder.FullName 'custom-name.json') | Should -BeTrue
    }

    # -OutputPath containing brackets must survive the file-naming branch too, which is
    # why the fix uses [System.IO.Path] rather than reverting to Split-Path -Path.
    It 'writes to a named output file under a bracketed folder' {
        $target = Join-Path $TestDrive 'Contoso [2027]' 'custom-name.json'

        { $script:Sample | Get-METReport -Format JSON -OutputPath $target | Out-Null } |
            Should -Not -Throw

        $written = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'Contoso [2027]') -Recurse -File -Filter 'custom-name.json')
        $written.Count | Should -Be 1
    }
}
