BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    Import-Module (Join-Path $root 'MET.psd1') -Force
    . (Join-Path $root 'Private' 'New-METCheckResult.ps1')

    function New-Result {
        param(
            [string] $CheckId,
            [string] $Category = 'MDO',
            [string] $Result,
            $Severity,
            $Score,
            $ErrorText = $null,
            $Timestamp = [datetime]::UtcNow
        )
        [PSCustomObject]@{
            CheckId        = $CheckId
            Category       = $Category
            Name           = $CheckId
            Result         = $Result
            Severity       = $Severity
            Score          = $Score
            AffectedObject = 'target'
            Finding        = 'finding text'
            Recommendation = ''
            ReferenceUrl   = ''
            Timestamp      = $Timestamp
            Error          = $ErrorText
            Metadata       = $null
        }
    }

    function Get-ReportedScore {
        param([object[]] $Results)
        $json = $Results | Get-METReport -Format JSON -TenantName 'contoso.com' | ConvertFrom-Json
        return $json
    }
}

Describe 'Posture score arithmetic' {
    It 'Computes the documented weighted average (Fail/High + Pass/High = 50)' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'High' -Score 100)
            (New-Result -CheckId 'MET-B' -Result 'Fail' -Severity 'High' -Score 0)
        )
        $json.postureScore | Should -Be 50
    }

    It 'Weights Critical findings four times a Low finding' {
        # Critical=40, Low=5. One Critical Fail + one Low Pass:
        # (0*40 + 100*5) / ((40 + 5) * 100) * 100 = 11.1 -> 11
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Fail' -Severity 'Critical' -Score 0)
            (New-Result -CheckId 'MET-B' -Result 'Pass' -Severity 'Low'      -Score 100)
        )
        $json.postureScore | Should -Be 11
    }

    It 'Scores a Warning at half credit' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Warning' -Severity 'High' -Score 50)
        )
        $json.postureScore | Should -Be 50
    }

    It 'Excludes Info and NotApplicable results from the denominator' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass'          -Severity 'High'          -Score 100)
            (New-Result -CheckId 'MET-B' -Result 'Info'          -Severity 'Informational' -Score $null)
            (New-Result -CheckId 'MET-C' -Result 'NotApplicable' -Severity 'Informational' -Score $null)
        )
        $json.postureScore | Should -Be 100
    }

    It 'Renders the documented band label for each score range in the HTML report' {
        # Bands: 0-39 Critical, 40-59 Poor, 60-79 Fair, 80-94 Good, 95-100 Excellent.
        # The band is a console/HTML concern - the JSON payload carries only the number.
        $cases = @(
            @{ Result = 'Pass';    Score = 100; Band = 'Excellent' }
            @{ Result = 'Warning'; Score = 50;  Band = 'Poor' }
            @{ Result = 'Fail';    Score = 0;   Band = 'Critical' }
        )
        foreach ($case in $cases) {
            $results = @(New-Result -CheckId 'MET-A' -Result $case.Result -Severity 'High' -Score $case.Score)

            ($results | Get-METReport -Format JSON -TenantName 'contoso.com' | ConvertFrom-Json).postureScore |
                Should -Be $case.Score

            $folder = Join-Path $TestDrive "band-$($case.Result)"
            $results | Get-METReport -Format HTML -OutputPath $folder -TenantName 'contoso.com' -NoLaunch | Out-Null
            $generated = Get-ChildItem -Path $folder -Recurse -Filter '*.html' | Select-Object -First 1
            $html = Get-Content -Path $generated.FullName -Raw
            $html | Should -Match $case.Band -Because "a score of $($case.Score) is documented as $($case.Band)"
        }
    }
}

Describe 'Checks that failed to run' {
    # Invoke-METAssessment synthesises a Fail/High result with Score = 0 for any check that
    # throws. If that score were null, Get-METReport would drop the check from the
    # weighted average and report a clean posture over a table of its own failures.
    It 'Counts a crashed check against the score instead of silently excluding it' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'High' -Score 100)
            (New-Result -CheckId 'MET-B' -Result 'Pass' -Severity 'High' -Score 100)
            (New-Result -CheckId 'MET-C' -Result 'Pass' -Severity 'High' -Score 100)
            (New-Result -CheckId 'MET-D' -Result 'Fail' -Severity 'High'     -Score 0 -ErrorText 'boom')
            (New-Result -CheckId 'MET-E' -Result 'Fail' -Severity 'Critical' -Score 0 -ErrorText 'boom')
        )
        $json.postureScore | Should -Not -Be 100
        $json.postureScore | Should -Be 50
    }

    It 'Never reaches the Excellent band while any check carries a populated Error' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'Critical' -Score 100)
            (New-Result -CheckId 'MET-B' -Result 'Fail' -Severity 'Critical' -Score 0 -ErrorText 'cmdlet missing')
        )
        $json.postureScore | Should -BeLessThan 95
    }
}

Describe 'Malformed results do not destroy the report' {
    It 'Renders a report when a result carries a null Severity' {
        { Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity $null -Score 100)
        ) } | Should -Not -Throw
    }

    It 'Renders a report when a result carries an unrecognised Severity' {
        { Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'Catastrophic' -Score 100)
        ) } | Should -Not -Throw
    }

    It 'Renders a report when a result carries a null Timestamp' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'High' -Score 100 -Timestamp $null)
        )
        $json.checks[0].timestamp | Should -BeNullOrEmpty
    }

    It 'Still scores the well-formed results alongside a malformed one' {
        $json = Get-ReportedScore -Results @(
            (New-Result -CheckId 'MET-A' -Result 'Pass' -Severity 'High' -Score 100)
            (New-Result -CheckId 'MET-B' -Result 'Fail' -Severity $null  -Score 0)
        )
        $json.checks.Count | Should -Be 2
    }
}

Describe 'Get-METReport with no scorable results' {
    # An empty set is not a catastrophic tenant, it is an absent measurement.
    It 'does not present an empty result set as 0 / Critical' {
        $output = @(Get-METReport -InputObject @() -Format Console 6>&1) -join "`n"

        $output | Should -Match 'No scorable results'
        $output | Should -Not -Match 'Critical'
    }

    It 'does not present an all-Info result set as 0 / Critical' {
        $info = New-METCheckResult -CheckId 'MET-EXO016' -Category EXO -Name 'ARC Trusted Sealers Review' `
            -Result Info -Severity Informational -AffectedObject 'Tenant' -Finding 'None configured.'

        $output = @($info | Get-METReport -Format Console 6>&1) -join "`n"

        $output | Should -Match 'No scorable results'
    }
}

Describe 'Get-METReport issues table ordering' {
    # Sort-Object Severity is alphabetical: Critical, High, Low, Medium.
    It 'orders by severity weight, not alphabetically' {
        $results = @(
            New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
                -Result Fail -Severity Low -AffectedObject 'Default' -Finding 'Low finding.'
            New-METCheckResult -CheckId 'MET-EXO021' -Category EXO -Name 'Mailbox Audit Logging' `
                -Result Fail -Severity Medium -AffectedObject 'Tenant' -Finding 'Medium finding.'
            New-METCheckResult -CheckId 'MET-EXO010' -Category EXO -Name 'Direct Send Protection' `
                -Result Fail -Severity Critical -AffectedObject 'Tenant' -Finding 'Critical finding.'
            New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
                -Result Fail -Severity High -AffectedObject 'Default' -Finding 'High finding.'
        )

        $output = @($results | Get-METReport -Format Console 6>&1) -join "`n"

        $positions = @('Critical finding.','High finding.','Medium finding.','Low finding.') |
            ForEach-Object { $output.IndexOf($_) }

        $positions[0] | Should -BeLessThan $positions[1]
        $positions[1] | Should -BeLessThan $positions[2]
        $positions[2] | Should -BeLessThan $positions[3]
    }
}

Describe 'Get-METReport error bucket consistency' {
    BeforeAll {
        $script:Errored = [PSCustomObject]@{
            PSTypeName = 'MET.CheckResult'
            CheckId = 'MET-EXO011'; Category = 'EXO'; Name = 'Mail Flow Connector Hygiene'
            Result = 'Fail'; Severity = 'High'; Score = 0; AffectedObject = 'N/A'
            Finding = 'Check script failed to execute'; Recommendation = ''; ReferenceUrl = ''
            Timestamp = [datetime]::UtcNow; Error = 'Unable to reach the service.'; Metadata = $null
        }
    }

    # Pass 0, Fail 0, Warning 4, Error 45 printed directly above 40 rows whose Result
    # column read 'Fail'. Bucketing errored checks separately is the documented design;
    # the table contradicting the summary above it is not.
    It 'labels errored rows Error rather than Fail' {
        $output = @($script:Errored | Get-METReport -Format Console 6>&1) -join "`n"

        $output | Should -Match 'could not run'
        $output | Should -Match 'MET-EXO011'
    }

    It 'counts an errored check once, in the Error bucket only' {
        $json = $script:Errored | Get-METReport -Format JSON | ConvertFrom-Json

        $json.summary.Error | Should -Be 1
        $json.summary.Fail  | Should -Be 0
    }
}
