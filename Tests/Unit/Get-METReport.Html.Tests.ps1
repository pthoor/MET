BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force -ErrorAction Stop

    function New-METTestResult {
        param(
            [string] $CheckId, [string] $Category, [string] $Name, [string] $Result,
            [string] $Severity, [object] $Score, [string] $AffectedObject, [string] $Finding,
            [string] $Recommendation = '', [string] $ReferenceUrl = '',
            [string] $ErrorText = $null, [hashtable] $Metadata = $null
        )
        [PSCustomObject]@{
            CheckId        = $CheckId
            Category       = $Category
            Name           = $Name
            Result         = $Result
            Severity       = $Severity
            Score          = $Score
            AffectedObject = $AffectedObject
            Finding        = $Finding
            Recommendation = $Recommendation
            ReferenceUrl   = $ReferenceUrl
            Timestamp      = [datetime]::UtcNow
            Error          = $ErrorText
            Metadata       = $Metadata
        }
    }

    function Get-METTestHtml {
        param([object[]] $Results, [string] $Folder, [string] $TenantName = 'contoso.onmicrosoft.com')

        $Results | Get-METReport -Format HTML -OutputPath $Folder -TenantName $TenantName | Out-Null
        $generated = Get-ChildItem -Path $Folder -Recurse -Filter '*.html' | Select-Object -First 1
        $generated | Should -Not -BeNullOrEmpty
        Get-Content -Path $generated.FullName -Raw
    }

    function Get-METTestResultSet {
        @(
            New-METTestResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' -Recommendation 'Enable Safe Links for email.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'
            New-METTestResult -CheckId 'MET-MDO002' -Category 'MDO' -Name 'Safe Attachments Policy' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Marketing policy' -Finding 'Action is Monitor'
            New-METTestResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Pass' `
                -Severity 'High' -Score 100 -AffectedObject 'contoso.com' -Finding 'DMARC policy is reject'
            New-METTestResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Transport Rule Audit' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Mail flow rules' -Finding 'Two rules bypass filtering'
            New-METTestResult -CheckId 'MET-Teams014' -Category 'Teams' -Name 'Cross-Tenant Access' -Result 'NotApplicable' `
                -Severity 'Medium' -Score $null -AffectedObject 'Cross-tenant access policy' `
                -Finding 'Microsoft Graph is not connected' -ErrorText 'Authentication needed. Please call Connect-MgGraph.'
        )
    }
}

Describe 'Get-METReport HTML self-containment' {
    BeforeAll {
        $script:selfContainedHtml = Get-METTestHtml -Results (Get-METTestResultSet) -Folder (Join-Path $TestDrive 'self-contained')
    }

    It 'loads no external script' {
        $script:selfContainedHtml | Should -Not -Match '<script[^>]+\bsrc\s*='
    }

    It 'loads no external stylesheet' {
        $script:selfContainedHtml | Should -Not -Match '<link[^>]*rel\s*=\s*"stylesheet"'
        $script:selfContainedHtml | Should -Not -Match '@import'
    }

    It 'references no CDN or remote asset in any resource-loading attribute' {
        $resourceRefs = [regex]::Matches(
            $script:selfContainedHtml,
            '(?i)\b(?:src|srcset|data-src|poster)\s*=\s*"([^"]*)"'
        ) | ForEach-Object { $_.Groups[1].Value }

        foreach ($ref in $resourceRefs) {
            $ref | Should -Not -Match '(?i)^\s*https?:'
        }

        $script:selfContainedHtml | Should -Not -Match '(?i)<link[^>]*href\s*=\s*"https?:'
        $script:selfContainedHtml | Should -Not -Match '(?i)<iframe'
        $script:selfContainedHtml | Should -Not -Match '(?i)(cdn|unpkg|jsdelivr|googleapis|cloudflare)\.'
    }

    It 'inlines the stylesheet and the script' {
        $script:selfContainedHtml | Should -Match '<style>'
        $script:selfContainedHtml | Should -Match '<script>'
    }
}

Describe 'Get-METReport HTML card and summary emission' {
    BeforeAll {
        $script:cardHtml = Get-METTestHtml -Results (Get-METTestResultSet) -Folder (Join-Path $TestDrive 'cards')
    }

    It 'embeds a check entry for every CheckId supplied' {
        foreach ($checkId in @('MET-MDO001', 'MET-MDO002', 'MET-EXO001', 'MET-EXO007', 'MET-Teams014')) {
            $script:cardHtml | Should -Match ('"checkId":"{0}"' -f [regex]::Escape($checkId))
        }
        ([regex]::Matches($script:cardHtml, '"checkId":"MET-')).Count | Should -Be 5
    }

    It 'carries every field the card renders from' {
        $script:cardHtml | Should -Match '"affectedObject":"Default Safe Links Policy"'
        $script:cardHtml | Should -Match '"finding":"Safe Links is disabled for email"'
        $script:cardHtml | Should -Match '"recommendation":"Enable Safe Links for email."'
        $script:cardHtml | Should -Match '"severity":"High"'
    }

    It 'renders banner counts that match the input set' {
        $script:cardHtml | Should -Match '(?s)id="sum-fail">1<'
        $script:cardHtml | Should -Match '(?s)id="sum-warn">1<'
        $script:cardHtml | Should -Match '(?s)id="sum-pass">1<'
        $script:cardHtml | Should -Match '(?s)id="sum-info">1<'
        $script:cardHtml | Should -Match '(?s)id="sum-err">1<'
        $script:cardHtml | Should -Match '(?s)id="sum-na">0<'
    }

    It 'renders a posture score and a non-empty band label' {
        $score = [regex]::Match($script:cardHtml, 'id="donut-score-text">(\d+)<').Groups[1].Value
        $score | Should -Not -BeNullOrEmpty
        [int]$score | Should -BeGreaterOrEqual 0
        [int]$score | Should -BeLessOrEqual 100

        $band = [regex]::Match($script:cardHtml, 'id="score-band">([^<]*)<').Groups[1].Value
        $band | Should -BeIn @('Critical', 'Poor', 'Fair', 'Good', 'Excellent')
    }

    It 'surfaces the Error text of a check that failed to run' {
        $script:cardHtml | Should -Match '"error":"Authentication needed. Please call Connect-MgGraph."'
        $script:cardHtml | Should -Match 'card-error'
    }

    It 'carries structured Metadata through to the embedded check data' {
        $withMetadata = New-METTestResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' `
            -Result 'Pass' -Severity 'High' -Score 100 -AffectedObject 'Tenant' -Finding 'ok' `
            -Metadata @{ DetailType = 'EffectivePolicyCoverage'; TotalRecipients = 7 }

        $html = Get-METTestHtml -Results @($withMetadata) -Folder (Join-Path $TestDrive 'metadata')
        $html | Should -Match 'EffectivePolicyCoverage'
        $html | Should -Match '"TotalRecipients":7'
    }
}

Describe 'Get-METReport HTML injection safety' {
    BeforeAll {
        $script:scriptBreakout = '</script><img src=x onerror=alert(1)>'
        $script:attributeBreakout = '"><svg onload=alert(1)>'
        $script:quoteAndBackslash = 'single '' double " backslash \ end'

        $hostile = @(
            New-METTestResult -CheckId 'MET-MDO001' -Category 'MDO' -Name ('Name ' + $script:attributeBreakout) `
                -Result 'Fail' -Severity 'High' -Score 0 `
                -AffectedObject $script:scriptBreakout `
                -Finding ($script:attributeBreakout + ' and ' + $script:quoteAndBackslash) `
                -Recommendation $script:scriptBreakout `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'
            New-METTestResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'Hostile error text' `
                -Result 'Fail' -Severity 'High' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'retrieval failed' -ErrorText $script:scriptBreakout
        )

        $script:hostileHtml = Get-METTestHtml -Results $hostile -Folder (Join-Path $TestDrive 'hostile') -TenantName $script:scriptBreakout
    }

    It 'never emits the raw image-onerror payload' {
        $script:hostileHtml | Should -Not -Match '<img src=x onerror='
    }

    It 'never emits the raw svg-onload payload' {
        $script:hostileHtml | Should -Not -Match '<svg onload='
    }

    It 'never closes the embedded data script block early' {
        # The generator escapes every '<' inside the JSON payload, so no </script>
        # variant - including '</script >' or a mixed-case one - can appear before the
        # single real closing tag that ends the report body.
        ([regex]::Matches($script:hostileHtml, '(?i)</\s*script')).Count | Should -Be 1
    }

    It 'escapes the payload rather than dropping it, in the embedded JSON' {
        $script:hostileHtml | Should -Match '\\u003C/script>\\u003Cimg src=x onerror=alert\(1\)>'
        $script:hostileHtml | Should -Match '\\u003Csvg onload=alert\(1\)>'
    }

    It 'preserves quotes and backslashes as valid JSON string escapes' {
        $script:hostileHtml | Should -Match 'single '' double \\" backslash \\\\ end'
    }

    It 'escapes hostile text rendered directly into markup outside the script block' {
        $headerMeta = [regex]::Match($script:hostileHtml, '(?s)id="header-meta">(.*?)</div>').Groups[1].Value
        $headerMeta | Should -Not -BeNullOrEmpty
        $headerMeta | Should -Not -Match '<img'
        $headerMeta | Should -Match '&lt;/script&gt;'

        $title = [regex]::Match($script:hostileHtml, '(?s)<title>(.*?)</title>').Groups[1].Value
        $title | Should -Not -Match '<img'
        $title | Should -Match '&lt;'
    }

    It 'escapes hostile Error text the same way as any other field' {
        $script:hostileHtml | Should -Match '"error":"\\u003C/script>\\u003Cimg src=x onerror=alert\(1\)>"'
    }

    It 'keeps the client-side renderer HTML-escaping every field it injects' {
        $script:hostileHtml | Should -Match "replace\(/&/g,'&amp;'\)"
        $script:hostileHtml | Should -Match "replace\(/</g,'&lt;'\)"
        $script:hostileHtml | Should -Match "replace\(/>/g,'&gt;'\)"
        $script:hostileHtml | Should -Match "replace\(/`"/g,'&quot;'\)"
    }
}

Describe 'Get-METReport HTML reference URL handling' {
    BeforeAll {
        $dangerous = @(
            New-METTestResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Javascript URI' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Policy' -Finding 'bad link' `
                -Recommendation 'fix it' -ReferenceUrl 'javascript:alert(1)'
            New-METTestResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'Data URI' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Domain' -Finding 'bad link' `
                -Recommendation 'fix it' -ReferenceUrl 'data:text/html,<script>alert(1)</script>'
        )

        $script:linkHtml = Get-METTestHtml -Results $dangerous -Folder (Join-Path $TestDrive 'links')
    }

    It 'never emits a live href for a javascript: or data: URI' {
        $script:linkHtml | Should -Not -Match '(?i)href\s*=\s*"\s*javascript:'
        $script:linkHtml | Should -Not -Match '(?i)href\s*=\s*''\s*javascript:'
        $script:linkHtml | Should -Not -Match '(?i)href\s*=\s*"\s*data:text/html'
    }

    It 'routes every rendered reference URL through the safeHref allow-list' {
        $script:linkHtml | Should -Match "const u = new URL\(url\)"
        $script:linkHtml | Should -Match "u\.protocol === 'https:' \|\| u\.protocol === 'http:'"
        $script:linkHtml | Should -Match "href=""' \+ safeHref\(check\.referenceUrl\)"
        $script:linkHtml | Should -Match "href=""' \+ safeHref\(c\.referenceUrl\)"
    }
}

Describe 'Get-METReport HTML degenerate result sets' {
    It 'renders an empty result set as a syntactically valid, script-error-free document' {
        $html = Get-METTestHtml -Results @() -Folder (Join-Path $TestDrive 'empty') -TenantName 'empty.contoso.com'

        $html | Should -Match '<html lang="en">'
        # An empty collection must still serialise to an empty JS array. PowerShell's
        # ConvertTo-Json emits nothing at all for an empty collection, which would produce
        # 'const CHECKS = ;' - a SyntaxError that kills the entire report script.
        $html | Should -Match 'const CHECKS = \[\];'
        $html | Should -Not -Match 'const CHECKS = ;'
    }

    It 'produces a numeric score and a real band label for an empty result set' {
        $html = Get-METTestHtml -Results @() -Folder (Join-Path $TestDrive 'empty-score') -TenantName 'empty.contoso.com'

        $html | Should -Match 'const INITIAL_SCORE = \d+;'
        $html | Should -Not -Match 'const INITIAL_SCORE = NaN'
        [regex]::Match($html, 'id="score-band">([^<]*)<').Groups[1].Value |
            Should -BeIn @('Critical', 'Poor', 'Fair', 'Good', 'Excellent')
    }

    It 'serialises a single result as a one-element array, not a bare object' {
        $single = New-METTestResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
            -Severity 'High' -Score 0 -AffectedObject 'contoso.com' -Finding 'DMARC policy is none' `
            -Recommendation 'Publish p=quarantine.'

        $html = Get-METTestHtml -Results @($single) -Folder (Join-Path $TestDrive 'single')

        # The report script calls CHECKS.slice(); a bare object throws
        # "CHECKS.slice is not a function" and no card is ever rendered.
        $html | Should -Match 'const CHECKS = \[\{'
    }

    It 'renders a single Info-only result with a valid score and band' {
        $info = New-METTestResult -CheckId 'MET-EXO016' -Category 'EXO' -Name 'ARC Trusted Sealers' -Result 'Info' `
            -Severity 'Informational' -Score $null -AffectedObject 'Tenant' -Finding 'No trusted sealers configured'

        $html = Get-METTestHtml -Results @($info) -Folder (Join-Path $TestDrive 'info-only')

        $html | Should -Match 'const INITIAL_SCORE = \d+;'
        [regex]::Match($html, 'id="donut-score-text">([^<]*)<').Groups[1].Value | Should -Match '^\d+$'
        $html | Should -Match '(?s)id="sum-info">1<'
        [regex]::Match($html, 'id="score-band">([^<]*)<').Groups[1].Value |
            Should -BeIn @('Critical', 'Poor', 'Fair', 'Good', 'Excellent')
    }
}
