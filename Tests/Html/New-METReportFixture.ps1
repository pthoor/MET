<#
.SYNOPSIS
    Generates an HTML report fixture for the Playwright browser tests.

.DESCRIPTION
    Invoked by the Playwright global setup so every browser run exercises the CURRENT
    Get-METReport generator instead of a stale checked-in HTML file. Nothing here is
    committed - the generated file lives under Tests/Html/.tmp/ which is git-ignored.

.PARAMETER Scenario
    Rich   - a nine-check result set spanning MDO/EXO/Teams and every Result value.
    Single - a single check (exercises the one-element JSON serialisation path).
    Empty  - no checks at all.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputFile,

    [Parameter()]
    [ValidateSet('Rich', 'Single', 'Empty', 'Hostile')]
    [string] $Scenario = 'Rich'
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force

function New-FixtureResult {
    param(
        [string] $CheckId, [string] $Category, [string] $Name, [string] $Result,
        [string] $Severity, [object] $Score, [string] $AffectedObject, [string] $Finding,
        [string] $Recommendation = '', [string] $ReferenceUrl = '', [string] $ErrorText = $null
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
        Timestamp      = [datetime]::new(2026, 6, 1, 14, 32, 0, [System.DateTimeKind]::Utc)
        Error          = $ErrorText
        Metadata       = $null
    }
}

$fixtures = switch ($Scenario) {
    'Empty' { @() }

    # Every field a check can populate, carrying a payload crafted for the sink it
    # reaches: an https URL that closes the href attribute, and enum values that close
    # a class attribute. Both survive scheme validation and .toLowerCase() respectively.
    'Hostile' {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Href breakout <img src=n1 onerror="window.__xssName=1">' `
                -Result 'Fail' -Severity 'High' -Score 0 `
                -AffectedObject 'Policy "><img src=n2 onerror="window.__xssAffected=1">' `
                -Finding 'Finding "><img src=n3 onerror="window.__xssFinding=1">' `
                -Recommendation 'Recommendation "><img src=n4 onerror="window.__xssRec=1">' `
                -ReferenceUrl 'https://x.example/"><img src=n5 onerror="window.__xssHref=1">'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO"><img src=n6 onerror="window.__xssCat=1">' `
                -Name 'Class breakout' -Result 'Warning' -Severity 'Medium"><img src=n7 onerror="window.__xssSev=1">' `
                -Score 50 -AffectedObject 'Domain' -Finding 'Class attribute payload' `
                -Recommendation 'none' -ReferenceUrl 'https://aka.ms/dmarc'

            New-FixtureResult -CheckId 'MET-Teams003' -Category 'Teams' -Name 'Errored with payload' `
                -Result 'NotApplicable' -Severity 'Low' -Score $null -AffectedObject 'Teams' `
                -Finding 'Check could not run' `
                -ErrorText 'Error "><img src=n8 onerror="window.__xssError=1">'
        )
    }

    'Single' {
        @(
            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'DMARC policy is set to none' `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'
        )
    }

    default {
        @(
            New-FixtureResult -CheckId 'MET-MDO001' -Category 'MDO' -Name 'Safe Links Policy' -Result 'Fail' `
                -Severity 'High' -Score 0 -AffectedObject 'Default Safe Links Policy' `
                -Finding 'Safe Links is disabled for email' `
                -Recommendation "Open the Defender portal.`nEdit the Safe Links policy.`nEnable Safe Links for email." `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-links-about'

            New-FixtureResult -CheckId 'MET-MDO002' -Category 'MDO' -Name 'Safe Attachments Policy' -Result 'Warning' `
                -Severity 'Medium' -Score 50 -AffectedObject 'Marketing Attachments Policy' `
                -Finding 'Action is set to Monitor rather than Block' `
                -Recommendation 'Set the Safe Attachments action to Block.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/safe-attachments-about'

            New-FixtureResult -CheckId 'MET-MDO009' -Category 'MDO' -Name 'Zero-Hour Auto Purge' -Result 'Pass' `
                -Severity 'High' -Score 100 -AffectedObject 'All anti-spam policies' `
                -Finding 'Auto purge of delivered mail is enabled everywhere' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge'

            New-FixtureResult -CheckId 'MET-EXO001' -Category 'EXO' -Name 'DMARC Record' -Result 'Fail' `
                -Severity 'Critical' -Score 0 -AffectedObject 'contoso.com' `
                -Finding 'DMARC policy is set to none' `
                -Recommendation 'Publish a DMARC record with p=quarantine.' `
                -ReferenceUrl 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'

            New-FixtureResult -CheckId 'MET-EXO007' -Category 'EXO' -Name 'Transport Rule Audit' -Result 'Info' `
                -Severity 'Informational' -Score $null -AffectedObject 'Mail flow rules' `
                -Finding 'Two rules bypass spam filtering'

            New-FixtureResult -CheckId 'MET-EXO012' -Category 'EXO' -Name 'Mailbox Forwarding' -Result 'Pass' `
                -Severity 'Low' -Score 100 -AffectedObject 'finance@contoso.com' `
                -Finding 'No silent external forwarding configured'

            New-FixtureResult -CheckId 'MET-Teams003' -Category 'Teams' -Name 'Meeting Protection' -Result 'Warning' `
                -Severity 'High' -Score 50 -AffectedObject 'Global meeting policy' `
                -Finding 'Anonymous participants bypass the lobby' `
                -Recommendation 'Restrict lobby bypass to people in the organization.' `
                -ReferenceUrl 'https://learn.microsoft.com/microsoftteams/settings-policies-reference'

            New-FixtureResult -CheckId 'MET-Teams006' -Category 'Teams' -Name 'External Access Federation' -Result 'Pass' `
                -Severity 'Medium' -Score 100 -AffectedObject 'Tenant federation configuration' `
                -Finding 'Federation is limited to an explicit allow list'

            New-FixtureResult -CheckId 'MET-Teams014' -Category 'Teams' -Name 'Cross-Tenant Access' -Result 'NotApplicable' `
                -Severity 'Medium' -Score $null -AffectedObject 'Cross-tenant access policy' `
                -Finding 'Microsoft Graph is not connected' `
                -ErrorText 'Authentication needed. Please call Connect-MgGraph.'
        )
    }
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ('met-html-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    $fixtures | Get-METReport -Format HTML -OutputPath $staging -TenantName 'contoso.onmicrosoft.com' | Out-Null

    $generated = Get-ChildItem -Path $staging -Recurse -Filter '*.html' | Select-Object -First 1
    if (-not $generated) {
        throw "Get-METReport did not produce an HTML file under $staging"
    }

    $destinationFolder = Split-Path -Path $OutputFile -Parent
    if ($destinationFolder -and -not (Test-Path $destinationFolder)) {
        New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
    }

    Copy-Item -Path $generated.FullName -Destination $OutputFile -Force
    Write-Output $OutputFile
}
finally {
    Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
}
