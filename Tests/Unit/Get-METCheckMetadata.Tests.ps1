# Get-METCheck reads check metadata off the AST rather than by running the check, because
# it is the cmdlet a user runs before connecting - possibly on a machine with no
# ExchangeOnlineManagement installed at all. This file pins that the parse handles every
# literal shape a header can legally take, and that a header-less file degrades rather
# than throws (the 51 headers land after this helper does).
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'Get-METCheckMetadata.ps1')

    $script:Fixtures = Join-Path $TestDrive 'Checks' 'MDO'
    New-Item -ItemType Directory -Path $script:Fixtures -Force | Out-Null

    function New-METFixtureCheck {
        param([string] $FileName, [string] $Body)
        $path = Join-Path $script:Fixtures $FileName
        Set-Content -LiteralPath $path -Value $Body -Encoding utf8
        $path
    }
}

Describe 'Get-METCheckMetadata' {

    It 'Reads all four fields from a well-formed header' {
        $path = New-METFixtureCheck -FileName 'MET-MDO001-SafeLinks.ps1' -Body @'
param()

$METCheckInfo = @{
    Name           = 'Safe Links Effective Coverage'
    Severity       = 'High'
    Description    = 'Resolves the precedence-winning Safe Links policy per mailbox.'
    RequiresModule = @('ExchangeOnlineManagement')
}

Write-Verbose 'body'
'@
        $info = Get-METCheckMetadata -Path $path
        $info.Name           | Should -Be 'Safe Links Effective Coverage'
        $info.Severity       | Should -Be 'High'
        $info.Description    | Should -Be 'Resolves the precedence-winning Safe Links policy per mailbox.'
        $info.RequiresModule | Should -Be @('ExchangeOnlineManagement')
    }

    It 'Derives CheckId and Category from the path, not the header' {
        # Duplicating CheckId and Category inside the header would create a second place
        # for them to drift from the filename, which is the thing the report keys on.
        $path = New-METFixtureCheck -FileName 'MET-MDO009-ZAP.ps1' -Body @'
param()

$METCheckInfo = @{
    Name           = 'ZAP'
    Severity       = 'High'
    Description    = 'Zero-hour auto purge.'
    RequiresModule = @('ExchangeOnlineManagement')
}
'@
        $info = Get-METCheckMetadata -Path $path
        $info.CheckId  | Should -Be 'MET-MDO009'
        $info.Category | Should -Be 'MDO'
        $info.Script   | Should -Be 'MET-MDO009-ZAP.ps1'
    }

    It 'Reads a multi-module RequiresModule regardless of array literal shape' {
        $path = New-METFixtureCheck -FileName 'MET-MDO002-Multi.ps1' -Body @'
param()

$METCheckInfo = @{
    Name           = 'Multi'
    Severity       = 'Medium'
    Description    = 'Two modules.'
    RequiresModule = 'ExchangeOnlineManagement', 'Microsoft.Graph'
}
'@
        $info = Get-METCheckMetadata -Path $path
        @($info.RequiresModule) | Should -Be @('ExchangeOnlineManagement', 'Microsoft.Graph')
    }

    It 'Returns an object with null metadata when the file carries no header' {
        # Tasks run in order: this helper exists before any of the 51 headers do. If a
        # missing header threw, Get-METCheck could not list a single check until all 51
        # landed, and the header-adding task would have no way to see its own progress.
        $path = New-METFixtureCheck -FileName 'MET-MDO003-NoHeader.ps1' -Body 'Write-Verbose "nothing here"'
        $info = Get-METCheckMetadata -Path $path
        $info.CheckId          | Should -Be 'MET-MDO003'
        $info.Name             | Should -BeNullOrEmpty
        $info.Severity         | Should -BeNullOrEmpty
        @($info.RequiresModule) | Should -BeNullOrEmpty
    }

    It 'Never executes the check body' {
        # The load-bearing claim of the whole design. A header read that ran the file would
        # call Exchange Online cmdlets on a machine that may not even have the module.
        # $env:TEMP is frequently unset on Linux, so the fixture and the assertion are built
        # from one resolved path rather than each guessing at the temp directory.
        $sentinel = Join-Path ([System.IO.Path]::GetTempPath()) 'met-should-not-exist.txt'
        if (Test-Path -LiteralPath $sentinel) { Remove-Item -LiteralPath $sentinel -Force }

        $path = New-METFixtureCheck -FileName 'MET-MDO004-Side.ps1' -Body @"
param()

`$METCheckInfo = @{
    Name           = 'Side'
    Severity       = 'Low'
    Description    = 'Has a side effect below.'
    RequiresModule = @('ExchangeOnlineManagement')
}

New-Item -ItemType File -Path '$sentinel' -Force
"@
        $null = Get-METCheckMetadata -Path $path
        Test-Path -LiteralPath $sentinel | Should -BeFalse
    }

    It 'Throws a path-naming error on a file that does not parse' {
        $path = New-METFixtureCheck -FileName 'MET-MDO005-Broken.ps1' -Body 'function {'
        { Get-METCheckMetadata -Path $path } | Should -Throw '*MET-MDO005-Broken.ps1*'
    }

    It 'Stamps the object so the format file can select a table view' {
        $path = New-METFixtureCheck -FileName 'MET-MDO006-Typed.ps1' -Body @'
param()

$METCheckInfo = @{
    Name           = 'Typed'
    Severity       = 'Low'
    Description    = 'Typed.'
    RequiresModule = @('ExchangeOnlineManagement')
}
'@
        (Get-METCheckMetadata -Path $path).PSObject.TypeNames | Should -Contain 'MET.CheckInfo'
    }
}
