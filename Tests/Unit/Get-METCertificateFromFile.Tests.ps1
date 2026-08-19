BeforeAll {
    . "$PSScriptRoot/../../Private/Get-METCertificateFromFile.ps1"
}

Describe 'Get-METCertificateFromFile' {
    It 'throws a clear error when the file does not exist' {
        $missing = Join-Path $TestDrive 'does-not-exist.pfx'
        $securePassword = ConvertTo-SecureString 'irrelevant' -AsPlainText -Force
        { Get-METCertificateFromFile -Path $missing -Password $securePassword } | Should -Throw '*not found*'
    }

    It 'wraps a load failure with the file path in the error message' {
        $badFile = Join-Path $TestDrive 'not-a-cert.pfx'
        Set-Content -Path $badFile -Value 'this is not a valid pfx file'
        $securePassword = ConvertTo-SecureString 'wrong' -AsPlainText -Force
        { Get-METCertificateFromFile -Path $badFile -Password $securePassword } | Should -Throw "*$badFile*"
    }
}
