function Get-METCertificateFromFile {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [System.Security.SecureString] $Password
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Certificate file not found: '$Path'"
    }

    try {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Password)
    }
    catch {
        throw "Failed to load certificate from '$Path': $($_.Exception.Message)"
    }
}
