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

    # EphemeralKeySet keeps the private key in memory instead of writing it into the
    # user's on-disk key container. With the default flags the key file persists until
    # the certificate object is disposed, so an abnormal process exit leaks private key
    # material to disk. macOS does not support ephemeral keys, so it keeps the default
    # behaviour - callers there must dispose the returned object.
    $flags = if ($IsMacOS) {
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    }
    else {
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    }

    try {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Password, $flags)
    }
    catch {
        throw "Failed to load certificate from '$Path': $($_.Exception.Message)"
    }
}
