function Get-METPresetSecurityPolicyTier {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Name)

    if ($Name -match '^(Strict|Standard) Preset Security Policy') {
        return $Matches[1]
    }

    return $null
}
