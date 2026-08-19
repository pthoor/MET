function Test-METIsPresetSecurityPolicyName {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Name)

    return [bool](Get-METPresetSecurityPolicyTier -Name $Name)
}
