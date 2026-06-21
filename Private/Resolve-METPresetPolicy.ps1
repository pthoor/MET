function Resolve-METPresetPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Standard','Strict')] [string] $Tier,
        # EOP covers anti-spam and anti-malware rules; ATP covers Safe Links, Safe Attachments, and Anti-Phish.
        # The two preset rules can have different recipient conditions even for the same tier.
        [ValidateSet('EOP','ATP')] [string] $Stack = 'EOP'
    )

    $policyName = if ($Tier -eq 'Standard') { 'Standard Preset Security Policy' } else { 'Strict Preset Security Policy' }

    try {
        $rule = if ($Stack -eq 'ATP') {
            Get-ATPProtectionPolicyRule -Identity $policyName -ErrorAction Stop
        } else {
            Get-EOPProtectionPolicyRule -Identity $policyName -ErrorAction Stop
        }
        [PSCustomObject]@{
            Tier       = $Tier
            Stack      = $Stack
            PolicyName = $policyName
            Enabled    = ($rule.State -eq 'Enabled')
            Rule       = $rule
        }
    }
    catch {
        Write-Verbose "Preset policy '$policyName' ($Stack) not found or inaccessible: $_"
        [PSCustomObject]@{
            Tier       = $Tier
            Stack      = $Stack
            PolicyName = $policyName
            Enabled    = $false
            Rule       = $null
        }
    }
}
