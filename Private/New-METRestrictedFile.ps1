function New-METRestrictedFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Create restricted file')) { return }

    New-Item -ItemType File -Path $Path -Force | Out-Null

    try {
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            foreach ($who in @($identity, 'BUILTIN\Administrators')) {
                $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                        $who, 'FullControl', 'None', 'None', 'Allow'))
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        else {
            try {
                $file = Get-Item -LiteralPath $Path
                $file.UnixMode = 'rw-------'
            }
            catch {
                & /bin/chmod 600 $Path
                if ($LASTEXITCODE -ne 0) {
                    throw "chmod exited with code $LASTEXITCODE"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not restrict permissions on '$Path': $($_.Exception.Message). The report contains the tenant's full security configuration - secure it manually."
    }
}
