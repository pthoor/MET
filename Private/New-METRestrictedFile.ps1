function New-METRestrictedFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Create restricted file')) { return }

    New-Item -ItemType File -Path $Path -Force | Out-Null

    try {
        # Get-Acl/Set-Acl raise non-terminating errors by default (e.g. "does not possess the
        # 'SeSecurityPrivilege' privilege", seen on some drives/mounts without an elevated
        # process) - without -ErrorAction Stop that error is only written to the error stream
        # and this catch never fires, so the raw ACL error leaks to the console instead of the
        # friendly warning below.
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $adminsSid = [System.Security.Principal.SecurityIdentifier]::new(
                [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
            foreach ($who in @($identity, $adminsSid)) {
                $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                        $who, 'FullControl', 'None', 'None', 'Allow'))
            }
            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        }
        else {
            [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]'UserRead, UserWrite')
        }
    }
    catch {
        Write-Warning "Could not restrict permissions on '$Path': $($_.Exception.Message). The report contains the tenant's full security configuration - secure it manually."
    }
}
