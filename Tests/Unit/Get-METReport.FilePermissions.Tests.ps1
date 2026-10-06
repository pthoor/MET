BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    Import-Module (Join-Path $root 'MET.psd1') -Force

    function Get-AcceptedDomain { [CmdletBinding()] param() }

    $script:sample = [PSCustomObject]@{
        CheckId = 'MET-EXO001'; Category = 'EXO'; Name = 'DMARC Record'
        Result = 'Pass'; Severity = 'High'; Score = 100
        AffectedObject = 'contoso.com'; Finding = 'ok'; Recommendation = ''
        ReferenceUrl = ''; Timestamp = [datetime]::UtcNow; Error = $null; Metadata = $null
    }
}

Describe 'Get-METReport writes reports owner-only' {
    BeforeEach {
        $script:outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("met-perm-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:outDir -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Creates the JSON report with no group or world access' -Skip:$IsWindows {
        $script:sample | Get-METReport -Format JSON -OutputPath $script:outDir -TenantName 'contoso.com' | Out-Null
        $file = Get-ChildItem -Path $script:outDir -Recurse -Filter '*.json' | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty
        $mode = (& stat -c '%a' $file.FullName)
        $mode | Should -Be '600'
    }

    It 'Creates the HTML report with no group or world access' -Skip:$IsWindows {
        $script:sample | Get-METReport -Format HTML -OutputPath $script:outDir -TenantName 'contoso.com' -NoLaunch | Out-Null
        $file = Get-ChildItem -Path $script:outDir -Recurse -Filter '*.html' | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty
        (& stat -c '%a' $file.FullName) | Should -Be '600'
    }

    It 'Grants the JSON report to no identity beyond the owner and administrators' -Skip:(-not $IsWindows) {
        $script:sample | Get-METReport -Format JSON -OutputPath $script:outDir -TenantName 'contoso.com' | Out-Null
        $file = Get-ChildItem -Path $script:outDir -Recurse -Filter '*.json' | Select-Object -First 1
        $acl = Get-Acl -LiteralPath $file.FullName
        $unexpected = $acl.Access | Where-Object {
            $_.IdentityReference.Value -notmatch '(?i)(BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM)$' -and
            $_.IdentityReference.Value -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        $unexpected | Should -BeNullOrEmpty
    }

    # Set-Acl raises a non-terminating error by default (seen live as "does not possess the
    # 'SeSecurityPrivilege' privilege" on some drives without an elevated process) - without
    # -ErrorAction Stop on the Set-Acl call inside New-METRestrictedFile, its catch block never
    # fires and the raw ACL error leaks to the console instead of the friendly warning.
    It 'Warns instead of leaking a raw ACL error when Set-Acl fails non-terminating' -Skip:(-not $IsWindows) {
        Mock -ModuleName MET Set-Acl {
            Write-Error "The process does not possess the 'SeSecurityPrivilege' privilege which is required for this operation."
        }

        # Called directly, not inside a `{ } | Should -Not -Throw` scriptblock: that scriptblock
        # runs in a child scope, so -WarningVariable would populate a $warnings the assertion
        # below never sees. An unexpected throw still fails this It.
        $warnings = $null
        $script:sample | Get-METReport -Format JSON -OutputPath $script:outDir -TenantName 'contoso.com' -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        $file = Get-ChildItem -Path $script:outDir -Recurse -Filter '*.json' | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty
        ($warnings -join "`n") | Should -Match "Could not restrict permissions"
    }
}
