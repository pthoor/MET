@{
    ModuleVersion        = '0.12.1'
    GUID                 = '52cfd4a5-c6d6-4691-a195-ae0b24ac912b'
    Author               = 'Pierre Thoor'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Pierre Thoor. MIT License.'
    Description          = 'Security Posture Scanner for MDO, EXO and Teams - assesses MDO, EXO/EOP, and Teams protection posture.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    RequiredModules      = @()
    # Dependencies are checked at runtime by Test-METPrerequisites and Connect-METSession.
    # Declaring them in RequiredModules causes a hard import failure when they aren't installed,
    # which prevents Test-METPrerequisites from running and guiding the user.
    # Required: ExchangeOnlineManagement 3.7.2+
    # Optional: Microsoft.Graph.Identity.SignIns 2.x / Microsoft.Graph.Groups 2.x - group expansion
    #           falls back to Exchange Online cmdlets when Graph is missing or fails to connect.
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) - Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FormatsToProcess     = @('MET.Format.ps1xml')
    FunctionsToExport    = @(
        'Connect-METSession'
        'Disconnect-METSession'
        'Invoke-METAssessment'
        'Get-METCheck'
        'Get-METReport'
        'Import-METReport'
        'Test-METPrerequisites'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('Invoke-METTriage')
    PrivateData          = @{
        PSData = @{
            Tags         = @('MDO', 'Microsoft365', 'Defender', 'ExchangeOnline', 'Teams', 'Security', 'Posture', 'Assessment')
            LicenseUri   = 'https://github.com/pthoor/MET/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/pthoor/MET'
            IconUri      = 'https://raw.githubusercontent.com/pthoor/MET/main/assets/favicon-180.png'
            ReleaseNotes = 'v0.12.1 - Connection and DNS grading fixes. Connect-METSession now connects Microsoft Graph 2.41.0+ alongside Exchange Online (an outdated pre-check blocked it), no longer breaks Teams sign-in for B2B guest and delegated admins by passing -AccountId, and reports a Teams session without a Teams admin role instead of reconnecting. On Windows, MET-EXO001 and MET-EXO003 now grade a domain with no DMARC/SPF record as Fail rather than as a failed DNS lookup. MET-Teams014 names a missing or version-mismatched Microsoft.Graph.Identity.SignIns module instead of reporting Graph as not connected. See https://github.com/pthoor/MET/blob/main/CHANGELOG.md'
        }
    }
}
