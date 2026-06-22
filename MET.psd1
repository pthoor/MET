@{
    ModuleVersion        = '0.4.0'
    GUID                 = '52cfd4a5-c6d6-4691-a195-ae0b24ac912b'
    Author               = 'Pierre Thoor'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Pierre Thoor. MIT License.'
    Description          = 'Security Posture Scanner for MDO, EXO and Teams — assesses MDO, EXO/EOP, and Teams protection posture.'
    PowerShellVersion    = '7.4'
    RequiredModules      = @()
    # Dependencies are checked at runtime by Test-METPrerequisites and Connect-METSession.
    # Declaring them in RequiredModules causes a hard import failure when they aren't installed,
    # which prevents Test-METPrerequisites from running and guiding the user.
    # Required: ExchangeOnlineManagement 3.9+, Microsoft.Graph.Identity.SignIns 2.x, Microsoft.Graph.Groups 2.x
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) — Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FunctionsToExport    = @(
        'Connect-METSession'
        'Invoke-METTriage'
        'Get-METReport'
        'Test-METPrerequisites'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('MDO', 'Microsoft365', 'Defender', 'ExchangeOnline', 'Teams', 'Security', 'Posture', 'Assessment')
            LicenseUri   = 'https://github.com/pthoor/MET/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/pthoor/MET'
            ReleaseNotes = 'v0.4.0 — Complete check set: MDO001-012, EXO001-009, Teams001-005. Promotions folder baseline docs. MDO010 rewritten (Get-EmailTenantSettings + Get-User -IsVIP, no Graph dependency). MDO011 returns Info with portal link. Get-METReport -Format All now requires -OutputPath (terminating error if omitted). Cross-platform DNS (Resolve-METDnsName). PSScriptAnalyzer CI gate. Invoke-METTriage -PassThru and -ListChecks. Code coverage in CI.'
        }
    }
}
