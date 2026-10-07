@{
    ModuleVersion        = '0.12.0'
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
            ReleaseNotes = 'v0.12.0 - Pre-1.0 audit remediation, Teams and MDO protection updates. The first release since 0.11.0 (0.11.1 was never published). Fixes checks that reported Pass for settings the service never returned, a stored cross-site scripting vulnerability in the HTML report, reports labelled with the wrong tenant, and posture-score defects. Adds Get-METCheck, Import-METReport, about_MET, MET-Teams016 and MET-MDO015, and a redesigned, keyboard-accessible HTML report. Invoke-METTriage is now Invoke-METAssessment (alias kept); review the Changed section of CHANGELOG.md before upgrading - scoring, risk acceptances and -OutputPath behaviour changed. See https://github.com/pthoor/MET/blob/main/CHANGELOG.md'
        }
    }
}
