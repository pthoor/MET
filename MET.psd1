@{
    ModuleVersion        = '0.10.0'
    GUID                 = '52cfd4a5-c6d6-4691-a195-ae0b24ac912b'
    Author               = 'Pierre Thoor'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Pierre Thoor. MIT License.'
    Description          = 'Security Posture Scanner for MDO, EXO and Teams - assesses MDO, EXO/EOP, and Teams protection posture.'
    PowerShellVersion    = '7.4'
    RequiredModules      = @()
    # Dependencies are checked at runtime by Test-METPrerequisites and Connect-METSession.
    # Declaring them in RequiredModules causes a hard import failure when they aren't installed,
    # which prevents Test-METPrerequisites from running and guiding the user.
    # Required: ExchangeOnlineManagement 3.9+
    # Optional: Microsoft.Graph.Identity.SignIns 2.x / Microsoft.Graph.Groups 2.x - group expansion
    #           falls back to Exchange Online cmdlets when Graph is missing or fails to connect.
    # Optional: MicrosoftTeams 6.x+ (latest: 7.x) - Teams checks skip gracefully if not present.
    RootModule           = 'MET.psm1'
    FunctionsToExport    = @(
        'Connect-METSession'
        'Disconnect-METSession'
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
            ReleaseNotes = 'v0.10.0 - Connect-METSession security hardening. Fixes a confirmed cross-customer data leak in session reuse: Connect-METSession previously reused any live Exchange Online/Graph/Teams connection without verifying it belonged to the requested tenant, so running MET against two different -DelegatedOrganization customers in the same session without disconnecting in between could return a report labeled for one customer containing another customer''s actual configuration. Adds certificate-file authentication (-CertificatePath/-CertificatePassword) for non-Windows platforms, since -CertificateThumbprint is Windows-only. Scopes device-code authentication down to a documented headless-only fallback, with a warning on every use, per Microsoft''s current guidance to block it wherever possible. Adds Disconnect-METSession for clean session teardown across all three connection legs. Adds MET-MDO014 (Group Reference Audit) and expands MET-EXO014 (Advanced Delivery Policy) coverage. v0.9.0 - Quarantine policy accuracy pass. Fixes two confirmed false-positive bugs: MET-EXO009 previously flagged Microsoft''s own Standard/Strict preset security policies as Fail/Warning for impersonation, spoof, and phish quarantine verdicts, even though Microsoft''s own Strict preset uses full-access quarantine policies for those verdicts by design; corrected to only evaluate the two verdicts (Malware, High-Confidence Phish) that actually have a restrictive floor. MET-EXO004 previously flagged the built-in AdminOnlyAccessPolicy''s by-design "no access" configuration as a misconfiguration on every tenant; narrowed to evaluate only genuinely custom quarantine policies. Adds preset-aware retention handling to MET-EXO008 and a new informational check, MET-EXO017 (Quarantine Notification Cadence). v0.8.0 - Teams attack-surface hardening. Adds five new Teams checks: MET-Teams009 (Trial Tenant Federation Exposure), MET-Teams010 (Per-User External Access Policy Drift), MET-Teams011 (SecOps Blocklist Authority & Blocked Entities), MET-Teams012 (Call Reporting / vishing surface), and MET-Teams014 (Cross-Tenant Guest & External Collaboration, the first check with a direct Microsoft Graph dependency). Also fixes a real gap in MET-Teams003, which previously only evaluated the Global meeting policy and missed custom meeting policies entirely, and adds rule-level exception visibility to MET-Teams001 and MET-Teams004.'
        }
    }
}
