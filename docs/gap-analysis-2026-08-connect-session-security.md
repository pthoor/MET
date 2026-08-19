# Gap Analysis — 2026-08 — Connect-METSession Security Hardening

Source: `docs/deviceauth-change.md`, a hardening proposal drafted by a separate Opus instance in response to the question "should MET even offer device-code auth?" This doc records independent verification of every technical claim against the actual `Connect-METSession.ps1` code (not taken on trust), external research grounding the device-code phishing risk claim against current Microsoft guidance, my own engineering judgment on scope/sequencing, and the resulting implementation plan.

Tracked in `ROADMAP.md` under **v0.10.0 — Planned**.

---

## Verification: every claim checked against the real code

Read `Public/Connect-METSession.ps1` in full before accepting anything from the proposal. All six items check out - this is not a hallucinated review.

| # | Claim | Verified against | Verdict |
|---|---|---|---|
| 1 | All three legs reuse any live connection with no tenant check | `:96-98` (EXO: `Get-ConnectionInformation \| Where State -eq 'Connected'`), `:163-164` (Graph: `Get-MgContext`), `:210-214` (Teams: `Get-CsTenant`) | **Confirmed, and worse than described** - the Teams leg (`:246`) even logs `"already connected to tenant $($teamsConnection.TenantId)"`, meaning the tenant ID is in hand at that exact point and simply never compared against what was requested |
| 2 | No `Disconnect-METSession` exists | `Public/` directory listing | Confirmed |
| 3 | ServicePrincipal only accepts `-CertificateThumbprint`, X509Store-based | `:19-20`, `Get-METCertificateByThumbprint` | Confirmed |
| 4 | Four failure paths recommend `-UseDeviceAuthentication` as the generic retry | `:124`, `:192`, `:250`, `:253` | Confirmed - exactly four |
| 5 | No auth-method/tenant metadata surfaces in the report | `Get-METReport.ps1` header rendering | Confirmed |
| 6 | README overstates when device auth is "required" vs. code's actual auto-`DisableWAM` behavior | README `:20` ("connect with `-UseDeviceAuthentication`" for any Linux/macOS + Teams 7.9+) vs. `Connect-METSession.ps1:228` (`$disableWamRequested = $DisableWAM -or -not $IsWindows` - already automatic off-Windows) | Confirmed real contradiction - device code should only be needed for a genuinely headless host (no browser reachable at all), not "any Linux machine" |

**Cross-customer data leak scenario (item 1), concretely:** an MSSP/consultant runs `Connect-METSession -DelegatedOrganization customerA.onmicrosoft.com`, completes an assessment, then in the *same PowerShell session* runs `Connect-METSession -DelegatedOrganization customerB.onmicrosoft.com` without disconnecting first. All three legs silently reuse the still-live customer-A session. `Invoke-METTriage` produces a report labeled "customerB" (from the parameter the caller passed) containing customer A's actual tenant configuration. This is exactly the scenario `-DelegatedOrganization` exists to support, so it's not a theoretical edge case for this tool's actual intended usage.

---

## Research: is the device-code phishing risk claim accurate?

Dispatched a research agent to ground-truth this independently rather than accept the proposal's framing at face value. Findings, current as of the research pass (checked 2026-08-18):

- **The attack is real, active, and ongoing into 2026**, not a stale 2025 headline. Microsoft's Storm-2372 campaign (publicly detailed Feb 2025) abuses the device-code flow's legitimate UX: an attacker generates a real device code, social-engineers a victim (Teams-meeting-lure emails, rapport-building over WhatsApp/Signal) into visiting `microsoft.com/devicelogin` and entering the *attacker's* code. The victim authenticates normally - MFA and all - but the resulting tokens land in the attacker's session. No credential theft, no MFA bypass exploit needed; it abuses the flow exactly as designed. Follow-on Microsoft reporting continued through April 2026 (AI-enabled device-code campaigns); independent researchers reported a 340+-org campaign via a phishing-as-a-service kit in March 2026.
- **Microsoft's own current guidance is stronger than the proposal's framing**: *"Device code flow is a high-risk authentication method that can be part of a phishing attack... Microsoft recommends blocking device code flow wherever possible."* ([Block authentication flows with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)) Microsoft has been proactively rolling out Microsoft-managed Conditional Access policies since early 2025 that restrict it by default in many tenants - the direction of travel is toward default-blocked-unless-scoped, not just "risky but fine."
- **The headless-fallback carve-out is legitimate, not a weak compromise**: Microsoft's own docs still describe device code flow as the correct mechanism for devices "that lack local input devices" - SSH sessions, containers, CI runners, cloud IDEs (Codespaces, exactly MET's own documented dev environment). There is no newer Microsoft-recommended alternative for genuinely browserless hosts; WAM-based browser handoff requires a broker and GUI session that doesn't exist there. So scoping to "headless fallback only" matches Microsoft's documented exception, not a lesser standard invented for convenience.
- **Comparison to cert-based auth**: Microsoft's preference order for automation/admin tooling is managed identity → certificate-based service principal → interactive/device code as a last resort. Cert auth is phishing-resistant by construction (no human-enterable code, no consent-page social-engineering surface); device code's risk is inherent to being interactive-by-a-human, not fixable by better implementation.

**Conclusion: keep device-code auth, but adopt the proposal's scoping almost exactly, with Microsoft's stronger "block wherever possible / allow only where necessary" wording folded into MET's own guidance and warnings** - not "these are Real Concerns amongst many," but "this is Microsoft's own current default posture, and MET's guidance should say so plainly."

Sources: [Storm-2372 device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) · [Defending against evolving identity attack techniques](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/) · [Block authentication flows with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows) · [Authentication flows condition in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows) · [App-only authentication in Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2)

---

## Implementation plan

Ordered by priority, not by the proposal's numbering - #1 is a real, exploitable-by-accident bug affecting this tool's core supported MSSP scenario, so it leads. The proposal's own stated constraint is preserved throughout: **no change to check logic, output shape, or the `Interactive`/`ServicePrincipal`/`ManagedIdentity` parameter-set names.**

### 1. Tenant-scoped session reuse (highest priority - the actual security bug)

- Compute `$requestedOrg` from `-DelegatedOrganization` (Interactive/default) or `-TenantId` (ServicePrincipal). Skip the check entirely when neither is supplied (home-tenant connect with no stated identity to compare against - matches current behavior, avoids inventing a check with nothing to check against).
- EXO: compare `$requestedOrg` against the existing connection's `Organization` property (`Get-ConnectionInformation`) before reusing; on mismatch, throw naming the actually-connected org and pointing at `Disconnect-METSession`.
- Graph: same pattern against `$mgContext.TenantId`.
- Teams: same pattern against `$teamsConnection.TenantId` - the value is already being read at `:246`, just never compared.
- Also verify auth *mode* matches: an Interactive session must not silently satisfy a ServicePrincipal/ManagedIdentity request (a delegated-admin's interactive session should never be mistaken for the unattended service-principal path a scheduled run expects).
- New Pester cases in `Tests/Unit/Connect-METSession.Tests.ps1`: matching tenant reuses silently, mismatched tenant throws with the real org named, no existing session connects fresh (unchanged path).

### 2. Add `Disconnect-METSession`

- New public function: `Disconnect-ExchangeOnline -Confirm:$false`, `Disconnect-MgGraph`, `Disconnect-MicrosoftTeams`, each in its own try/catch so one failure doesn't block the others (mirrors `Connect-METSession`'s existing per-leg isolation). `-Verbose` reports what was actually torn down.
- Add to `FunctionsToExport` in `MET.psd1`.
- Referenced by name in item 1's mismatch error message, so land these together.
- Document the tenant-switch workflow (`Disconnect-METSession` then reconnect to the new org) in the README, next to the existing MSSP/`-DelegatedOrganization` guidance.

### 3. Certificate-file auth on Linux/Codespaces

- Add `-CertificatePath` + `-CertificatePassword` (`[SecureString]`) to the `ServicePrincipal` parameter set, mutually exclusive with `-CertificateThumbprint` (both remain in the same parameter-set name, per the no-parameter-set-rename constraint - just add optional params, don't split into a new set).
- Load via `X509Certificate2` from file; pass to EXO/Graph/Teams as `-Certificate` (all three already accept a certificate object per their own cmdlet signatures, not just a thumbprint - confirm exact parameter name per leg while implementing, since EXO/Teams may expect `-Certificate` where Graph's `Connect-MgGraph` also supports `-ClientCertificate`).
- Windows keeps the thumbprint/X509Store path unchanged. On non-Windows, if `-CertificateThumbprint` is used and the store lookup fails, the thrown error should name `-CertificatePath` as the actual alternative instead of pointing at device code (this is what makes item 4's tightened guidance land honestly - there needs to be a real non-device-code answer for Linux to point people at).
- This is what turns "prefer cert auth over device code" from aspirational advice into something a Codespaces user can actually do with a secret-stored cert, matching the cert-based-is-phishing-resistant conclusion from the research above.

### 4. Scope the device-code guidance down

- Windows failure paths: recommend `-DisableWAM` and `-UserPrincipalName` only. Never suggest device code as the first-line retry.
- Non-Windows failure paths: recommend `-DisableWAM` first (already auto-applied per item 6, but explicit retry guidance should say so); mention device code only as the documented headless-host fallback (no browser reachable at all), with wording drawn from Microsoft's own current framing - block/avoid wherever possible, use only when genuinely no alternative exists - rather than a soft "frequently blocked" caveat.
- Emit `Write-Warning` at connect time whenever `-UseDeviceAuthentication` is actually used, regardless of platform, so it's never a silent path.
- Update all four sites identified in the verification table (`:124`, `:192`, `:250`, `:253`).

### 5. Record the auth method in the report

- `Connect-METSession` returns an object (or sets module-scoped state `Invoke-METTriage`/`Get-METReport` can read) carrying: auth mode used (Interactive/ServicePrincipal/ManagedIdentity), whether device code was used, tenant identity connected, and which of the three services actually connected.
- Surface it in the `Get-METReport` header (console/JSON/HTML) alongside the existing tenant name / run timestamp line.
- Value: lets a customer's SOC reconcile a `deviceCodeFlow` sign-in event they see in their own logs with a known, expected MET run instead of triaging it as a live incident - directly useful given how the Storm-2372-style detection story plays out for a defender watching their own tenant.
- Lower urgency than 1-4; can land as a follow-up if scope needs trimming, but is cheap once item 1's per-leg identity data is already being read for the tenant-match check (same data, just also returned instead of only compared).

### 6. Fix the README/code contradiction

- `Connect-METSession.ps1:228` already auto-applies `-DisableWAM` off-Windows, resolving the `kernel32.dll` P/Invoke failure on its own.
- Narrow README's current blanket claim ("on Linux/macOS with MicrosoftTeams 7.9.0+, connect with `-UseDeviceAuthentication`") to the genuine case: a host with **no browser reachable at all** (true headless - CI runner, SSH-only box). A Codespace with a forwarded browser tab, or a normal Linux/macOS desktop, should not need it once `-DisableWAM` is automatic.
- Re-verify in an actual Codespace with `-DisableWAM` alone (no `-UseDeviceAuthentication`) before finalizing the doc change, per the source proposal's own instruction - don't just narrow the claim on paper without re-testing it.

---

## Sequencing for implementation

Items 1+2 together first (the fix and its remediation tool belong in one change - the mismatch error message names `Disconnect-METSession`, so it can't ship without it existing). Item 3 next (makes item 4's tightened guidance honest on Linux). Item 4+6 together (both are guidance/wording changes touching the same failure-path call sites and the same README section). Item 5 last (independent, lowest urgency, cheapest to defer if needed).

This is auth-path infrastructure, not a self-contained check - higher blast radius than any single `Checks/*.ps1` file if something regresses (every user's ability to connect runs through this one function). Recommend implementing with the same parallel-subagent-dispatch pattern used for the Teams/quarantine passes, but gated on an explicit go-ahead before starting, given the sensitivity - not a "plan now, code immediately after" turn like the check-level work earlier in this project.
