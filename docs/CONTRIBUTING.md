# Contributing to MET

Thank you for contributing to MET. This guide explains how to add a new check, run the test suite, and submit a pull request.

---

## Adding a new check

### 1. Choose an ID

Check IDs follow the pattern `MET-<CATEGORY><NNN>`:

- `MET-MDO001` - first MDO check
- `MET-EXO007` - seventh EXO check
- `MET-Teams003` - third Teams check

Look at the existing check inventory in `README.md` and pick the next available ID in the appropriate category.

### 2. Create the check file

Create `Checks/<Category>/MET-<ID>-<ShortName>.ps1`.

Each check script is a standalone `.ps1` file (not a function). It is dot-sourced and executed by `Invoke-METAssessment`. The script:

- Has access to all `Private/` helpers (`New-METCheckResult`, `Get-METCheckWeight`)
- Must **not** throw - wrap all EXO/Graph/Teams calls in `try/catch`
- Surfaces errors via the `Error` field of the result object, not as terminating exceptions
- Must output one or more `PSCustomObject` results via `New-METCheckResult`

Minimal check template:

```powershell
try {
    $data = Get-SomeEXOCmdlet -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-XXX999' -Category MDO -Name 'My Check' `
        -Result Fail -Severity High -AffectedObject 'Object Name' `
        -Finding 'Unable to retrieve data' `
        -Recommendation 'Ensure the account has Security Reader permissions.' `
        -ReferenceUrl 'https://aka.ms/...' -ErrorMessage $_.ToString()
    return
}

# ... assessment logic ...

New-METCheckResult -CheckId 'MET-XXX999' -Category MDO -Name 'My Check' `
    -Result Pass -Severity High -AffectedObject $data.Name `
    -Finding 'Setting is correctly configured' `
    -ReferenceUrl 'https://aka.ms/...'
```

### 3. Follow the result schema

| Field | Rules |
|---|---|
| `CheckId` | Must match the filename prefix exactly |
| `Category` | `MDO`, `EXO`, or `Teams` |
| `Result` | `Pass`, `Fail`, `Warning`, `Info`, `NotApplicable` |
| `Severity` | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `Finding` | Plain English, present tense, factual - no "you should" |
| `Recommendation` | Actionable steps, imperative mood |
| `ReferenceUrl` | `https://aka.ms/...` where possible |

#### An absent property never yields `Pass`

A property that the service did not return tells you nothing about the tenant's configuration. Never resolve a missing or `$null` property into a `Pass` - a green result nobody investigates is the most damaging outcome a posture scanner can produce.

- Absent on some objects but present on others -> `Warning`, naming the objects whose property was absent
- Absent on every object -> `NotApplicable`, with `-ErrorMessage` recording that the property was not returned - typically a module or service version that does not expose it
- A check may escalate to `Fail` where absence has a specific, documented meaning for that control. `MET-EXO023` does this and explains why in its own `Finding`

Test the property against the object as well as its value, so a property that is missing entirely is caught alongside one that is present but `$null`:

```powershell
$withProperty    = @($items | Where-Object { $null -ne $_.PSObject.Properties['Setting'] -and $null -ne $_.Setting })
$withoutProperty = @($items | Where-Object { $null -eq $_.PSObject.Properties['Setting'] -or  $null -eq $_.Setting })
```

#### Rule 2 - a fail-closed verdict must not describe a value it did not observe

Reaching the right `Result` on an absent property is not enough - the `Finding` text must not assert a value that was never returned. Don't write "Safe Attachments for Teams is disabled (`EnableATPForSPOTeamsODB = $false`)" when the property was absent; say instead that whether it is enabled was not established.

On any branch that resolves to `NotApplicable` or `Warning` because of an absent property, the `Finding` must also say *why* an unconfirmed state is not graded as a pass, not just stop at "was not established" - `Get-METReport`'s HTML card collapses `Recommendation` behind "How to fix," so a reader scanning cards sees only the `Finding`. This scoping is deliberate: the "reported as unassessed rather than a pass" clause belongs on `NotApplicable`/`Warning` branches, not on branches that still resolve to `Fail` - on a `Fail` branch nothing is being reported as unassessed, so the sentence would be false there.

`MET-MDO002` (`Checks/MDO/MET-MDO002-SafeAttachments.ps1`) is the reference implementation for this shape.

### 4. Write Pester tests

Add tests to the appropriate file in `Tests/Unit/`:

- `Checks.MDO.Tests.ps1` - MDO checks
- `Checks.EXO.Tests.ps1` - EXO checks
- `Checks.Teams.Tests.ps1` - Teams checks

Tests must use `Mock` to simulate EXO/Graph/Teams cmdlets - never connect to a real tenant in unit tests. Define stubs in `BeforeAll` if the cmdlet is not already stubbed.

Minimum test cases per check:

1. All settings correct → `Pass`
2. Primary failure case → `Fail` (assert `Finding` content)
3. API failure (cmdlet throws) → `Fail` with `Error` populated
4. The assessed property absent → never `Pass` (see above)

### 5. Write a check doc

Create `docs/checks/MET-<ID>-<ShortName>.md` using the structure:

```markdown
# MET-XXXNNN - Name

**Category:** MDO/EXO/Teams | **Severity:** High

## What it checks
## Why it matters
## Pass / Fail / Warning  (table)
## Recommendation
## Reference
```

### 6. Update the README

Add the new check to the check inventory table in `README.md`.

---

## Running the tests

Requires **Pester 5.x**:

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser

# Unit tests (no tenant connection required)
$config = New-PesterConfiguration
$config.Run.Path = './Tests/Unit'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
```

---

## Code conventions

- **Approved verbs only** - `Invoke-`, `Get-`, `Test-`, `New-`, `Resolve-`
- **No inline comments** unless explaining a non-obvious workaround
- **No `Write-Host`** - use `Write-Verbose` for progress, `Write-Warning` for non-fatal issues
- **No positional parameters** on public functions
- **Error handling** - `try/catch` on all remote calls; surface in `Error` field, never throw
- **No plain-text secrets** - all auth through `Connect-METSession`
- **An absent property never yields `Pass`** - `Warning` when it is absent on only some objects, `NotApplicable` with `-ErrorMessage` when absent on all
- **Rule 2: a fail-closed verdict must not describe a value it did not observe** - on a `NotApplicable`/`Warning` branch, say what was not established, never name a value nothing returned; also say why that is not graded as a pass. Not on `Fail` branches - see above
- **No external HTTP calls inside check scripts** - DNS lookups via `Resolve-DnsName` are allowed for email auth checks

---

## Pull request checklist

- [ ] New check file created with correct naming
- [ ] `New-METCheckResult` used for all output
- [ ] `try/catch` wraps all remote calls
- [ ] Pester tests added (Pass, Fail, API-error, and absent-property scenarios)
- [ ] Check doc added to `docs/checks/`
- [ ] README check inventory updated
- [ ] All unit tests pass locally (`Invoke-Pester -Configuration $config`)

---

## Questions?

Open an issue at [github.com/pthoor/MET](https://github.com/pthoor/MET).
