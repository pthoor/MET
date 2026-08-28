# HTML report browser tests

Playwright tests that drive the report produced by `Get-METReport -Format HTML` in a real
Chromium instance. They cover the behaviour that string-level assertions cannot reach:
tab switching, live search, the severity/result filters, the Accept Risk flow and its
`localStorage` persistence, card expansion, and the absence of uncaught script errors.

String-level assertions on the same generator (self-containment, HTML-injection safety,
`safeHref`, banner counts) live in `Tests/Unit/Get-METReport.Html.Tests.ps1` and run as
part of the normal Pester suite - no Node required.

## Fixtures

Nothing generated is committed. `global-setup.js` shells out to PowerShell before the
suite starts and runs `New-METReportFixture.ps1`, which imports the module from this
working tree and writes three reports into `Tests/Html/.tmp/` (git-ignored):

| File | Scenario | Purpose |
|---|---|---|
| `report.html` | `Rich` | Nine checks across MDO/EXO/Teams covering every `Result` value |
| `report-single.html` | `Single` | One check - exercises single-element JSON serialisation |
| `report-empty.html` | `Empty` | No checks - exercises empty-collection serialisation |

Because the fixture is regenerated on every run, the tests always exercise the current
`Public/Get-METReport.ps1` rather than a stale snapshot.

The fixtures are served over `http://127.0.0.1:4173` by `serve.js` (a dependency-free
static server started automatically by Playwright's `webServer`), so `localStorage` has a
stable origin across reloads. Override the port with `MET_HTML_PORT`.

## Prerequisites

- Node.js 18+ and npm
- PowerShell 7.4+ on `PATH` as `pwsh` (override with the `MET_PWSH` environment variable)
- A Chromium build. `playwright.config.js` resolves the executable from
  `PLAYWRIGHT_BROWSERS_PATH` when that variable is set, so a preinstalled browser is used
  as-is; if it is not set, Playwright falls back to its own browser cache.

## Install and run

```bash
cd Tests/Html
npm install                 # installs @playwright/test only

# If this machine has no Chromium yet AND PLAYWRIGHT_BROWSERS_PATH is not preset:
npx playwright install chromium

npm test                    # run the whole suite
npm test -- report.spec.js  # run one spec file
npm test -- -g 'accept risk'   # run one describe block
npm run test:headed         # watch it in a visible browser
npx playwright show-trace test-results/<test>/trace.zip   # inspect a failure
```

On an image that already ships the browser (`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`,
`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`), skip `npx playwright install` entirely - the config
points Playwright at the binary already on disk.

## Spec files

| File | Covers |
|---|---|
| `report.spec.js` | Score banner and summary counters, tab switching and tab counts, live search on CheckId/Name/AffectedObject/Finding, severity + result filters and their AND composition, the "Showing N of M" counter, card and "How to fix" expansion, the full Accept Risk / reload / undo cycle, and zero sub-resource requests |
| `result-set-size.spec.js` | Degenerate result-set sizes: a one-check report and an empty report must both render |

Every test runs through a `page` fixture (`fixtures.js`) that fails the test if any
`pageerror` or `console.error` fires during the run.

## Regression coverage

`result-set-size.spec.js` guards a defect that reached the report generator once already:
the embedded check array was serialised with `ConvertTo-Json`, which collapses a
one-element collection to a bare object (`const CHECKS = {...}`, giving
`CHECKS.slice is not a function`) and an empty collection to nothing at all
(`const CHECKS = ;`, giving `Unexpected token ';'`). Either way the whole report script
died and no cards rendered - reachable from a normal single-check run. The generator now
materialises the collection first and emits a literal `[]` when it is empty, because
`-AsArray` alone does not cover the empty case. Do not weaken these tests.
