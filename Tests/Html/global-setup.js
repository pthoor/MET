// Generates every HTML fixture from the CURRENT Get-METReport before the suite runs.
// No generated .html is ever committed - see .gitignore in this folder.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const TMP_DIR = path.join(__dirname, '.tmp');

const SCENARIOS = [
  { scenario: 'Rich', file: 'report.html' },
  { scenario: 'Single', file: 'report-single.html' },
  { scenario: 'Empty', file: 'report-empty.html' },
  { scenario: 'Hostile', file: 'report-hostile.html' },
  { scenario: 'RepeatedCheckId', file: 'report-repeated-checkid.html' },
  { scenario: 'SameAffectedObject', file: 'report-same-affected-object.html' },
  { scenario: 'ErrorBuckets', file: 'report-error-buckets.html' },
  { scenario: 'InfoOnly', file: 'report-info-only.html' },
  { scenario: 'FailPlusInfo', file: 'report-fail-plus-info.html' },
];

function pwshExecutable() {
  return process.env.MET_PWSH || 'pwsh';
}

// serve.js serves out of this same directory, and playwright.config.js sets
// reuseExistingServer outside CI - so a server left behind by an interrupted or concurrent
// run keeps answering requests while this setup regenerates. Deleting the directory up
// front (fs.rmSync on TMP_DIR) made every fixture briefly nonexistent, which is how a
// request landed on a 404 and the test that made it sat out its 30s timeout. Nothing is
// removed before generation now: each fixture is written under a staging name and moved
// into place with rename(), which is atomic within a filesystem, so a concurrent reader
// sees either the previous complete file or the new one and never a gap.
module.exports = async () => {
  fs.mkdirSync(TMP_DIR, { recursive: true });

  for (const { scenario, file } of SCENARIOS) {
    const destination = path.join(TMP_DIR, file);
    const staging = `${destination}.${process.pid}.staging`;

    execFileSync(
      pwshExecutable(),
      [
        '-NoProfile',
        '-File',
        path.join(__dirname, 'New-METReportFixture.ps1'),
        '-OutputFile',
        staging,
        '-Scenario',
        scenario,
      ],
      { stdio: 'inherit' }
    );
    if (!fs.existsSync(staging)) {
      throw new Error(`Fixture generation failed for scenario ${scenario} (${staging} not created)`);
    }
    fs.renameSync(staging, destination);
  }

  // Prune only once every current fixture is in place, so the pruning pass can never be
  // the thing that removes a file a reader is about to ask for.
  // Staging files are left alone: a second run's in-flight staging file must survive this
  // pass, or one run deletes the fixture the other is about to move into place.
  const expected = new Set(SCENARIOS.map((entry) => entry.file));
  for (const entry of fs.readdirSync(TMP_DIR)) {
    if (/^report.*\.html$/.test(entry) && !expected.has(entry)) {
      fs.rmSync(path.join(TMP_DIR, entry), { force: true });
    }
  }
};
