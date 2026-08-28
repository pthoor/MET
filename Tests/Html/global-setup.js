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
];

function pwshExecutable() {
  return process.env.MET_PWSH || 'pwsh';
}

module.exports = async () => {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
  fs.mkdirSync(TMP_DIR, { recursive: true });

  for (const { scenario, file } of SCENARIOS) {
    const destination = path.join(TMP_DIR, file);
    execFileSync(
      pwshExecutable(),
      [
        '-NoProfile',
        '-File',
        path.join(__dirname, 'New-METReportFixture.ps1'),
        '-OutputFile',
        destination,
        '-Scenario',
        scenario,
      ],
      { stdio: 'inherit' }
    );
    if (!fs.existsSync(destination)) {
      throw new Error(`Fixture generation failed for scenario ${scenario} (${destination} not created)`);
    }
  }
};
