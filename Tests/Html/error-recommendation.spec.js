// G-2: a check that failed to run (populated Error) can also carry a Recommendation - the
// guidance an operator needs most when a check errors on a permission gap. Before the fix,
// `(errorHtml || buildRecommendation(check.recommendation))` meant the recommendation was
// discarded outright whenever an error was present, and the disclosure was mislabelled
// "How to fix" for a tool failure rather than a posture finding.
const { test, expect } = require('./fixtures');

test.describe('an errored check with a recommendation renders both', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-error-with-recommendation.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('shows the error banner and the recommendation together, under a Details heading', async ({ page }) => {
    const card = page.locator('.card[data-check-id="MET-EXO011"]');
    await card.locator('.card-header').click();

    const fix = card.locator('.card-fix');
    await expect(fix).toContainText('Details');
    await expect(fix).not.toContainText('How to fix');

    const fixContent = card.locator('.fix-content');
    await expect(fixContent.locator('.card-error')).toContainText("Get-InboundConnector' is not recognized");
    await expect(fixContent).toContainText('Re-run with a Security Reader role.');
  });
});
