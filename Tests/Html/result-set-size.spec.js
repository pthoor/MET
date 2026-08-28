// Degenerate result-set sizes. A report of one check (Invoke-METTriage -CheckId ... |
// Get-METReport -Format HTML) and a report of none must both render: these exercise the
// serialisation of the embedded CHECKS array, where PowerShell's ConvertTo-Json collapses
// a one-element collection to a bare object and an empty collection to nothing at all.
const { test, expect } = require('./fixtures');

test.describe('single-check report', () => {
  test('renders the one card without a script error', async ({ page }) => {
    await page.goto('/report-single.html');
    await expect(page.locator('#cards-container .card')).toHaveCount(1);
    await expect(page.locator('.card[data-check-id="MET-EXO001"] .card-name')).toHaveText('DMARC Record');
    await expect(page.locator('#tc-all')).toHaveText('1');
    await expect(page.locator('#result-count')).toHaveText('Showing 1 of 1 checks');
  });

  test('scores and filters the single check', async ({ page }) => {
    await page.goto('/report-single.html');
    await expect(page.locator('#donut-score-text')).toHaveText('0');
    await expect(page.locator('#score-band')).toHaveText('Critical');
    await page.locator('#search').fill('dmarc');
    await expect(page.locator('#cards-container .card:visible')).toHaveCount(1);
  });
});

test.describe('empty report', () => {
  test('renders an empty state without a script error', async ({ page }) => {
    await page.goto('/report-empty.html');
    await expect(page.locator('#tc-all')).toHaveText('0');
    await expect(page.locator('#cards-container .card')).toHaveCount(0);
    await expect(page.locator('#no-results')).toBeVisible();
  });
});
