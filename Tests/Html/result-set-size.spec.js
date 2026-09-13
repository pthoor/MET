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

  // An empty set is an absent measurement, not a catastrophic tenant - see
  // Tests/Html/band-none.spec.js for the same "not a false Critical" assertion on a
  // non-empty all-Info set (and after a client-side rescore), where the result is the
  // 'None' band. A zero-check report is a stricter case still (G-8): it must not even
  // read as a real 'None' band value, but as a distinct "no data at all" state - see
  // Tests/Html/empty-report-banner.spec.js for the full behavior this renders.
  test('reports a no-data state, not a false Critical', async ({ page }) => {
    await page.goto('/report-empty.html');
    await expect(page.locator('#score-band')).toHaveText('No data');
    await expect(page.locator('#score-band')).toHaveClass(/band-none/);
    await expect(page.locator('#donut-score-text')).toHaveText('—');
  });
});
