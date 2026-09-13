// G-8: a zero-check report (no assessment ran, or none was imported) rendered a score of 0
// and band CRITICAL - a reader sees a catastrophic posture report when in fact nothing was
// assessed. This is distinct from the pre-existing 'None' band (see band-none.spec.js /
// C-5), which covers a *non-empty* CHECKS array where every result is unscorable (e.g. all
// Info) - that mechanism already renders band None correctly. G-8 is the CHECKS.length === 0
// case specifically: zero checks at all, which must read as "no data", not as a real score.
const { test, expect } = require('./fixtures');

test.describe('empty report: score banner does not present as a real posture score', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-empty.html');
  });

  test('the score digit and band show a neutral no-data state, not 0/Critical', async ({ page }) => {
    await expect(page.locator('#donut-score-text')).not.toHaveText('0');
    await expect(page.locator('#score-band')).not.toHaveText('Critical');
    await expect(page.locator('#score-band')).not.toHaveText('0');
  });

  test('no category meters render for an empty report', async ({ page }) => {
    await expect(page.locator('#cat-meters .cat-meter-row')).toHaveCount(0);
  });

  test('the donut draws no segments for an empty report', async ({ page }) => {
    await expect(page.locator('#donut-segments').locator('*')).toHaveCount(0);
  });

  test('the empty-state message is distinct from the filtered-to-zero message', async ({ page }) => {
    const noResults = page.locator('#no-results');
    await expect(noResults).toBeVisible();
    await expect(noResults).toHaveText('No check results in this report.');
    await expect(noResults).not.toHaveText('No checks match the current filters.');
  });
});

test.describe('non-empty report: filtered-to-zero keeps the original message', () => {
  test('a search matching nothing on a real report still shows the filters message', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await page.locator('#search').fill('this-matches-absolutely-nothing-zzz');
    const noResults = page.locator('#no-results');
    await expect(noResults).toBeVisible();
    await expect(noResults).toHaveText('No checks match the current filters.');
    await expect(noResults).not.toHaveText('No check results in this report.');
  });
});
