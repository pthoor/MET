// G-5: Top 5 ranked by result-order-then-per-item-severity with no aggregation, so three
// results sharing one CheckId (e.g. MET-EXO004 evaluated per policy) burned multiple slots
// on the same control, and an errored check (couldn't even be assessed) could still surface
// with useless "Check could not complete" copy. Fixed by grouping actionable results by
// CheckId, ranking groups by summed severity weight, and excluding any result with a
// populated Error field.
const { test, expect } = require('./fixtures');

test.describe('Top 5 groups repeated CheckIds', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-repeated-checkid.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('three MET-EXO004 Fail results collapse into a single Top 5 row', async ({ page }) => {
    const rows = page.locator('.top5-row');
    await expect(rows).toHaveCount(1);
    await expect(rows.first().locator('.top5-id')).toHaveText('MET-EXO004');
  });

  test('the grouped row names the member count', async ({ page }) => {
    await expect(page.locator('.top5-row .top5-name')).toContainText('3');
  });
});

test.describe('Top 5 ranks groups by summed severity weight', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-ranking-by-sum.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('three Medium Fails (weight 30) outrank a single High Fail (weight 20)', async ({ page }) => {
    const rows = page.locator('.top5-row');
    await expect(rows).toHaveCount(2);
    await expect(rows.first().locator('.top5-id')).toHaveText('MET-EXO004');
    await expect(rows.nth(1).locator('.top5-id')).toHaveText('MET-MDO001');
  });
});

test.describe('Top 5 excludes errored checks', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-error-buckets.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('a Fail carrying a populated Error field never appears in Top 5', async ({ page }) => {
    // ErrorBuckets fixture: MET-MDO001 is a clean Fail (no Error); MET-MDO002 is a Fail
    // that also carries a populated Error ("Fail that failed to run") and must be excluded.
    // MET-EXO001 is a Warning carrying an Error and must also be excluded.
    const ids = await page.locator('.top5-row .top5-id').allTextContents();
    expect(ids).toContain('MET-MDO001');
    expect(ids).not.toContain('MET-MDO002');
    expect(ids).not.toContain('MET-EXO001');
  });
});
