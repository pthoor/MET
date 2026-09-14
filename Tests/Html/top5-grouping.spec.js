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

// Copilot review of commit 466fd0c, item 7: a single CheckId can emit actionable members
// with different severities and findings (e.g. MET-MDO010's High Fail for the protection
// toggle vs. its Medium Warning for tagging). The grouped Top 5 row kept only the first
// member seen, which could show an arbitrary/less-severe issue. The group must show the
// highest-priority member deterministically (Fail before Warning, then higher severity
// weight), same ranking used for card sorting elsewhere in this file.
test.describe('Top 5 group picks the highest-priority member, not the first one seen', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-mixed-severity-group.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('the group shows the High Fail\'s severity and finding, even though the Medium Warning is listed first', async ({ page }) => {
    const rows = page.locator('.top5-row');
    await expect(rows).toHaveCount(1);
    await expect(rows.first().locator('.top5-id')).toHaveText('MET-MDO010');
    await expect(rows.first().locator('.sev-pill')).toHaveText('HIGH');
    await expect(rows.first()).toContainText('Priority account protection is disabled tenant-wide');
    await expect(rows.first()).not.toContainText('No priority account tags are applied');
  });

  test('the grouped row still names the member count', async ({ page }) => {
    await expect(page.locator('.top5-row .top5-name')).toContainText('2');
  });
});

// Copilot review of commit 466fd0c, item 9: the NullFields fixture's actionable Warning has
// no usable Name - Top 5 must fall back to the CheckId, same as the card title already does
// (G-14 item 6), instead of rendering a blank name.
test.describe('Top 5 falls back to CheckId when Name is null', () => {
  test('a null-Name actionable check shows its CheckId in the Top 5 name', async ({ page }) => {
    await page.goto('/report-null-fields.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const row = page.locator('.top5-row').filter({ hasText: 'MET-EXO099' });
    await expect(row).toHaveCount(1);
    await expect(row.locator('.top5-name')).not.toHaveText('');
    await expect(row.locator('.top5-name')).toContainText('MET-EXO099');
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
