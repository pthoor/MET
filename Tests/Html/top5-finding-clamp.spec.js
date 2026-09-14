// G-6: fmtFinding() had no length clamp in the Top 5 row, so a long Finding (a 1600+
// character string is a real shape - some checks emit multi-issue, multi-line Findings)
// expanded one row to many lines and pushed the rest of the section off-screen. Fixed with
// a CSS -webkit-line-clamp on .top5-finding rather than truncating fmtFinding() itself,
// which is also used on the full check card where the complete Finding must still render.
const { test, expect } = require('./fixtures');

test.describe('Top 5 finding text is clamped', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-long-finding.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('a 1600+ character finding does not blow out the row height', async ({ page }) => {
    const rows = page.locator('.top5-row');
    await expect(rows).toHaveCount(2);

    const shortHeight = await page
      .locator('.top5-row', { has: page.locator('.top5-id', { hasText: 'MET-MDO001' }) })
      .locator('.top5-finding')
      .evaluate((el) => el.getBoundingClientRect().height);

    const longFinding = page.locator('.top5-row', { has: page.locator('.top5-id', { hasText: 'MET-EXO001' }) })
      .locator('.top5-finding');
    const longHeight = await longFinding.evaluate((el) => el.getBoundingClientRect().height);

    // Clamped to 2 lines: allow generous slack over the short (1-line) row's height, but
    // nowhere near the dozens of lines an unclamped 1600+ char string would render as.
    expect(longHeight).toBeLessThan(shortHeight * 3);
  });

  test('the clamped finding overflows its box rather than fully rendering', async ({ page }) => {
    const longFinding = page
      .locator('.top5-row', { has: page.locator('.top5-id', { hasText: 'MET-EXO001' }) })
      .locator('.top5-finding');
    const overflows = await longFinding.evaluate((el) => el.scrollHeight > el.clientHeight + 1);
    expect(overflows).toBe(true);
  });
});
