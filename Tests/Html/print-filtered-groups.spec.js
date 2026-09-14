// Codex review of commit 466fd0c, item 4: updateGroupHeaders() adds .empty (base rule
// display:none) to any result group a search/filter/tab scope leaves with zero matches.
// The print stylesheet already forces collapsed group bodies and individual cards visible,
// but never overrode .card-group.empty itself - so a hidden ancestor still removed every
// card in that group from the printed page, no matter what the card's own print rule said.
const { test, expect } = require('./fixtures');

test.describe('print output ignores the live on-screen filter/grouping state', () => {
  test('a search that empties some groups on screen still prints every card', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    // "dmarc" matches only MET-EXO001 (Fail) in the Rich fixture - Warning/Pass/Info/Error
    // groups all end up with zero visible matches on screen.
    await page.locator('#search').fill('dmarc');
    const warningGroup = page.locator('.card-group[data-group="Warning"]');
    await expect(warningGroup).toHaveClass(/empty/);
    await expect(warningGroup.locator('.card:visible')).toHaveCount(0);

    await page.emulateMedia({ media: 'print' });

    // Every card in the filtered-out Warning group must still be visible on the printed
    // page, regardless of the live search filter.
    await expect(warningGroup).toBeVisible();
    const warningCards = warningGroup.locator('.card');
    const warningCount = await warningCards.count();
    expect(warningCount).toBeGreaterThan(0);
    for (let i = 0; i < warningCount; i++) {
      await expect(warningCards.nth(i)).toBeVisible();
    }
  });
});
