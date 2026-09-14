// Copilot review of commit 466fd0c, item 8: applyFilters() hides #cards-container while the
// Top5 tab is active, so clicking a remediation row from the dedicated Top 5 tab called
// scrollIntoView() on a display:none card and could neither reach nor expand it. The
// Controls-row jump handler in renderControlsRef() already switched to the All tab first -
// the Top 5 row handler must do the same before looking up the card.
const { test, expect } = require('./fixtures');

test.describe('Top 5 row navigation from the dedicated Top 5 tab', () => {
  test('clicking a row from the Top5 tab switches to All and expands the right card', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await page.locator('.tab[data-tab="Top5"]').click();
    await expect(page.locator('.tab[data-tab="Top5"]')).toHaveClass(/active/);
    await expect(page.locator('#cards-container')).toBeHidden();

    const firstRow = page.locator('.top5-row').first();
    const targetId = await firstRow.locator('.top5-id').textContent();
    await firstRow.click();

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    await expect(page.locator('#cards-container')).toBeVisible();

    const card = page.locator('.card[data-check-id="' + targetId + '"]').first();
    await expect(card.locator('.card-body')).toHaveClass(/open/);
    await expect(card).toBeInViewport();
  });
});
