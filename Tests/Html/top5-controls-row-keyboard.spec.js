// Copilot review of commit 466fd0c, items 11 & 12: .top5-row (renderTop5()) and .ctrl-row
// (renderControlsRef()) were plain click-only elements with no way to reach or activate them
// from the keyboard. Same role="button"/tabindex="0"/Enter-or-Space pattern already
// established for .card-header and the tabs (see tabs-keyboard.spec.js).
const { test, expect } = require('./fixtures');

test.describe('.top5-row is keyboard-reachable and keyboard-activatable', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('carries role=button and tabindex=0', async ({ page }) => {
    const row = page.locator('.top5-row').first();
    await expect(row).toHaveAttribute('role', 'button');
    await expect(row).toHaveAttribute('tabindex', '0');
  });

  test('is reachable via Tab and Enter triggers the same navigation as a click', async ({ page }) => {
    const row = page.locator('.top5-row').first();
    const targetId = await row.locator('.top5-id').textContent();

    await row.focus();
    await expect(row).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    const card = page.locator('.card[data-check-id="' + targetId + '"]').first();
    await expect(card.locator('.card-body')).toHaveClass(/open/);
  });

  test('Space also triggers navigation', async ({ page }) => {
    const row = page.locator('.top5-row').first();
    const targetId = await row.locator('.top5-id').textContent();

    await row.focus();
    await page.keyboard.press(' ');

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    const card = page.locator('.card[data-check-id="' + targetId + '"]').first();
    await expect(card.locator('.card-body')).toHaveClass(/open/);
  });
});

test.describe('.ctrl-row (All Controls jump row) is keyboard-reachable and keyboard-activatable', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
    await page.locator('.tab[data-tab="Controls"]').click();
  });

  test('carries role=button and tabindex=0', async ({ page }) => {
    const row = page.locator('.ctrl-row').first();
    await expect(row).toHaveAttribute('role', 'button');
    await expect(row).toHaveAttribute('tabindex', '0');
  });

  test('is reachable via Tab and Enter jumps to and expands the right card', async ({ page }) => {
    const row = page.locator('.ctrl-row').first();
    const targetId = await row.getAttribute('data-checkid');

    await row.focus();
    await expect(row).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    const card = page.locator('.card[data-check-id="' + targetId + '"]').first();
    await expect(card).toBeInViewport();
  });

  test('Space also triggers navigation', async ({ page }) => {
    const row = page.locator('.ctrl-row').first();
    const targetId = await row.getAttribute('data-checkid');

    await row.focus();
    await page.keyboard.press(' ');

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    const card = page.locator('.card[data-check-id="' + targetId + '"]').first();
    await expect(card).toBeInViewport();
  });
});
