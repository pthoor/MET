// G-3: the tab bar was seven `<div class="tab" data-tab="...">` elements with a click
// handler only - no role, no tabindex, so all seven were unreachable by keyboard and a
// screen reader had no way to know they were tabs at all.
const { test, expect } = require('./fixtures');

test.beforeEach(async ({ page }) => {
  await page.goto('/report.html');
  await expect(page.locator('#cards-container .card').first()).toBeVisible();
});

test.describe('tab bar keyboard operability', () => {
  test('the tab bar exposes tablist/tab semantics with one tab in the tab order', async ({ page }) => {
    await expect(page.locator('.tabs')).toHaveAttribute('role', 'tablist');

    const tabs = page.locator('.tab');
    await expect(tabs).toHaveCount(7);
    for (let i = 0; i < 7; i++) {
      await expect(tabs.nth(i)).toHaveAttribute('role', 'tab');
    }

    // Roving tabindex: only the active tab is in the Tab order; the rest are reachable
    // by arrow key once the tablist has focus, not by repeated Tab presses.
    await expect(page.locator('.tab.active')).toHaveAttribute('tabindex', '0');
    await expect(page.locator('.tab.active')).toHaveAttribute('aria-selected', 'true');
    const inactiveTabs = page.locator('.tab:not(.active)');
    await expect(inactiveTabs).toHaveCount(6);
    for (let i = 0; i < 6; i++) {
      await expect(inactiveTabs.nth(i)).toHaveAttribute('tabindex', '-1');
      await expect(inactiveTabs.nth(i)).toHaveAttribute('aria-selected', 'false');
    }
  });

  test('Tab from the search box reaches the active tab directly', async ({ page }) => {
    await page.locator('#search').focus();
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('.tab[data-tab="All"]')).toBeFocused();
  });

  test('Enter activates the focused tab', async ({ page }) => {
    await page.locator('.tab[data-tab="All"]').focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('.tab[data-tab="Top5"]')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('.tab[data-tab="Top5"]')).toHaveClass(/active/);
    await expect(page.locator('#top5-body')).toHaveClass(/open/);
  });

  test('Space activates the focused tab', async ({ page }) => {
    await page.locator('.tab[data-tab="MDO"]').focus();
    await page.keyboard.press(' ');
    await expect(page.locator('.tab[data-tab="MDO"]')).toHaveClass(/active/);
    const ids = await page.locator('#cards-container .card:visible').evaluateAll(
      (cards) => cards.map((c) => c.dataset.checkId)
    );
    expect(ids.every((id) => id.startsWith('MET-MDO'))).toBe(true);
  });

  test('ArrowRight/ArrowLeft move focus and activation across tabs, with wraparound', async ({ page }) => {
    await page.locator('.tab[data-tab="All"]').focus();

    await page.keyboard.press('ArrowLeft');
    await expect(page.locator('.tab[data-tab="Controls"]')).toBeFocused();
    await expect(page.locator('.tab[data-tab="Controls"]')).toHaveClass(/active/);

    await page.keyboard.press('ArrowRight');
    await expect(page.locator('.tab[data-tab="All"]')).toBeFocused();
    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
  });

  test('Home/End jump focus and activation to the first/last tab', async ({ page }) => {
    await page.locator('.tab[data-tab="EXO"]').focus();

    await page.keyboard.press('End');
    await expect(page.locator('.tab[data-tab="Controls"]')).toBeFocused();
    await expect(page.locator('.tab[data-tab="Controls"]')).toHaveClass(/active/);

    await page.keyboard.press('Home');
    await expect(page.locator('.tab[data-tab="All"]')).toBeFocused();
    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
  });
});
