// Codex review of commit 466fd0c, item 5: .card-group-header's sticky offset was a
// hardcoded `top:48px`, which assumed a one-row toolbar. At the report's documented
// 1024px minimum width (see CLAUDE.md's HTML Report Specification), the toolbar wraps
// to two rows, and the fixed 48px placed the sticky group header underneath the taller
// sticky toolbar instead of below it - the toolbar has the higher z-index, so the group
// header became genuinely unusable while scrolling, not just visually crowded. Fixed by
// tracking the toolbar's real rendered height in a CSS custom property (--toolbar-h),
// kept in sync by a ResizeObserver.
const { test, expect } = require('./fixtures');

test.describe('sticky group header vs. a wrapped (two-row) toolbar', () => {
  test('the toolbar wraps at 1024px width (precondition for this regression)', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 800 });
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const toolbarHeight = await page.locator('.toolbar').evaluate((el) => el.getBoundingClientRect().height);
    // A single-row toolbar is ~48px tall; a wrapped two-row toolbar is meaningfully taller.
    expect(toolbarHeight).toBeGreaterThan(60);
  });

  test('--toolbar-h tracks the toolbar\'s actual rendered height, not a hardcoded 48px', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 800 });
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const { toolbarHeight, toolbarHVar } = await page.evaluate(() => {
      const toolbar = document.querySelector('.toolbar');
      return {
        toolbarHeight: toolbar.getBoundingClientRect().height,
        toolbarHVar: getComputedStyle(document.documentElement).getPropertyValue('--toolbar-h').trim(),
      };
    });
    expect(toolbarHVar).toBe(Math.round(toolbarHeight) + 'px');
  });

  test('a sticky group header is not obscured by the wrapped sticky toolbar while scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 800 });
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const header = page.locator('.card-group[data-group="Fail"] .card-group-header');
    await header.scrollIntoViewIfNeeded();
    // Scroll further so both the toolbar and this group header are pinned in their sticky
    // positions at the same time, which is the exact condition the bug required.
    await page.mouse.wheel(0, 400);

    const [toolbarBox, headerBox] = await Promise.all([
      page.locator('.toolbar').evaluate((el) => el.getBoundingClientRect()),
      header.evaluate((el) => el.getBoundingClientRect()),
    ]);

    expect(headerBox.top).toBeGreaterThanOrEqual(toolbarBox.bottom);
  });
});
