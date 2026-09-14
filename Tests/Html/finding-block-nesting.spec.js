// Copilot review of commit 466fd0c, item 6: fmtFinding() can return block content
// (<div class="finding-policy">...</div> per line) for a multi-line/multi-policy Finding,
// but the call site still wrapped it in <span class="field-value">, the same invalid-nesting
// pattern G-14 item 7 already fixed for the Effective Policy Coverage table. Fixed by using
// a block <div class="field-value"> here too, keeping dir="auto".
const { test, expect } = require('./fixtures');

test.describe('multi-line Finding block nesting', () => {
  test('a multi-line Finding is not nested inside a <span>', async ({ page }) => {
    await page.goto('/report-coverage-table.html');
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await card.locator('.card-header').click();

    const policyBlock = card.locator('.finding-policy').first();
    await expect(policyBlock).toBeVisible();

    const fieldValue = card.locator('.field-value').filter({ has: page.locator('.finding-policy') }).first();
    const tagName = await fieldValue.evaluate((el) => el.tagName.toLowerCase());
    expect(tagName).toBe('div');
    await expect(fieldValue).toHaveAttribute('dir', 'auto');

    const hasSpanAncestorWithinCard = await policyBlock.evaluate((el, cardEl) => {
      let node = el.parentElement;
      while (node && node !== cardEl) {
        if (node.tagName.toLowerCase() === 'span') return true;
        node = node.parentElement;
      }
      return false;
    }, await card.elementHandle());
    expect(hasSpanAncestorWithinCard).toBe(false);
  });
});
