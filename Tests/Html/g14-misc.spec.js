// G-14: a grab-bag of smaller HTML report findings from the accessibility/functionality/
// design audit. One file per group of related items rather than a per-item file, since each
// is small and self-contained.
const { test, expect } = require('./fixtures');

async function transformAngle(locator) {
  return locator.evaluate((el) => {
    const t = getComputedStyle(el).transform;
    if (t === 'none') return 0;
    const m = new DOMMatrix(t);
    return Math.round(Math.atan2(m.b, m.a) * (180 / Math.PI));
  });
}

test.describe('item 1: fix-chevron rotation direction', () => {
  test('rotates to point down (90deg) when expanded, not left (180deg)', async ({ page }) => {
    await page.goto('/report.html');
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    // Expanding a Fail card auto-opens its fix section.
    await card.locator('.card-header').click();
    const chevron = card.locator('.fix-chevron');
    await expect(chevron).toHaveClass(/open/);
    expect(await transformAngle(chevron)).toBe(90);

    await card.locator('.fix-toggle').click();
    await expect(chevron).not.toHaveClass(/open/);
    // .fix-chevron has a 200ms CSS transition on transform - poll past it instead of
    // sampling mid-animation.
    await expect.poll(() => transformAngle(chevron)).toBe(0);
  });
});

test.describe('item 2: codifyQuotes punctuation spacing', () => {
  test('a technical value immediately followed by punctuation gets tight padding, no stray space', async ({ page }) => {
    await page.goto('/report-single.html');
    const card = page.locator('.card[data-check-id="MET-EXO001"]');
    await card.locator('.card-header').click();

    const code = card.locator('.fix-content .inline-code', { hasText: 'p=quarantine' });
    await expect(code).toHaveClass(/inline-code--tight/);
    const paddingRight = await code.evaluate((el) => parseFloat(getComputedStyle(el).paddingRight));
    expect(paddingRight).toBeLessThan(5);

    const html = await page.content();
    expect(html).not.toMatch(/<\/code>\s+[.,;:!?]/);
  });
});

test.describe('item 3: unknown category vs. tab count agreement', () => {
  test('a category outside MDO/EXO/Teams still appears in All Controls and matches #tc-controls', async ({ page }) => {
    await page.goto('/report-unknown-category.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await page.locator('.tab[data-tab="Controls"]').click();
    const tabCount = await page.locator('#tc-controls').textContent();
    const rowCount = await page.locator('#ctrl-ref .ctrl-row').count();

    expect(rowCount).toBe(2);
    expect(String(rowCount)).toBe(tabCount);
    await expect(page.locator('#ctrl-ref')).toContainText('Compliance');
    await expect(page.locator('#ctrl-ref .ctrl-row[data-checkid="MET-XYZ001"]')).toHaveCount(1);
  });
});

test.describe('item 4: dead #result-count on the Controls tab', () => {
  test('is cleared, not left showing a stale value from another tab', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
    await expect(page.locator('#result-count')).not.toHaveText('');

    await page.locator('.tab[data-tab="Controls"]').click();
    await expect(page.locator('#result-count')).toHaveText('');
  });
});

test.describe('item 5: dir="auto" on bidi-sensitive fields', () => {
  test('field-value, card-name and top5-finding all carry dir="auto"', async ({ page }) => {
    await page.goto('/report.html');
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await card.locator('.card-header').click();

    await expect(card.locator('.field-value').first()).toHaveAttribute('dir', 'auto');
    await expect(card.locator('.card-name')).toHaveAttribute('dir', 'auto');
    await expect(page.locator('.top5-finding').first()).toHaveAttribute('dir', 'auto');
  });
});

test.describe('item 6: null Name/AffectedObject/Finding', () => {
  test('renders no empty .card-field and falls back to the CheckId as the card title', async ({ page }) => {
    await page.goto('/report-null-fields.html');
    const card = page.locator('.card[data-check-id="MET-EXO099"]');

    await expect(card.locator('.card-name')).toHaveText('MET-EXO099');

    await card.locator('.card-header').click();
    await expect(card.locator('.card-field')).toHaveCount(0);
  });
});

test.describe('item 7: coverage table block nesting', () => {
  test('the Effective Policy Coverage table is not nested inside a <span>', async ({ page }) => {
    await page.goto('/report-coverage-table.html');
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await card.locator('.card-header').click();

    const table = card.locator('.coverage-table');
    await expect(table).toBeVisible();

    const fieldValueTag = await table.evaluate((el) => el.closest('.field-value').tagName.toLowerCase());
    expect(fieldValueTag).toBe('div');

    const hasSpanAncestorWithinCard = await table.evaluate((el, cardEl) => {
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

test.describe('item 8: search/filter accessibility labelling', () => {
  test('search box and filter selects have aria-label; result-count announces politely', async ({ page }) => {
    await page.goto('/report.html');

    await expect(page.locator('#search')).toHaveAttribute('aria-label', /.+/);
    await expect(page.locator('#sev-filter')).toHaveAttribute('aria-label', /.+/);
    await expect(page.locator('#result-filter')).toHaveAttribute('aria-label', /.+/);
    await expect(page.locator('#result-count')).toHaveAttribute('aria-live', 'polite');
  });
});

test.describe('item 9: consistent focus-visible ring', () => {
  test('fix-toggle receives a visible outline on keyboard focus, matching card-header', async ({ page }) => {
    await page.goto('/report.html');
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    const header = card.locator('.card-header');

    // :focus-visible reflects keyboard modality, not merely which element is focused - a
    // real Tab keypress (not locator.focus()) is what makes Chromium apply it.
    await header.focus();
    await page.keyboard.press('Enter');
    await page.keyboard.press('Tab');

    const fixToggle = card.locator('.fix-toggle');
    await expect(fixToggle).toBeFocused();
    const outlineWidth = await fixToggle.evaluate((el) => getComputedStyle(el).outlineWidth);
    expect(outlineWidth).not.toBe('0px');
  });
});

test.describe('codifyQuotes: unquoted check-derived identifiers and values', () => {
  test('renders KNOWN_TOKENS identifiers, $true and CIDR values as inline code', async ({ page }) => {
    await page.goto('/report-known-tokens.html');
    const card = page.locator('.card[data-check-id="MET-EXO010"]');
    await card.locator('.card-header').click();

    const codes = card.locator('.inline-code');
    await expect(codes.filter({ hasText: /^RejectDirectSend$/ })).toHaveCount(1);
    await expect(codes.filter({ hasText: /^EnableSafeList$/ })).toHaveCount(1);
    await expect(codes.filter({ hasText: /^\$true$/ })).toHaveCount(1);
    await expect(codes.filter({ hasText: /^10\.0\.0\.0\/8$/ })).toHaveCount(1);
    // Surrounding prose stays plain text - only the identifiers themselves are coded.
    await expect(codes.filter({ hasText: /disabled/ })).toHaveCount(0);
  });
});
