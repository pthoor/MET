const { test, expect } = require('./fixtures');

// A-5: risk acceptance is keyed on the result (checkId + affectedObject), not the CheckId
// alone. Invoke-METTriage -Detailed routinely emits several results sharing one CheckId (one
// per domain/policy/mailbox) - MET-EXO004 (Quarantine Policies) here, with three distinct
// AffectedObject values, all Fail. Before the fix, accepting the first of three same-CheckId
// cards collided in `cardMap` (a single slot keyed by CheckId): only the last-written card
// visually updated, and the localStorage key was shared by all three, so a reload read all
// three as ACCEPTED even though only one was ever actioned.

test.describe('risk acceptance keyed per result', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-repeated-checkid.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('accepting one result of a repeated CheckId leaves its siblings untouched', async ({ page }) => {
    const cards = page.locator('[data-check-id="MET-EXO004"]');
    await expect(cards).toHaveCount(3);

    const before = parseInt(await page.locator('#tc-all').innerText(), 10);

    await cards.nth(0).locator('.card-header').click();
    await cards.nth(0).getByRole('button', { name: /accept risk/i }).click();
    await expect(page.locator('#modal-overlay')).toHaveClass(/open/);
    await page.locator('#modal-text').fill('Reviewed 2026-09-03, compensating control in place');
    await expect(page.locator('#modal-confirm')).toBeEnabled();
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);

    await expect(cards.nth(0)).toContainText('ACCEPTED');
    await expect(cards.nth(1)).not.toContainText('ACCEPTED');
    await expect(cards.nth(2)).not.toContainText('ACCEPTED');
    expect(parseInt(await page.locator('#tc-all').innerText(), 10)).toBe(before - 1);

    await page.reload();
    const cardsAfterReload = page.locator('[data-check-id="MET-EXO004"]');
    await expect(cardsAfterReload.nth(0)).toContainText('ACCEPTED');
    await expect(cardsAfterReload.nth(1)).not.toContainText('ACCEPTED');
    await expect(cardsAfterReload.nth(2)).not.toContainText('ACCEPTED');
  });

  test('a Top 5 row scrolls to its own card, not a same-CheckId sibling', async ({ page }) => {
    const rows = page.locator('.top5-row');
    await expect(rows).toHaveCount(3);

    const targetRow = rows.nth(1);
    const targetKey = await targetRow.getAttribute('data-result-key');
    expect(targetKey).toBeTruthy();

    await targetRow.click();

    const targetCard = page.locator(`.card[data-result-key="${targetKey}"]`);
    await expect(targetCard).toBeInViewport();
    await expect(targetCard.locator('.card-body')).toHaveClass(/open/);
  });

  test('an All-Controls row jumps to its own card', async ({ page }) => {
    await page.locator('.tab[data-tab="Controls"]').click();
    const rows = page.locator('.ctrl-row[data-checkid="MET-EXO004"]');
    await expect(rows).toHaveCount(3);

    const targetRow = rows.nth(2);
    const targetKey = await targetRow.getAttribute('data-result-key');

    await targetRow.click();

    await expect(page.locator('.tab[data-tab="All"]')).toHaveClass(/active/);
    const targetCard = page.locator(`.card[data-result-key="${targetKey}"]`);
    await expect(targetCard).toBeInViewport();
  });
});
