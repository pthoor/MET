// G-4: the Accept Risk modal was a plain <div> with no role, no aria-modal, no
// aria-labelledby; Escape did nothing; Tab walked straight out into the page behind it;
// and focus was never returned to whatever triggered the modal on close.
const { test, expect } = require('./fixtures');

test.beforeEach(async ({ page }) => {
  await page.goto('/report.html');
  await expect(page.locator('#cards-container .card').first()).toBeVisible();
});

async function openModalFor(page, checkId) {
  const card = page.locator(`.card[data-check-id="${checkId}"]`);
  await card.locator('.card-header').click();
  await card.getByRole('button', { name: /accept risk/i }).click();
  await expect(page.locator('#modal-overlay')).toHaveClass(/open/);
}

test.describe('Accept Risk modal dialog semantics', () => {
  test('exposes dialog role, aria-modal and aria-labelledby pointing at the title', async ({ page }) => {
    await openModalFor(page, 'MET-MDO001');

    const modal = page.locator('.modal');
    await expect(modal).toHaveAttribute('role', 'dialog');
    await expect(modal).toHaveAttribute('aria-modal', 'true');

    const labelledBy = await modal.getAttribute('aria-labelledby');
    expect(labelledBy).toBeTruthy();
    await expect(page.locator(`#${labelledBy}`)).toHaveText('Accept Risk');
  });

  test('Escape closes the modal without accepting anything', async ({ page }) => {
    await openModalFor(page, 'MET-MDO001');
    await page.locator('#modal-text').fill('Should not be saved');
    await page.keyboard.press('Escape');

    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await expect(card).not.toContainText('ACCEPTED');
  });

  test('focus returns to the triggering Accept Risk button after Escape', async ({ page }) => {
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await card.locator('.card-header').click();
    const acceptBtn = card.getByRole('button', { name: /accept risk/i });
    await acceptBtn.click();
    await expect(page.locator('#modal-overlay')).toHaveClass(/open/);

    await page.keyboard.press('Escape');
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);
    await expect(acceptBtn).toBeFocused();
  });

  test('Tab cycles focus within the modal instead of escaping into the page', async ({ page }) => {
    await openModalFor(page, 'MET-MDO001');

    // Starts on the textarea (auto-focused on open); Confirm is disabled until text is entered.
    await expect(page.locator('#modal-text')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#modal-cancel')).toBeFocused();
    await page.keyboard.press('Tab');
    // Confirm is still disabled (no justification typed), so it is skipped by native Tab
    // order and focus wraps back to the textarea, not out to the page behind the modal.
    await expect(page.locator('#modal-text')).toBeFocused();

    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#modal-cancel')).toBeFocused();
  });

  test('Tab cycles through all three controls once Confirm is enabled', async ({ page }) => {
    await openModalFor(page, 'MET-MDO001');
    await page.locator('#modal-text').fill('Compensating control in place.');

    await expect(page.locator('#modal-text')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#modal-cancel')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#modal-confirm')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#modal-text')).toBeFocused();
  });
});
