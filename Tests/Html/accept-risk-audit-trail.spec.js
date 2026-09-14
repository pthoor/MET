const { test, expect } = require('./fixtures');

// G-9: setAccepted() stored only the bare justification string, dropping the acceptance
// date entirely - for a risk-acceptance audit trail the date is the point. The stored
// value must now be JSON carrying both `justification` and `acceptedAt`, and the Accepted
// card must render the date somewhere visible. Old bare-string values already sitting in a
// user's browser localStorage from before this fix must keep working (back-compat read).
//
// G-12: the justification <textarea> took unbounded input. A multi-megabyte paste throws
// QuotaExceededError inside lsSet(), which is silently swallowed into an in-memory fallback -
// the acceptance appears to succeed and vanishes on reload. The textarea now carries a
// maxlength, and the confirm handler defensively truncates so this input specifically can
// never trigger that path.

// Mirrors the 'MET-MDO001' entry in New-METReportFixture.ps1's default (Rich) scenario:
// CheckId 'MET-MDO001', Name 'Safe Links Policy', AffectedObject 'Default Safe Links Policy'.
const LEGACY_KEY = 'MET_accepted_contoso.onmicrosoft.com_MET-MDO001|Safe Links Policy|Default Safe Links Policy';

async function findStoredAcceptance(page, resultKey) {
  return page.evaluate((rKey) => {
    for (const k of Object.keys(localStorage)) {
      if (k.startsWith('MET_accepted_') && k.endsWith(rKey)) return localStorage.getItem(k);
    }
    return null;
  }, resultKey);
}

async function openModalFor(page, checkId) {
  const card = page.locator(`.card[data-check-id="${checkId}"]`);
  await card.locator('.card-header').click();
  await card.getByRole('button', { name: /accept risk/i }).click();
  await expect(page.locator('#modal-overlay')).toHaveClass(/open/);
}

test.describe('accept risk audit trail (G-9)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('accepting a risk stores justification and an acceptedAt timestamp, and shows the date on the card', async ({ page }) => {
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    const resultKey = await card.getAttribute('data-result-key');

    const before = Date.now();
    await openModalFor(page, 'MET-MDO001');
    await page.locator('#modal-text').fill('Compensating control in place, reviewed 2026-09-13.');
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);
    const after = Date.now();

    const raw = await findStoredAcceptance(page, resultKey);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw);
    expect(parsed.justification).toBe('Compensating control in place, reviewed 2026-09-13.');
    expect(parsed.acceptedAt).toBeTruthy();
    const acceptedAtMs = new Date(parsed.acceptedAt).getTime();
    expect(acceptedAtMs).toBeGreaterThanOrEqual(before - 1000);
    expect(acceptedAtMs).toBeLessThanOrEqual(after + 1000);

    // Accepting moves the card out of the All tab's scope entirely (see accept-risk-modal-a11y.spec.js),
    // so it must be viewed via the Accepted tab from here on.
    await page.locator('.tab[data-tab="Accepted"]').click();
    const acceptedCard = page.locator('.card[data-check-id="MET-MDO001"]');
    await expect(acceptedCard).toContainText('Compensating control in place, reviewed 2026-09-13.');
    await acceptedCard.locator('.card-header').click();
    await expect(acceptedCard.locator('.accepted-date')).toBeVisible();

    await page.reload();
    await page.locator('.tab[data-tab="Accepted"]').click();
    const reloadedCard = page.locator('.card[data-check-id="MET-MDO001"]');
    await expect(reloadedCard).toContainText('ACCEPTED');
    await reloadedCard.locator('.card-header').click();
    await expect(reloadedCard.locator('.accepted-date')).toBeVisible();
  });

  test('a legacy bare-string acceptance value still renders as the justification with no date and no crash', async ({ page, context }) => {
    await context.addInitScript((key) => {
      window.localStorage.setItem(key, 'Old-format acceptance, pre-G9');
    }, LEGACY_KEY);

    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await expect(card).toContainText('ACCEPTED');
    await expect(card).toContainText('Old-format acceptance, pre-G9');

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('undefined');
    expect(bodyText).not.toContain('[object Object]');

    await expect(card.locator('.accepted-date')).toHaveCount(0);
  });
});

test.describe('accept risk justification length bound (G-12)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('the justification textarea declares a maxlength', async ({ page }) => {
    await openModalFor(page, 'MET-MDO001');
    const maxLength = await page.locator('#modal-text').getAttribute('maxlength');
    expect(maxLength).toBeTruthy();
    expect(parseInt(maxLength, 10)).toBeGreaterThan(0);
  });

  test('a programmatic value beyond maxlength is truncated before being stored, not dropped or thrown', async ({ page }) => {
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    const resultKey = await card.getAttribute('data-result-key');
    const maxLength = parseInt(await (async () => {
      await openModalFor(page, 'MET-MDO001');
      return page.locator('#modal-text').getAttribute('maxlength');
    })(), 10);

    const oversized = 'A'.repeat(maxLength + 1000);
    await page.locator('#modal-text').evaluate((el, text) => {
      el.value = text;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }, oversized);

    await expect(page.locator('#modal-confirm')).toBeEnabled();
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);

    const raw = await findStoredAcceptance(page, resultKey);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw);
    expect(parsed.justification.length).toBeLessThanOrEqual(maxLength);
    expect(parsed.justification.length).toBeGreaterThan(0);
  });
});
