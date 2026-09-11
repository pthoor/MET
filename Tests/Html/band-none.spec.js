// The 'None' band: an unscorable result set (empty, or every result Info/NotApplicable)
// must never be presented as a real band on the 5-band ladder, either in the server-rendered
// initial HTML or after a client-side rescore. Public/Get-METReport.ps1's PowerShell-side
// $band assignment reports 'None' correctly on load; bandOf()/recalcScore() are the client's
// own reimplementation of that same ladder and did not know 'None' existed, so a rescore
// (e.g. accepting the only remaining scorable Fail) silently replaced a correct server-
// rendered None with a false Critical - the exact defect C-5 removed on the server side.
const { test, expect } = require('./fixtures');

test.describe('None band on initial load', () => {
  test('an all-Info result set renders band None, not a false Critical', async ({ page }) => {
    await page.goto('/report-info-only.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await expect(page.locator('#score-band')).toHaveText('None');
    await expect(page.locator('#score-band')).toHaveClass(/band-none/);
    await expect(page.locator('#donut-score-text')).toHaveText('0');
  });
});

test.describe('None band after a client-side rescore', () => {
  test('accepting the only scorable Fail leaves band None, not Critical', async ({ page }) => {
    await page.goto('/report-fail-plus-info.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    // Confirms the fixture starts scorable (real Critical band) so the rescore below is
    // actually exercising a transition, not just re-asserting an already-None band.
    await expect(page.locator('#score-band')).toHaveText('Critical');

    const card = page.locator('.card[data-check-id="MET-EXO001"]');
    await card.locator('.card-header').click();
    await card.getByRole('button', { name: /accept risk/i }).click();
    await expect(page.locator('#modal-overlay')).toHaveClass(/open/);
    await page.locator('#modal-text').fill('Compensating control in place.');
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);

    // The only scorable result is now accepted-away - nothing scorable remains.
    await expect(page.locator('#score-band')).toHaveText('None');
    await expect(page.locator('#score-band')).not.toHaveText('Critical');
    await expect(page.locator('#score-band')).toHaveClass(/band-none/);

    // The banner border-color hook and the tooltip's current-row highlight both key off
    // the same band value - confirm neither is left pointing at a stale/wrong band.
    await expect(page.locator('#score-banner')).toHaveAttribute('data-band', 'none');
    await expect(page.locator('.band-tooltip .btr.cur')).toHaveCount(0);
  });
});
