// G-10: the score-delta feature compares this run's score (INITIAL_SCORE) against a score
// cached in localStorage from a prior viewing (MET_score_<tenant>), via `parseInt(prev, 10)`
// with no finiteness guard. A corrupt cached value (e.g. hand-edited or from an unrelated
// app sharing the origin) parses to NaN, which then rendered as the literal text "NaN"
// beside the posture index. A corrupt cached value must be treated exactly like no cached
// value at all - no delta shown - not like a broken one.
const { test, expect } = require('./fixtures');

const SCORE_KEY = 'MET_score_contoso.onmicrosoft.com';

test.describe('score delta vs. a corrupt cached score', () => {
  test('a non-numeric cached score renders no delta and no "NaN" text', async ({ page, context }) => {
    await context.addInitScript((key) => {
      window.localStorage.setItem(key, 'not-a-number');
    }, SCORE_KEY);

    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('NaN');

    const deltaEl = page.locator('#score-delta');
    await expect(deltaEl).toHaveText('');
    await expect(deltaEl).not.toHaveClass(/delta-up/);
    await expect(deltaEl).not.toHaveClass(/delta-down/);
  });

  test('no cached score at all also renders no delta (baseline the corrupt case must match)', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const deltaEl = page.locator('#score-delta');
    await expect(deltaEl).toHaveText('');
    await expect(deltaEl).not.toHaveClass(/delta-up/);
    await expect(deltaEl).not.toHaveClass(/delta-down/);
  });

  test('a valid cached score still renders a real delta (regression guard for the guard itself)', async ({ page, context }) => {
    await context.addInitScript((key) => {
      window.localStorage.setItem(key, '30');
    }, SCORE_KEY);

    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const deltaEl = page.locator('#score-delta');
    await expect(deltaEl).toHaveText('+10');
    await expect(deltaEl).toHaveClass(/delta-up/);
  });
});
