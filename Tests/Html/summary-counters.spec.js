// Summary bucket arithmetic, observed in the rendered page.
//
// A result can carry both a Result value and a populated Error field - Invoke-METTriage
// synthesizes Fail+Error for a check that threw, and MET-Teams014 reports NotApplicable+Error
// when Graph is unreachable. Error is a bucket of its own, mutually exclusive with every
// Result-based bucket, in the server-rendered banner AND in renderDonut(), which recomputes
// the same buckets on load and after every risk-acceptance toggle. If the two disagree, the
// banner counters and the donut drift away from the ERROR badges on the cards themselves.
//
// This used to be asserted by regex-matching the generator's JavaScript source for
// "result === 'Fail' && !isAccepted(resultKey(c)) && !c.error" and friends: broken by any
// whitespace change, and proof of nothing about what a browser computes.
const { test, expect } = require('./fixtures');

// Mirrors New-METReportFixture.ps1 -Scenario ErrorBuckets: 7 results, of which 5 carry an
// Error. Only the clean Fail and the clean Warning may appear under a Result bucket, so
// three buckets are non-empty (Fail, Warning, Error) and the donut draws three segments.
const BUCKETS = { total: 7, fail: 1, warn: 1, pass: 0, na: 0, info: 0, error: 5 };

test.describe('summary buckets exclude results that failed to run', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-error-buckets.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('an errored result is counted once, under Error only', async ({ page }) => {
    // sum-fail and sum-warn are the two counters renderDonut() rewrites on load, so these
    // two are the client's own arithmetic; the rest is the server's, and they must agree.
    await expect(page.locator('#sum-fail')).toHaveText(String(BUCKETS.fail));
    await expect(page.locator('#sum-warn')).toHaveText(String(BUCKETS.warn));
    await expect(page.locator('#sum-pass')).toHaveText(String(BUCKETS.pass));
    await expect(page.locator('#sum-na')).toHaveText(String(BUCKETS.na));
    await expect(page.locator('#sum-info')).toHaveText(String(BUCKETS.info));
    await expect(page.locator('#sum-err')).toHaveText(String(BUCKETS.error));
    await expect(page.locator('#tc-all')).toHaveText(String(BUCKETS.total));
  });

  test('the donut draws one segment per non-empty bucket', async ({ page }) => {
    // The only place the client's Pass/NotApplicable/Info recounts are observable: those
    // three counters are server-rendered and renderDonut() does not write them back. Drop
    // the Error exclusion from any of them and a fourth segment appears here.
    await expect(page.locator('#donut-segments circle')).toHaveCount(3);
  });

  test('the Error filter returns every errored result and no Result option repeats one', async ({ page }) => {
    await page.locator('#result-filter').selectOption('Error');
    await expect(page.locator('#cards-container .card:visible')).toHaveCount(BUCKETS.error);

    for (const [option, expected] of [
      ['Fail', BUCKETS.fail],
      ['Warning', BUCKETS.warn],
      ['Pass', BUCKETS.pass],
      ['NotApplicable', BUCKETS.na],
      ['Info', BUCKETS.info],
    ]) {
      await page.locator('#result-filter').selectOption(option);
      await expect(page.locator('#cards-container .card:visible')).toHaveCount(expected);
    }
  });

  test('accepting the clean Fail empties the Fail bucket live and on reload', async ({ page }) => {
    const card = page.locator('.card[data-check-id="MET-MDO001"]');
    await card.locator('.card-header').click();
    await card.getByRole('button', { name: /accept risk/i }).click();
    await page.locator('#modal-text').fill('Compensating control in place.');
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);

    // The Fail bucket also excludes accepted results, so it empties and its segment goes.
    await expect(page.locator('#sum-fail')).toHaveText('0');
    await expect(page.locator('#sum-warn')).toHaveText(String(BUCKETS.warn));
    await expect(page.locator('#sum-err')).toHaveText(String(BUCKETS.error));
    await expect(page.locator('#donut-segments circle')).toHaveCount(2);

    await page.reload();
    await expect(page.locator('#sum-fail')).toHaveText('0');
    await expect(page.locator('#donut-segments circle')).toHaveCount(2);
  });
});
