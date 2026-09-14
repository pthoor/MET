// Copilot review of commit 466fd0c, item 1: the donut's Error segment was still assigned
// var(--sev-critical), so a check that failed to run rendered as a Critical-red donut
// wedge even though its card, badge, and summary counter all use the neutral --result-error
// treatment (G-13 item 9). The donut must use --result-error for that segment too.
const { test, expect } = require('./fixtures');

// Mirrors New-METReportFixture.ps1 -Scenario ErrorBuckets: only Fail, Warning, and Error
// buckets are non-empty, so renderDonut() draws exactly 3 segments in that order (segs are
// built and filtered in the fixed order fail/warn/pass/na/info/error) - the third circle is
// the Error segment.
test.describe('donut Error segment color', () => {
  test('uses --result-error, not --sev-critical', async ({ page }) => {
    await page.goto('/report-error-buckets.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const circles = page.locator('#donut-segments circle');
    await expect(circles).toHaveCount(3);

    const { errorSegmentStroke, resultErrorRgb, sevCriticalRgb } = await page.evaluate(() => {
      function resolve(varName) {
        const value = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
        const probe = document.createElement('div');
        probe.style.color = value;
        document.body.appendChild(probe);
        const rgb = getComputedStyle(probe).color;
        probe.remove();
        return rgb;
      }
      const last = document.querySelectorAll('#donut-segments circle');
      return {
        errorSegmentStroke: getComputedStyle(last[last.length - 1]).stroke,
        resultErrorRgb: resolve('--result-error'),
        sevCriticalRgb: resolve('--sev-critical'),
      };
    });

    expect(errorSegmentStroke).toBe(resultErrorRgb);
    expect(errorSegmentStroke).not.toBe(sevCriticalRgb);
  });
});
