// G-13 (full design pass) + G-11 (contrast) regression coverage.
//
// G-11: recomputes WCAG contrast ratios in-browser from the ACTUAL computed colors of the
// four flagged token/context pairs, rather than re-typing hex values here - a value that
// drifts in the stylesheet fails these tests instead of silently going stale.
//
// G-13 item 2/9: a card's left border must be driven by Result (and, for a check that
// failed to run, a third neutral "error" state), never by Severity - see
// Tests/Html/New-METReportFixture.ps1's DesignHierarchy scenario for the specific
// combinations (Pass+Critical, Fail+Informational, NotApplicable+Error+Critical) that were
// indistinguishable, or actively misleading, under the old severity-driven border.
const { test, expect } = require('./fixtures');

// Relative luminance / contrast ratio (WCAG 2.x), computed from whatever
// getComputedStyle(...) hands back (an "rgb(r, g, b)" or "rgba(r, g, b, a)" string). Also
// exposes effectiveBackgroundColor(): most elements in this report don't set their own
// background (e.g. an Info/NotApplicable .card, or .card-body, both of which visually show
// whatever background their nearest ancestor painted) - getComputedStyle on the element
// itself would report transparent in that case, not what a reader actually sees, so this
// walks up to the nearest ancestor with a real (non-transparent) background-color.
function contrastRatioFn() {
  function parseRgb(str) {
    const m = str.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(',').map((n) => parseFloat(n.trim()));
    if (parts.length >= 4 && parts[3] === 0) return null; // fully transparent
    return parts.slice(0, 3);
  }
  function luminance([r, g, b]) {
    const lin = (c) => {
      c /= 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    };
    const [R, G, B] = [r, g, b].map(lin);
    return 0.2126 * R + 0.7152 * G + 0.0722 * B;
  }
  function contrastRatio(a, b) {
    const L1 = luminance(parseRgb(a));
    const L2 = luminance(parseRgb(b));
    const [hi, lo] = L1 > L2 ? [L1, L2] : [L2, L1];
    return (hi + 0.05) / (lo + 0.05);
  }
  function effectiveBackgroundColor(el) {
    let node = el;
    while (node) {
      const rgb = parseRgb(getComputedStyle(node).backgroundColor);
      if (rgb) return getComputedStyle(node).backgroundColor;
      node = node.parentElement;
    }
    return 'rgb(255, 255, 255)';
  }
  contrastRatio.effectiveBackgroundColor = effectiveBackgroundColor;
  return contrastRatio;
}

test.describe('G-11: contrast fixes, recomputed from actual rendered colors', () => {
  test('light mode: --text3 contexts (card chevron, search placeholder, band range) meet 4.5:1', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const results = await page.evaluate((fnSrc) => {
      const contrastRatio = eval(`(${fnSrc})`)();
      const out = {};

      // .card-chevron on an untinted card (NotApplicable/Info carry no background tint).
      const chevron = document.querySelector('.card[data-check-id="MET-EXO007"] .card-chevron');
      out.chevron = contrastRatio(getComputedStyle(chevron).color, contrastRatio.effectiveBackgroundColor(chevron));

      // Search box placeholder against its own background.
      const search = document.getElementById('search');
      const placeholderColor = getComputedStyle(search, '::placeholder').color;
      out.placeholder = contrastRatio(placeholderColor, contrastRatio.effectiveBackgroundColor(search));

      // .brange (band scale range) against the tooltip's own background.
      const tooltip = document.getElementById('band-tooltip');
      // Populate the tooltip so a .brange element actually exists to measure.
      document.querySelector('.score-band-wrap').dispatchEvent(new Event('mouseover', { bubbles: true }));
      const brange = tooltip.querySelector('.brange');
      out.brange = brange ? contrastRatio(getComputedStyle(brange).color, contrastRatio.effectiveBackgroundColor(brange)) : null;

      return out;
    }, contrastRatioFn.toString());

    expect(results.chevron, 'card-chevron vs card background').toBeGreaterThanOrEqual(4.5);
    expect(results.placeholder, 'search placeholder vs search-box background').toBeGreaterThanOrEqual(4.5);
    expect(results.brange, '.brange vs band-tooltip background').not.toBeNull();
    expect(results.brange, '.brange vs band-tooltip background').toBeGreaterThanOrEqual(4.5);
  });

  test('dark mode: --accent-mdo text contexts (How to fix / Microsoft Docs / active tab) meet 4.5:1', async ({ browser }) => {
    const context = await browser.newContext({ colorScheme: 'dark' });
    const page = await context.newPage();
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const results = await page.evaluate((fnSrc) => {
      const contrastRatio = eval(`(${fnSrc})`)();
      const out = {};

      const tab = document.querySelector('.tab.active');
      out.activeTab = contrastRatio(getComputedStyle(tab).color, contrastRatio.effectiveBackgroundColor(tab));

      const docsLink = document.querySelector('.btn-docs');
      out.docsLink = docsLink
        ? contrastRatio(getComputedStyle(docsLink).color, contrastRatio.effectiveBackgroundColor(docsLink))
        : null;

      return out;
    }, contrastRatioFn.toString());

    expect(results.activeTab, 'active tab text vs toolbar background (dark)').toBeGreaterThanOrEqual(4.5);
    expect(results.docsLink, '"Microsoft Docs" link vs card-body background (dark)').not.toBeNull();
    expect(results.docsLink, '"Microsoft Docs" link vs card-body background (dark)').toBeGreaterThanOrEqual(4.5);

    await context.close();
  });

  test('card-error text meets 4.5:1 against its own background, in both themes', async ({ browser }) => {
    for (const colorScheme of ['light', 'dark']) {
      const context = await browser.newContext({ colorScheme });
      const page = await context.newPage();
      await page.goto('/report-error-with-recommendation.html');
      await expect(page.locator('#cards-container .card').first()).toBeVisible();

      // Expanding a Fail/errored card auto-opens its "How to fix"/"Details" section on
      // first expand (see createCard()'s cardHeader click handler) - no second click needed.
      await page.locator('.card-header').first().click();
      const errorBox = page.locator('.card-error').first();
      await expect(errorBox).toBeVisible();

      const ratio = await page.evaluate((fnSrc) => {
        const contrastRatio = eval(`(${fnSrc})`)();
        const el = document.querySelector('.card-error');
        return contrastRatio(getComputedStyle(el).color, getComputedStyle(el).backgroundColor);
      }, contrastRatioFn.toString());

      expect(ratio, `.card-error contrast (${colorScheme})`).toBeGreaterThanOrEqual(4.5);
      await context.close();
    }
  });
});

// Resolves a CSS custom property (e.g. "--sev-critical") to the browser's normalised
// "rgb(r, g, b)" form, so a comparison against getComputedStyle() output never breaks over
// a hex/rgb spelling mismatch, and never needs a hardcoded color literal that could drift
// out of sync with the stylesheet.
async function resolveCssVar(page, varName) {
  return page.evaluate((name) => {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const probe = document.createElement('div');
    probe.style.color = value;
    document.body.appendChild(probe);
    const rgb = getComputedStyle(probe).color;
    probe.remove();
    return rgb;
  }, varName);
}

test.describe('G-13 item 2/9: result (and a distinct error state) drive card emphasis, not severity', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-design-hierarchy.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('a Pass card at Critical severity uses the Pass border, not the critical-red one', async ({ page }) => {
    const [sevCriticalRgb, resultPassRgb] = await Promise.all([
      resolveCssVar(page, '--sev-critical'),
      resolveCssVar(page, '--result-pass'),
    ]);
    const cardBorder = await page
      .locator('.card[data-check-id="MET-MDO009"]')
      .evaluate((el) => getComputedStyle(el).borderLeftColor);

    expect(cardBorder).not.toBe(sevCriticalRgb);
    expect(cardBorder).toBe(resultPassRgb);
  });

  test('the severity chip on that Pass card is desaturated (is-pass), not a solid Critical fill', async ({ page }) => {
    const sevCriticalRgb = await resolveCssVar(page, '--sev-critical');
    const pill = page.locator('.card[data-check-id="MET-MDO009"] .sev-pill');
    await expect(pill).toHaveClass(/is-pass/);
    await expect(pill).toHaveText('CRITICAL'); // severity is still reported...
    const styles = await pill.evaluate((el) => {
      const cs = getComputedStyle(el);
      return { color: cs.color, borderColor: cs.borderColor };
    });
    // ...but not rendered in the critical-red channel now that the control passed.
    expect(styles.color).not.toBe(sevCriticalRgb);
    expect(styles.borderColor).not.toBe(sevCriticalRgb);
  });

  test('a Fail card at Informational severity still gets the Fail (red) border', async ({ page }) => {
    const resultFailRgb = await resolveCssVar(page, '--result-fail');
    const borderColor = await page
      .locator('.card[data-check-id="MET-EXO007"]')
      .evaluate((el) => getComputedStyle(el).borderLeftColor);
    expect(borderColor).toBe(resultFailRgb);
  });

  test('an errored NotApplicable+Critical card is a third state - neither Fail-red nor severity-critical-red', async ({ page }) => {
    const [sevCriticalRgb, resultFailRgb] = await Promise.all([
      resolveCssVar(page, '--sev-critical'),
      resolveCssVar(page, '--result-fail'),
    ]);
    const card = page.locator('.card[data-check-id="MET-Teams014"]');
    const style = await card.evaluate((el) => {
      const cs = getComputedStyle(el);
      const before = getComputedStyle(el, '::before');
      return {
        borderLeftColor: cs.borderLeftColor,
        beforeBackgroundImage: before.backgroundImage,
      };
    });
    expect(style.borderLeftColor).not.toBe(resultFailRgb);
    expect(style.borderLeftColor).not.toBe(sevCriticalRgb);
    // The dashed/striped treatment lives on ::before (a diagonal hazard-stripe fill),
    // distinct from a flat border color a Fail or a Critical severity chip would use.
    expect(style.beforeBackgroundImage).toContain('repeating-linear-gradient');

    // The severity pill still reports the real severity, unmasked by the error state.
    await expect(card.locator('.sev-pill')).toHaveText('CRITICAL');
    await expect(card.locator('.result-badge')).toHaveText('ERROR');
  });
});

test.describe('G-13 item 3: grouped, collapsible, counted card sections', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('each result group header shows the correct count, and empty groups are hidden', async ({ page }) => {
    await expect(page.locator('.card-group[data-group="Fail"] .card-group-count')).toHaveText('2');
    await expect(page.locator('.card-group[data-group="Warning"] .card-group-count')).toHaveText('2');
    await expect(page.locator('.card-group[data-group="Pass"] .card-group-count')).toHaveText('3');
    await expect(page.locator('.card-group[data-group="Info"] .card-group-count')).toHaveText('1');
    await expect(page.locator('.card-group[data-group="Error"] .card-group-count')).toHaveText('1');
    // Rich fixture has no clean NotApplicable result (Teams014 is NotApplicable+Error, and
    // Error wins the group) - that group must exist but render nothing.
    await expect(page.locator('.card-group[data-group="NotApplicable"]')).toHaveClass(/empty/);
  });

  test('a group header collapses and expands its body on click', async ({ page }) => {
    const header = page.locator('.card-group[data-group="Pass"] .card-group-header');
    const body = page.locator('.card-group[data-group="Pass"] .card-group-body');
    await expect(body).not.toHaveClass(/collapsed/);
    await header.click();
    await expect(body).toHaveClass(/collapsed/);
    await header.click();
    await expect(body).not.toHaveClass(/collapsed/);
  });

  test('group counts recompute as search narrows the result set', async ({ page }) => {
    // "dmarc" matches only MET-EXO001 (Fail) in the Rich fixture.
    await page.locator('#search').fill('dmarc');
    await expect(page.locator('.card-group[data-group="Fail"] .card-group-count')).toHaveText('1');
    await expect(page.locator('.card-group[data-group="Warning"]')).toHaveClass(/empty/);
    await expect(page.locator('.card-group[data-group="Pass"]')).toHaveClass(/empty/);
  });

  test('clicking a Top 5 row expands its card even if the card\'s group was collapsed', async ({ page }) => {
    await page.locator('.card-group[data-group="Fail"] .card-group-header').click();
    await expect(page.locator('.card-group[data-group="Fail"] .card-group-body')).toHaveClass(/collapsed/);

    await page.locator('.top5-row').first().click();

    await expect(page.locator('.card-group[data-group="Fail"] .card-group-body')).not.toHaveClass(/collapsed/);
    const firstFailCard = page.locator('.card-group[data-group="Fail"] .card').first();
    await expect(firstFailCard.locator('.card-body')).toHaveClass(/open/);
  });
});

test.describe('G-13 item 7: the score delta states its baseline', () => {
  test('a real delta is shown with a "vs. last viewed run" caption', async ({ page, context }) => {
    await context.addInitScript(() => {
      window.localStorage.setItem('MET_score_contoso.onmicrosoft.com', '30');
    });
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await expect(page.locator('#score-delta')).toHaveText('+10');
    await expect(page.locator('#score-delta-caption')).toBeVisible();
    await expect(page.locator('#score-delta-caption')).toHaveText(/vs\. last viewed run/i);
  });

  test('no cached score means no delta and the caption stays hidden', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    await expect(page.locator('#score-delta')).toHaveText('');
    await expect(page.locator('#score-delta-caption')).toBeHidden();
  });
});

test.describe('G-13 item 8: Top 5 rows drop the redundant result badge', () => {
  test('every Top 5 row shows a severity chip and no result badge', async ({ page }) => {
    await page.goto('/report.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();

    const rows = page.locator('.top5-row');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThan(0);
    await expect(page.locator('.top5-row .result-badge')).toHaveCount(0);
    await expect(page.locator('.top5-row .sev-pill')).toHaveCount(rowCount);
  });
});
