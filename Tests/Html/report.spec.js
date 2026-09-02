const { test, expect, FIXTURE, visibleCardIds } = require('./fixtures');

test.beforeEach(async ({ page }) => {
  await page.goto('/report.html');
  await expect(page.locator('#cards-container .card').first()).toBeVisible();
});

test.describe('score banner', () => {
  test('renders the server-calculated posture score and band', async ({ page }) => {
    await expect(page.locator('#donut-score-text')).toHaveText(String(FIXTURE.initialScore));
    await expect(page.locator('#score-band')).toHaveText(FIXTURE.initialBand);
  });

  test('summary counters match the fixture result set', async ({ page }) => {
    await expect(page.locator('#sum-fail')).toHaveText('2');
    await expect(page.locator('#sum-warn')).toHaveText('2');
    await expect(page.locator('#sum-pass')).toHaveText('3');
    await expect(page.locator('#sum-info')).toHaveText('1');
    await expect(page.locator('#sum-err')).toHaveText('1');
  });

  test('renders one donut segment per non-empty result bucket', async ({ page }) => {
    await expect(page.locator('#donut-segments circle')).toHaveCount(5);
  });
});

test.describe('tabs', () => {
  test('tab counts are correct on load', async ({ page }) => {
    await expect(page.locator('#tc-all')).toHaveText(String(FIXTURE.total));
    await expect(page.locator('#tc-mdo')).toHaveText(String(FIXTURE.perCategory.MDO));
    await expect(page.locator('#tc-exo')).toHaveText(String(FIXTURE.perCategory.EXO));
    await expect(page.locator('#tc-teams')).toHaveText(String(FIXTURE.perCategory.Teams));
    await expect(page.locator('#tc-accepted')).toHaveText('0');
    await expect(page.locator('#tc-controls')).toHaveText(String(FIXTURE.total));
  });

  for (const category of ['MDO', 'EXO', 'Teams']) {
    test(`the ${category} tab shows only ${category} cards`, async ({ page }) => {
      await page.locator(`.tab[data-tab="${category}"]`).click();
      const ids = await visibleCardIds(page);
      expect(ids).toHaveLength(FIXTURE.perCategory[category]);
      for (const id of ids) {
        expect(id.startsWith(`MET-${category}`)).toBeTruthy();
      }
      await expect(page.locator('#result-count')).toHaveText(
        `Showing ${FIXTURE.perCategory[category]} of ${FIXTURE.perCategory[category]} checks`
      );
    });
  }

  test('the All tab shows every card and the Top 5 section', async ({ page }) => {
    await page.locator('.tab[data-tab="MDO"]').click();
    await page.locator('.tab[data-tab="All"]').click();
    expect(await visibleCardIds(page)).toHaveLength(FIXTURE.total);
    await expect(page.locator('#top5-section')).toBeVisible();
  });

  test('the Accepted tab is empty before anything is accepted', async ({ page }) => {
    await page.locator('.tab[data-tab="Accepted"]').click();
    expect(await visibleCardIds(page)).toHaveLength(0);
    await expect(page.locator('#no-results')).toBeVisible();
  });

  test('the Top 5 tab hides the cards and expands the remediation list', async ({ page }) => {
    await page.locator('.tab[data-tab="Top5"]').click();
    await expect(page.locator('#cards-container')).toBeHidden();
    await expect(page.locator('#top5-body')).toHaveClass(/open/);
    // 2 Fail + 2 Warning in the fixture, all actionable.
    await expect(page.locator('.top5-row')).toHaveCount(4);
    await expect(page.locator('.top5-row').first().locator('.top5-id')).toHaveText('MET-EXO001');
  });

  test('the All Controls tab renders the reference table instead of cards', async ({ page }) => {
    await page.locator('.tab[data-tab="Controls"]').click();
    await expect(page.locator('#ctrl-ref')).toHaveClass(/visible/);
    await expect(page.locator('#cards-container')).toBeHidden();
    await expect(page.locator('#ctrl-ref .ctrl-row')).toHaveCount(FIXTURE.total);
    await expect(page.locator('#result-count')).toHaveText(`${FIXTURE.total} controls`);
  });
});

test.describe('search and filters', () => {
  const searches = [
    { term: 'MET-EXO001', field: 'CheckId', expected: ['MET-EXO001'] },
    { term: 'attachments', field: 'Name', expected: ['MET-MDO002'] },
    { term: 'finance@contoso.com', field: 'AffectedObject', expected: ['MET-EXO012'] },
    { term: 'bypass the lobby', field: 'Finding', expected: ['MET-Teams003'] },
  ];

  for (const { term, field, expected } of searches) {
    test(`search filters on ${field}`, async ({ page }) => {
      await page.locator('#search').fill(term);
      expect((await visibleCardIds(page)).sort()).toEqual(expected.sort());
      await expect(page.locator('#result-count')).toHaveText(
        `Showing ${expected.length} of ${FIXTURE.total} checks`
      );
    });
  }

  test('search is case-insensitive and clears back to the full set', async ({ page }) => {
    await page.locator('#search').fill('SAFE LINKS');
    expect(await visibleCardIds(page)).toEqual(['MET-MDO001']);
    await page.locator('#search').fill('');
    expect(await visibleCardIds(page)).toHaveLength(FIXTURE.total);
  });

  test('a search matching nothing shows the empty state', async ({ page }) => {
    await page.locator('#search').fill('no-such-check-anywhere');
    expect(await visibleCardIds(page)).toHaveLength(0);
    await expect(page.locator('#no-results')).toBeVisible();
    await expect(page.locator('#result-count')).toHaveText(`Showing 0 of ${FIXTURE.total} checks`);
  });

  test('the severity filter narrows to a single severity', async ({ page }) => {
    await page.locator('#sev-filter').selectOption('Critical');
    expect(await visibleCardIds(page)).toEqual(['MET-EXO001']);

    await page.locator('#sev-filter').selectOption('High');
    expect((await visibleCardIds(page)).sort()).toEqual(['MET-MDO001', 'MET-MDO009', 'MET-Teams003']);
  });

  test('the result filter narrows to a single result value', async ({ page }) => {
    await page.locator('#result-filter').selectOption('Fail');
    expect((await visibleCardIds(page)).sort()).toEqual(['MET-EXO001', 'MET-MDO001']);

    await page.locator('#result-filter').selectOption('Pass');
    expect((await visibleCardIds(page)).sort()).toEqual(['MET-EXO012', 'MET-MDO009', 'MET-Teams006']);
  });

  test('the Error filter isolates checks that failed to run, excluding them from their own Result option', async ({ page }) => {
    await page.locator('#result-filter').selectOption('Error');
    expect(await visibleCardIds(page)).toEqual(['MET-Teams014']);

    // MET-Teams014's underlying Result is NotApplicable, but it errored - it must not
    // double up under the NotApplicable option too (Error is a mutually exclusive bucket).
    await page.locator('#result-filter').selectOption('NotApplicable');
    expect(await visibleCardIds(page)).toEqual([]);
  });

  test('severity, result and search combine with AND logic', async ({ page }) => {
    await page.locator('#sev-filter').selectOption('High');
    await page.locator('#result-filter').selectOption('Fail');
    expect(await visibleCardIds(page)).toEqual(['MET-MDO001']);

    await page.locator('#search').fill('dmarc');
    expect(await visibleCardIds(page)).toHaveLength(0);

    await page.locator('#search').fill('safe links');
    expect(await visibleCardIds(page)).toEqual(['MET-MDO001']);
  });

  test('filters compose with the category tab', async ({ page }) => {
    await page.locator('.tab[data-tab="Teams"]').click();
    await page.locator('#result-filter').selectOption('Pass');
    expect(await visibleCardIds(page)).toEqual(['MET-Teams006']);
    await expect(page.locator('#result-count')).toHaveText('Showing 1 of 3 checks');
  });
});

test.describe('card expansion', () => {
  test('cards start collapsed and expand on click', async ({ page }) => {
    const passCard = page.locator('.card[data-check-id="MET-MDO009"]');
    const body = passCard.locator('.card-body');

    await expect(body).not.toHaveClass(/open/);
    await expect(passCard.locator('.card-header')).toHaveAttribute('aria-expanded', 'false');

    await passCard.locator('.card-header').click();
    await expect(body).toHaveClass(/open/);
    await expect(passCard.locator('.card-header')).toHaveAttribute('aria-expanded', 'true');

    await passCard.locator('.card-header').click();
    await expect(body).not.toHaveClass(/open/);
  });

  test('opening a Fail card auto-expands How to fix, and the toggle still works', async ({ page }) => {
    const failCard = page.locator('.card[data-check-id="MET-MDO001"]');
    await failCard.locator('.card-header').click();

    const fixContent = failCard.locator('.fix-content');
    await expect(fixContent).toHaveClass(/open/);
    await expect(fixContent.locator('ol li')).toHaveCount(3);

    await failCard.locator('.fix-toggle').click();
    await expect(fixContent).not.toHaveClass(/open/);
    await failCard.locator('.fix-toggle').click();
    await expect(fixContent).toHaveClass(/open/);
  });

  test('an errored check surfaces its Error text in the fix panel', async ({ page }) => {
    const errCard = page.locator('.card[data-check-id="MET-Teams014"]');
    await errCard.locator('.card-header').click();
    await errCard.locator('.fix-toggle').click();
    await expect(errCard.locator('.card-error')).toContainText(
      'Authentication needed. Please call Connect-MgGraph.'
    );
  });

  test('Expand All opens every visible card', async ({ page }) => {
    await page.locator('#btn-collapse-all').click();
    const open = await page.locator('#cards-container .card .card-body.open').count();
    expect(open).toBe(FIXTURE.total);
    await page.locator('#btn-collapse-all').click();
    await expect(page.locator('#cards-container .card .card-body.open')).toHaveCount(0);
  });

  test('an accepted check that still carries an Error keeps the ERROR badge, not ACCEPTED', async ({ page }) => {
    // Invoke-METTriage synthesizes a Fail+Error result for a check that crashed, so a crashed
    // check CAN be risk-accepted through the normal Fail flow like any other finding - at which
    // point it must not silently lose its ERROR badge and go back to looking like a resolved risk.
    // Simulated here via localStorage (the mechanism Accept Risk itself writes to) since the
    // fixture's only Error case, MET-Teams014, is NotApplicable and has no Accept Risk button.
    await page.evaluate(() => {
      localStorage.setItem('MET_accepted_contoso.onmicrosoft.com_MET-Teams014', 'Pre-existing acceptance');
    });
    await page.reload();
    await page.locator('.tab[data-tab="Accepted"]').click();

    const card = page.locator('.card[data-check-id="MET-Teams014"]');
    await expect(card).toBeVisible();
    await expect(card.locator('.result-badge')).toHaveText('ERROR');
    await expect(card.locator('.result-badge')).toHaveClass(/rb-error/);
    await card.locator('.card-header').click();
    await expect(card.locator('.btn-undo')).toBeVisible();
  });
});

test.describe('accept risk', () => {
  const CHECK = 'MET-EXO001';

  async function acceptRisk(page, checkId, justification) {
    await page.locator(`.card[data-check-id="${checkId}"] .card-header`).click();
    await page.locator(`.btn-accept[data-checkid="${checkId}"]`).click();
    await expect(page.locator('#modal-overlay')).toHaveClass(/open/);
    await expect(page.locator('#modal-desc')).toContainText(checkId);
    await expect(page.locator('#modal-confirm')).toBeDisabled();
    await page.locator('#modal-text').fill(justification);
    await expect(page.locator('#modal-confirm')).toBeEnabled();
    await page.locator('#modal-confirm').click();
    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);
  }

  test('accepting a Fail moves the card, rescores, and survives a reload', async ({ page }) => {
    await acceptRisk(page, CHECK, 'Compensating control: inbound gateway enforces DMARC.');

    await expect(page.locator('#tc-accepted')).toHaveText('1');
    await expect(page.locator('#tc-all')).toHaveText(String(FIXTURE.total - 1));
    await expect(page.locator('#tc-exo')).toHaveText(String(FIXTURE.perCategory.EXO - 1));
    expect(await visibleCardIds(page)).not.toContain(CHECK);

    // Score excludes the accepted control: 40 -> 59.
    await expect(page.locator('#donut-score-text')).toHaveText('59');

    await page.locator('.tab[data-tab="Accepted"]').click();
    expect(await visibleCardIds(page)).toEqual([CHECK]);
    await expect(
      page.locator(`.card[data-check-id="${CHECK}"] .result-badge`)
    ).toHaveText('ACCEPTED');

    await page.reload();
    await expect(page.locator('#tc-accepted')).toHaveText('1');
    await expect(page.locator('#donut-score-text')).toHaveText('59');
    await page.locator('.tab[data-tab="Accepted"]').click();
    expect(await visibleCardIds(page)).toEqual([CHECK]);
  });

  test('undo returns the card to its category tab and restores the score', async ({ page }) => {
    await acceptRisk(page, CHECK, 'Temporary acceptance pending DNS change.');
    await page.locator('.tab[data-tab="Accepted"]').click();

    await page.locator(`.card[data-check-id="${CHECK}"] .card-header`).click();
    await page.locator(`.btn-undo[data-checkid="${CHECK}"]`).click();

    await expect(page.locator('#tc-accepted')).toHaveText('0');
    expect(await visibleCardIds(page)).toHaveLength(0);

    await page.locator('.tab[data-tab="All"]').click();
    expect(await visibleCardIds(page)).toContain(CHECK);
    await expect(page.locator('#donut-score-text')).toHaveText(String(FIXTURE.initialScore));
    await expect(
      page.locator(`.card[data-check-id="${CHECK}"] .result-badge`)
    ).toHaveText('FAIL');
  });

  test('cancelling the modal accepts nothing', async ({ page }) => {
    await page.locator(`.card[data-check-id="${CHECK}"] .card-header`).click();
    await page.locator(`.btn-accept[data-checkid="${CHECK}"]`).click();
    await page.locator('#modal-text').fill('never confirmed');
    await page.locator('#modal-cancel').click();

    await expect(page.locator('#modal-overlay')).not.toHaveClass(/open/);
    await expect(page.locator('#tc-accepted')).toHaveText('0');
    await expect(page.locator('#donut-score-text')).toHaveText(String(FIXTURE.initialScore));
  });

  test('accepting removes the control from the Top 5 remediation list', async ({ page }) => {
    await expect(page.locator('.top5-row')).toHaveCount(4);
    await acceptRisk(page, CHECK, 'Risk owned by the messaging team.');
    await expect(page.locator('.top5-row')).toHaveCount(3);
    const remaining = await page.locator('.top5-row .top5-id').allTextContents();
    expect(remaining).not.toContain(CHECK);
  });
});

test.describe('offline self-containment', () => {
  test('makes no network requests beyond the document itself', async ({ page }) => {
    const requests = [];
    page.on('request', (request) => requests.push(request.url()));
    await page.goto('/report.html');
    await page.locator('.tab[data-tab="Controls"]').click();
    await expect(page.locator('#ctrl-ref')).toHaveClass(/visible/);

    const external = requests.filter((url) => !url.endsWith('/report.html'));
    expect(external, `unexpected sub-resource requests: ${external.join(', ')}`).toEqual([]);
  });
});

// Injection safety at the DOM level. A string-level assertion cannot prove this: the
// payload legitimately appears inside the embedded CHECKS JSON, and the question is
// only ever whether the renderer turns it into markup. Scheme validation on a
// reference URL is not enough on its own - new URL() accepts quotes and angle
// brackets in a path, so an https: URL can still close an href attribute.
test.describe('injection safety', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/report-hostile.html');
    await expect(page.locator('#cards-container .card').first()).toBeVisible();
  });

  test('no payload from any check field becomes a live element', async ({ page }) => {
    await page.locator('#btn-collapse-all').click();
    await expect(page.locator('img')).toHaveCount(0);
    await expect(page.locator('[onerror]')).toHaveCount(0);
  });

  test('no injected handler executes, on any tab', async ({ page }) => {
    for (const tab of ['all', 'mdo', 'exo', 'teams', 'controls']) {
      const locator = page.locator(`.tab[data-tab="${tab}"]`);
      if (await locator.count()) await locator.click();
    }
    const flags = await page.evaluate(() =>
      Object.keys(window).filter((key) => key.startsWith('__xss'))
    );
    expect(flags).toEqual([]);
  });

  test('a hostile reference URL is escaped rather than emitted raw', async ({ page }) => {
    const hrefs = await page
      .locator('a.btn-docs')
      .evaluateAll((anchors) => anchors.map((a) => a.getAttribute('href')));
    for (const href of hrefs) {
      expect(href).not.toContain('<img');
      expect(href).not.toContain('"');
    }
  });

  test('an unrecognised Result or Severity still renders a visible badge', async ({ page }) => {
    // Breakout payloads reduce to the 'unknown' class; without a base background the
    // badge would render white-on-white and the finding would be invisible.
    const badges = page.locator('#cards-container .sev-pill');
    await expect(badges.first()).toBeVisible();
    const background = await badges
      .first()
      .evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(background).not.toBe('rgba(0, 0, 0, 0)');
  });
});
