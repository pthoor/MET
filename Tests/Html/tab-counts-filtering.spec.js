// G-7: updateTabCounts() counted allCards unconditionally, contradicting the spec's "Tab
// counts update in real-time as filters are applied." Searching for a term matching only
// one category left every tab badge at its unfiltered total while #result-count correctly
// reported the smaller matching count.
const { test, expect, FIXTURE } = require('./fixtures');

test.beforeEach(async ({ page }) => {
  await page.goto('/report.html');
  await expect(page.locator('#cards-container .card').first()).toBeVisible();
});

test.describe('tab counts respond to search/filter state', () => {
  test('unfiltered tab counts match the fixture totals', async ({ page }) => {
    await expect(page.locator('#tc-all')).toHaveText(String(FIXTURE.total));
    await expect(page.locator('#tc-mdo')).toHaveText(String(FIXTURE.perCategory.MDO));
    await expect(page.locator('#tc-exo')).toHaveText(String(FIXTURE.perCategory.EXO));
    await expect(page.locator('#tc-teams')).toHaveText(String(FIXTURE.perCategory.Teams));
  });

  test('searching a term unique to one check narrows every tab badge, agreeing with result-count', async ({ page }) => {
    // "dmarc" appears only in MET-EXO001's name/finding among the Rich fixture's 9 checks.
    await page.locator('#search').fill('dmarc');

    await expect(page.locator('#result-count')).toHaveText('Showing 1 of 9 checks');
    await expect(page.locator('#tc-all')).toHaveText('1');
    await expect(page.locator('#tc-exo')).toHaveText('1');
    await expect(page.locator('#tc-mdo')).toHaveText('0');
    await expect(page.locator('#tc-teams')).toHaveText('0');

    // Switching to the tab that still has a match keeps a card visible and its own badge
    // in sync with what is actually shown.
    await page.locator('.tab[data-tab="EXO"]').click();
    const visibleIds = await page.locator('#cards-container .card:visible').evaluateAll(
      (cards) => cards.map((card) => card.dataset.checkId)
    );
    expect(visibleIds).toEqual(['MET-EXO001']);
    await expect(page.locator('#tc-exo')).toHaveText('1');

    // Clearing the search restores every badge to its unfiltered total.
    await page.locator('#search').fill('');
    await expect(page.locator('#tc-all')).toHaveText(String(FIXTURE.total));
    await expect(page.locator('#tc-mdo')).toHaveText(String(FIXTURE.perCategory.MDO));
    await expect(page.locator('#tc-exo')).toHaveText(String(FIXTURE.perCategory.EXO));
    await expect(page.locator('#tc-teams')).toHaveText(String(FIXTURE.perCategory.Teams));
  });

  test('the result-filter dropdown also narrows tab badges', async ({ page }) => {
    // Rich fixture has exactly one Pass in each of MDO and EXO/Teams? Check: Pass results
    // are MET-MDO009 (MDO), MET-EXO012 (EXO), MET-Teams006 (Teams) - one per category.
    await page.locator('#result-filter').selectOption('Pass');

    await expect(page.locator('#tc-all')).toHaveText('3');
    await expect(page.locator('#tc-mdo')).toHaveText('1');
    await expect(page.locator('#tc-exo')).toHaveText('1');
    await expect(page.locator('#tc-teams')).toHaveText('1');
    await expect(page.locator('#result-count')).toHaveText('Showing 3 of 9 checks');
  });
});
