const base = require('@playwright/test');

// Every test runs against a page whose uncaught errors are fatal: a report that throws
// during render still "looks" fine to a string-level assertion but is dead in a browser.
const test = base.test.extend({
  page: async ({ page }, use) => {
    const failures = [];
    page.on('pageerror', (error) => failures.push(`pageerror: ${error.message}`));
    page.on('console', (message) => {
      if (message.type() === 'error') failures.push(`console.error: ${message.text()}`);
    });

    await use(page);

    base.expect(failures, 'report must render without uncaught page errors').toEqual([]);
  },
});

const { expect } = base;

// Mirrors Tests/Html/New-METReportFixture.ps1 -Scenario Rich.
const FIXTURE = {
  total: 9,
  perCategory: { MDO: 3, EXO: 3, Teams: 3 },
  initialScore: 40,
  initialBand: 'Poor',
};

async function visibleCardIds(page) {
  return page.locator('#cards-container .card:visible').evaluateAll((cards) =>
    cards.map((card) => card.dataset.checkId)
  );
}

module.exports = { test, expect, FIXTURE, visibleCardIds };
