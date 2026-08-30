// Resolves the preinstalled Chromium binary. CI images and this container ship the
// browser under PLAYWRIGHT_BROWSERS_PATH with PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1, so
// `npx playwright install` must never be needed - point Playwright at the real binary.
const fs = require('fs');
const path = require('path');

function resolveChromiumExecutable() {
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (!root || !fs.existsSync(root)) return undefined;

  const candidates = [];
  const direct = path.join(root, 'chromium');
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) candidates.push(direct);

  for (const entry of fs.readdirSync(root)) {
    if (entry.startsWith('chromium-')) {
      candidates.push(path.join(root, entry, 'chrome-linux', 'chrome'));
      candidates.push(path.join(root, entry, 'chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'));
      candidates.push(path.join(root, entry, 'chrome-win', 'chrome.exe'));
    }
  }

  return candidates.find((candidate) => fs.existsSync(candidate));
}

module.exports = { resolveChromiumExecutable };
