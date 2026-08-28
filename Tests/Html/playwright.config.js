const { defineConfig, devices } = require('@playwright/test');
const { resolveChromiumExecutable } = require('./browser-path');

const executablePath = resolveChromiumExecutable();
const PORT = Number(process.env.MET_HTML_PORT || 4173);

module.exports = defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.js',
  globalSetup: require.resolve('./global-setup'),
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    launchOptions: {},
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node serve.js',
    url: `http://127.0.0.1:${PORT}`,
    cwd: __dirname,
    reuseExistingServer: !process.env.CI,
    stdout: 'ignore',
    stderr: 'pipe',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1400, height: 900 },
        launchOptions: {
          ...(executablePath ? { executablePath } : {}),
          args: ['--no-sandbox', '--disable-dev-shm-usage'],
        },
      },
    },
  ],
});
