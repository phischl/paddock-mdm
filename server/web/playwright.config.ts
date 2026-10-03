import { defineConfig, devices } from '@playwright/test'

// End-to-end tests against the running development stack (`make up dev-seed e2e`).
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.PADDOCK_E2E_BASE_URL ?? 'https://admin.paddock.localhost:8443',
    // The development stack uses Caddy's internal CA.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
