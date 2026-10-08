import { expect } from '@playwright/test'
import { login } from './auth'
import { test } from './cleanup'

// README screenshots (plan M6b decision 6), only with PADDOCK_E2E_SCREENSHOTS=1: written to docs/assets/screenshots/
// in the light and the dark color scheme of the browser.
const dir = '../../docs/assets/screenshots'

for (const scheme of ['light', 'dark'] as const) {
  test(`README screenshots (${scheme})`, async ({ page }) => {
    test.skip(!process.env.PADDOCK_E2E_SCREENSHOTS, 'set PADDOCK_E2E_SCREENSHOTS=1 to write the README screenshots')
    await page.emulateMedia({ colorScheme: scheme })
    await page.setViewportSize({ width: 1440, height: 900 })
    await login(page, 'alice@acme.test', 'dev_alice_password')
    for (const [path, heading, name] of [
      ['/devices', 'Devices', 'devices'],
      ['/audit', 'Audit log', 'audit'],
      ['/vulnerabilities', 'Vulnerabilities', 'vulnerabilities'],
    ] as const) {
      await page.goto(path)
      await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible()
      await expect(page.locator('[aria-busy="true"]')).toHaveCount(0)
      await page.screenshot({ path: `${dir}/${name}-${scheme}.png` })
    }
  })
}
