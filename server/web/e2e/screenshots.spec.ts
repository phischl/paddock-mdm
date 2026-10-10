import { expect, type Page } from '@playwright/test'
import { login } from './auth'
import { test } from './cleanup'

// README screenshots (plan M6b decision 6, amended by plan M7c §6.9), only with PADDOCK_E2E_SCREENSHOTS=1: written to
// docs/assets/screenshots/ as <name>-light.png and <name>-dark.png at 1440×900. The visual review set (plan M7c step
// 10) goes to test-results/visual/<page>-<width>-<theme>.png and is not committed. The account keeps the system theme
// so the emulated colour scheme decides.
const dir = '../../docs/assets/screenshots'
const visual = 'test-results/visual'
const themes = ['light', 'dark'] as const

async function settle(page: Page, path: string, heading?: string): Promise<void> {
  await page.goto(path)
  if (heading) await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible()
  else await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0)
}

async function firstDevice(page: Page): Promise<{ id: string; hostname: string }> {
  const res = await page.request.get('/api/v1/devices?page_size=10&sort=hostname&state=active')
  const items = ((await res.json()) as { items: { id: string; hostname: string }[] }).items
  expect(items.length).toBeGreaterThan(0)
  return items[0]
}

async function systemTheme(page: Page): Promise<void> {
  const res = await page.request.patch('/api/v1/me', { headers: { 'X-Paddock-CSRF': '1' }, data: { theme: 'system' } })
  expect(res.status()).toBe(200)
}

test('README screenshots and the visual review set', async ({ page }) => {
  test.skip(!process.env.PADDOCK_E2E_SCREENSHOTS, 'set PADDOCK_E2E_SCREENSHOTS=1 to write the README screenshots')
  test.setTimeout(300_000)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await systemTheme(page)
  const device = await firstDevice(page)

  for (const theme of themes) {
    await page.emulateMedia({ colorScheme: theme })
    await page.setViewportSize({ width: 1440, height: 900 })
    for (const [path, heading, name] of [
      ['/', 'Overview', 'overview'],
      ['/devices', 'Devices', 'devices'],
      [`/devices/${device.id}`, device.hostname, 'device'],
      ['/audit', 'Audit log', 'audit'],
    ] as const) {
      await settle(page, path, heading)
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      await page.screenshot({ path: `${dir}/${name}-${theme}.png` })
    }

    for (const width of [390, 1280, 1920]) {
      await page.setViewportSize({ width, height: width < 600 ? 844 : 900 })
      for (const [path, name] of [
        ['/', 'overview'], ['/devices', 'devices'], [`/devices/${device.id}`, 'device'], ['/attention', 'attention'], ['/audit', 'audit'],
      ] as const) {
        await settle(page, path)
        await page.screenshot({ path: `${visual}/${name}-${width}-${theme}.png`, fullPage: true })
      }
    }
  }
})
