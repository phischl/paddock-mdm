import { expect, type Page } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

async function chooseTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
  await openUserMenu(page)
  await page.getByTestId('theme-menu').click()
  await page.getByTestId('theme-' + theme).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await page.keyboard.press('Escape')
}

// Plan M7c decision 36 (AC3): axe finds no serious or critical violation on the redesigned pages, the command
// palette and a confirm dialog, in the light and in the dark theme, each chosen through the user menu.
for (const theme of ['light', 'dark'] as const) {
  test(`the portal is accessible in the ${theme} theme`, async ({ page }) => {
    test.setTimeout(180_000)
    const csp = watchCSP(page)
    await login(page, 'alice@acme.test', 'dev_alice_password')
    try {
      await chooseTheme(page, theme)
      const devices = await (await page.request.get('/api/v1/devices?page_size=10&sort=hostname&state=active')).json() as { items: { id: string }[] }
      const pages = ['/', '/devices', '/attention', '/audit', '/vulnerabilities', '/settings/updates']
      if (devices.items[0]) pages.push(`/devices/${devices.items[0].id}`, `/devices/${devices.items[0].id}/access`)
      for (const path of pages) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
        await expectAccessible(page)
      }

      // The command palette.
      await page.goto('/')
      await page.keyboard.press('Control+k')
      await expect(page.getByRole('combobox')).toBeFocused()
      await expectAccessible(page)
      await page.keyboard.press('Escape')

      // A confirm dialog (Retire, opened from the danger zone and cancelled), with the focus on Cancel.
      if (devices.items[0]) {
        await page.goto(`/devices/${devices.items[0].id}`)
        await page.getByTestId('device-retire').click()
        const dialog = page.getByTestId('confirm-dialog')
        await expect(page.getByTestId('confirm-cancel')).toBeFocused()
        await expectAccessible(page)
        await page.getByTestId('confirm-cancel').click()
        await expect(dialog).toBeHidden()
      }
      expect(csp).toEqual([])
    } finally {
      const res = await page.request.patch('/api/v1/me', { headers: { 'X-Paddock-CSRF': '1' }, data: { theme: 'system' } })
      expect(res.status()).toBe(200)
    }
  })
}

// Between 600 and 1279 px the drawer starts as a rail, whose eagerly rendered tooltips the 1280 px runs above never
// show to axe (aria-tooltip-name).
test('the portal is accessible with the navigation as a rail', async ({ page }) => {
  const csp = watchCSP(page)
  await page.setViewportSize({ width: 960, height: 900 })
  await login(page, 'alice@acme.test', 'dev_alice_password')
  for (const path of ['/', '/devices']) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByTestId('nav-drawer')).toHaveClass(/v-navigation-drawer--rail/)
    await expectAccessible(page)
  }
  expect(csp).toEqual([])
})

// At phone width the overview tables scroll sideways; their containers must be reachable by keyboard
// (axe scrollable-region-focusable), which the wider runs above never trigger.
test('the overview is accessible at phone width', async ({ page }) => {
  const csp = watchCSP(page)
  await page.setViewportSize({ width: 375, height: 812 })
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  const audit = page.getByRole('region', { name: 'Recent audit activity table', exact: true })
  await audit.focus()
  await expect(audit).toBeFocused()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
