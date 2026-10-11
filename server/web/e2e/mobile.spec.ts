import { expect, type Page } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

test.use({ viewport: { width: 390, height: 844 } })

async function expectNoHorizontalScroll(page: Page, path: string): Promise<void> {
  const { scrollWidth, innerWidth } = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth,
  }))
  expect(scrollWidth, path).toBeLessThanOrEqual(innerWidth)
}

// Plan M7c decision 35 (AC10): at 390 px no page scrolls horizontally, lists are cards with the hostname and a
// status chip, and the filters open in a sheet that applies to the URL.
test('organization admin uses the portal on a phone', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const devices = await (await page.request.get('/api/v1/devices?page_size=10&sort=hostname')).json() as { items: { id: string; hostname: string }[] }
  expect(devices.items.length).toBeGreaterThan(0)
  const device = devices.items[0]

  for (const path of ['/', '/devices', `/devices/${device.id}`, '/attention', '/audit', '/vulnerabilities', '/settings/updates']) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0)
    await expectNoHorizontalScroll(page, path)
  }

  // The device list is a list of cards: the hostname and its status chip.
  await page.goto('/devices')
  const card = page.getByTestId('device-list').locator('.pd-card').filter({ hasText: device.hostname })
  await expect(card.getByRole('link', { name: device.hostname })).toBeVisible()
  await expect(card.locator('.pd-chip').first()).toBeVisible()

  // The filters open in a sheet; applying keeps them in the URL and the button counts them.
  await page.getByTestId('list-filters-open').click()
  const sheet = page.getByTestId('list-filter-sheet')
  await expect(sheet).toBeVisible()
  await sheet.getByTestId('list-filter-state').click()
  await page.getByRole('option', { name: 'Active' }).click()
  await page.keyboard.press('Escape')
  await sheet.getByTestId('list-filters-apply').click()
  await expect(sheet).toBeHidden()
  await expect(page).toHaveURL(/[?&]state=active/)
  await expect(page.getByTestId('list-filters-open')).toContainText('(1)')
  await expectNoHorizontalScroll(page, '/devices?state=active')
  await expectAccessible(page)

  // The device page drops the pane and offers the way back.
  await page.goto(`/devices/${device.id}`)
  await expect(page.getByTestId('device-pane')).toBeHidden()
  await expect(page.getByRole('link', { name: 'Back to devices' })).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
