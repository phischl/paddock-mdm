import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The keyboard model (plan M7c decision 17): the palette reaches pages and devices, g-sequences navigate, the help
// dialog lists everything, shortcuts are inert in inputs and can be switched off; no shortcut is destructive.
test('organization admin works the portal from the keyboard', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await page.goto('/devices')
  await expect(page.getByRole('heading', { level: 1, name: 'Devices' })).toBeVisible()

  // Ctrl K opens the palette with the pages; a seeded device is found from two characters and Enter opens it.
  await page.keyboard.press('Control+k')
  const palette = page.getByTestId('command-palette')
  await expect(palette).toBeVisible()
  await expect(page.getByTestId('palette-input')).toBeFocused()
  await expect(palette.getByRole('option', { name: 'Device groups' })).toBeVisible()
  await expectAccessible(page)
  const devices = ((await (await page.request.get('/api/v1/devices?page_size=10&sort=hostname')).json()) as { items: { id: string; hostname: string }[] }).items
  if (devices.length > 0) {
    await page.getByTestId('palette-input').fill(devices[0].hostname.slice(0, 6))
    const option = palette.getByRole('option', { name: devices[0].hostname }).first()
    await expect(option).toBeVisible()
    await option.click()
    await expect(page).toHaveURL(new RegExp('/devices/' + devices[0].id))
  } else {
    await page.keyboard.press('Escape')
  }
  await expect(palette).toBeHidden()

  // g a goes to the attention list; ? opens the help dialog with every shortcut.
  await page.keyboard.press('g')
  await page.keyboard.press('a')
  await expect(page).toHaveURL(/\/attention$/)
  await page.keyboard.press('Shift+?')
  const help = page.getByTestId('shortcut-help')
  await expect(help).toBeVisible()
  await expect(help.getByRole('button', { name: 'Close' })).toBeFocused()
  await expect(help).toContainText('Go to Devices')
  await expectAccessible(page)
  await page.keyboard.press('Escape')
  await expect(help).toBeHidden()

  // Inert in an input: typing g d into the search field does not navigate.
  await page.goto('/devices')
  await page.getByTestId('list-search').getByRole('searchbox').focus()
  await page.keyboard.type('gd')
  await expect(page).toHaveURL(/\/devices/)
  await page.keyboard.press('Escape')

  // The switch turns single-key shortcuts off; Ctrl K keeps working.
  await page.goto('/attention')
  await page.keyboard.press('Shift+?')
  await help.getByLabel('Single-key shortcuts').click()
  await help.getByRole('button', { name: 'Close' }).click()
  try {
    await page.keyboard.press('g')
    await page.keyboard.press('d')
    await page.waitForTimeout(500)
    await expect(page).toHaveURL(/\/attention$/)
    await page.keyboard.press('Control+k')
    await expect(palette).toBeVisible()
    await page.keyboard.press('Escape')
  } finally {
    await page.evaluate(() => localStorage.setItem('paddock.shortcuts.singleKey', 'true'))
  }
  expect(csp).toEqual([])
})
