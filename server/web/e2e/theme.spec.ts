import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

// The theme preference lives on the account (plan M7c decision 1, ADR 0023): the user menu stores it, GET /api/v1/me
// returns it, a reload keeps it, and "System" follows the operating system's preference.
test('organization admin stores the theme on the account', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const html = page.locator('html')
  const reset = async () => {
    const res = await page.request.patch('/api/v1/me', { headers: { 'X-Paddock-CSRF': '1' }, data: { theme: 'system' } })
    expect(res.status()).toBe(200)
  }
  try {
    await reset()
    await page.emulateMedia({ colorScheme: 'light' })
    await page.reload()
    await expect(html).toHaveAttribute('data-theme', 'light')

    await openUserMenu(page)
    await page.getByTestId('theme-menu').click()
    await page.getByTestId('theme-dark').click()
    await expect(html).toHaveAttribute('data-theme', 'dark')
    await expect(page.getByTestId('theme-toggle')).toHaveAccessibleName('Switch to the light theme')
    const me = await (await page.request.get('/api/v1/me')).json()
    expect(me.theme).toBe('dark')
    await expectAccessible(page)

    await page.reload()
    await expect(html).toHaveAttribute('data-theme', 'dark')

    // The app-bar toggle sets an explicit preference.
    await page.getByTestId('theme-toggle').click()
    await expect(html).toHaveAttribute('data-theme', 'light')
    expect((await (await page.request.get('/api/v1/me')).json()).theme).toBe('light')

    // System follows prefers-color-scheme.
    await openUserMenu(page)
    await page.getByTestId('theme-menu').click()
    await page.getByTestId('theme-system').click()
    expect((await (await page.request.get('/api/v1/me')).json()).theme).toBe('system')
    await page.emulateMedia({ colorScheme: 'dark' })
    await page.reload()
    await expect(html).toHaveAttribute('data-theme', 'dark')
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    await reset()
  }
})
