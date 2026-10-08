import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// German smoke test (plan M6b decision 2): the language switch of the user menu persists on the account, and the
// portal — navigation, device list, audit page with its event texts — speaks German while audit codes stay English.
test('organization admin switches the portal to German', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  try {
    await page.getByTestId('language-menu').click()
    await page.getByTestId('language-de').click()
    await expect(page.locator('html')).toHaveAttribute('lang', 'de')
    await expect(page.getByTestId('user-role')).toHaveText('Organisationsadministrator')
    await expect(page.getByRole('button', { name: 'Abmelden' })).toBeVisible()

    // The choice is stored on the account, not in the browser: a reload keeps it.
    await page.goto('/devices')
    await expect(page.getByRole('heading', { level: 1, name: 'Geräte' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Letzter Kontakt' })).toBeVisible()
    await expect(page.getByRole('combobox', { name: 'Einträge pro Seite' })).toBeVisible()
    const nav = page.getByRole('navigation', { name: 'Hauptnavigation' })
    await expect(nav.getByRole('link', { name: 'Gerätegruppen' })).toBeVisible()
    await expect(nav.getByRole('link', { name: 'Audit-Protokoll' })).toBeVisible()
    await expectAccessible(page)

    // Stored as the English code admin.login, displayed in German.
    await page.goto('/audit')
    await expect(page.getByRole('heading', { level: 1, name: 'Audit-Protokoll' })).toBeVisible()
    await expect(async () => {
      await page.reload()
      await expect(page.getByText('alice@acme.test hat sich angemeldet', { exact: true }).first()).toBeVisible({ timeout: 1_000 })
    }).toPass({ timeout: 60_000 })
    const res = await page.request.get('/api/v1/audit-events?page_size=10&sort=-occurred_at&code=admin.login')
    expect(res.status()).toBe(200)
    const codes = ((await res.json()) as { items: { code: string }[] }).items.map((e) => e.code)
    expect(codes.length).toBeGreaterThan(0)
    expect(new Set(codes)).toEqual(new Set(['admin.login']))
    await expectAccessible(page)

    await page.getByTestId('language-menu').click()
    await page.getByTestId('language-en').click()
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await expect(page.getByRole('heading', { level: 1, name: 'Audit log' })).toBeVisible()
    expect(csp).toEqual([])
  } finally {
    // The other specs expect alice in English.
    await page.request.patch('/api/v1/me', { headers: { 'X-Paddock-CSRF': '1' }, data: { locale: 'en' } })
  }
})
