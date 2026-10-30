import { expect } from '@playwright/test'
import { loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M10 decision 37 (PDK-145): an auditor opens Evidence exports from the navigation and from the audit log, sees
// the list and the signing keys, and the New export dialog validates the range and the purpose before it sends the
// browser to the step-up. The temporary user has no TOTP key (plan amendment A7), so the spec stops at the redirect
// start; the request after the step-up is covered by the component tests.
test('auditor opens the evidence exports, the dialog validates and starts the step-up', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const auditor = await tempUser('e2e-exports-auditor', 'paddock.acme.auditors')
  try {
    await loginWithPassword(page, auditor.username, auditor.password)
    await expect(page).toHaveURL(/\/audit$/)
    await page.getByTestId('audit-exports-link').click()
    await expect(page).toHaveURL(/\/audit\/exports$/)
    await mainNav(page).getByRole('link', { name: 'Evidence integrity' }).click()
    await page.getByTestId('audit-exports-link').click()
    await expect(page.getByRole('heading', { level: 1, name: 'Evidence exports' })).toBeVisible()
    await expect(mainNav(page).getByRole('link', { name: 'Evidence exports' })).toBeVisible()

    const list = page.getByTestId('audit-exports')
    await expect(list.getByTestId('list-page-size')).toBeVisible()
    await expect(page.getByTestId('audit-keys').getByRole('heading', { level: 2, name: 'Signing keys' })).toBeVisible()
    await expect(page.getByTestId('audit-keys')).toContainText('Compare with the fingerprint your ISMS recorded')
    await expectAccessible(page)

    await page.getByTestId('new-export').click()
    const dialog = page.getByTestId('export-dialog')
    await expect(dialog.getByRole('heading', { level: 2, name: 'New evidence export' })).toBeVisible()
    await dialog.getByTestId('export-submit').click()
    await expect(dialog).toContainText('Enter the purpose.')
    await dialog.getByTestId('export-from').locator('input').fill('2026-10-03')
    await dialog.getByTestId('export-to').locator('input').fill('2026-10-02')
    await dialog.getByTestId('export-purpose').locator('textarea').fill('E2E audit')
    await dialog.getByTestId('export-submit').click()
    await expect(dialog).toContainText('The last day must not be before the first day.')
    await expectAccessible(page)

    await dialog.getByTestId('export-to').locator('input').fill('2026-10-04')
    const stepUp = page.waitForRequest((r) => r.url().includes('/api/auth/stepup'))
    await dialog.getByTestId('export-submit').click()
    expect((await stepUp).url()).toContain(encodeURIComponent('/audit/exports'))
    expect(csp).toEqual([])
  } finally {
    await auditor.remove()
  }
})
