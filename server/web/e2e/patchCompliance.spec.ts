import { expect } from '@playwright/test'
import { loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M13c decision 18 (PDK-814): the auditor opens the patch compliance report from the navigation, sees the cards
// and the sections of the state at generation (no period) and downloads the CSV export under the file name the server chose; the patch
// SLA form is read-only for the auditor.
test('auditor reads the patch compliance report and exports it', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const auditor = await tempUser('e2e-patch-auditor', 'paddock.acme.auditors')
  try {
    await loginWithPassword(page, auditor.username, auditor.password)
    await mainNav(page).getByRole('link', { name: 'Patch compliance' }).click()
    await expect(page).toHaveURL(/\/patch-compliance$/)
    await expect(page.getByRole('heading', { level: 1, name: 'Patch compliance' })).toBeVisible()
    for (const key of ['devices', 'compliant', 'breached', 'sla']) {
      await expect(page.getByTestId(`kpi-${key}`)).toBeVisible()
    }
    for (const key of ['severity', 'groups', 'breaches', 'catalog']) {
      await expect(page.getByTestId(`review-${key}`)).toBeVisible()
    }
    await expect(page.getByTestId('patch-state-at')).toContainText('State at')
    await expect(page.getByTestId('preset-30')).toHaveCount(0)
    await expectAccessible(page)

    const download = page.waitForEvent('download')
    await page.getByTestId('export-csv').click()
    expect((await download).suggestedFilename()).toMatch(/^paddock-patch-compliance-acme-\d{4}-\d{2}-\d{2}\.csv$/)

    await page.goto('/settings/patch-sla')
    await expect(page.getByRole('heading', { level: 1, name: 'Patch SLA' })).toBeVisible()
    await expect(page.getByTestId('patch-sla-read-only')).toBeVisible()
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    await auditor.remove()
  }
})
