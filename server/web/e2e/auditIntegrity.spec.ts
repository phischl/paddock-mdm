import { expect } from '@playwright/test'
import { loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M8b gate V6 (decision 32): an auditor opens Evidence integrity from the navigation and sees the KPI strip and
// both lists with their pagination controls; the sort survives a reload in the URL; the page speaks German. An
// operator has no entry, and a direct visit shows the page's no-access state (the API answers 403). Temporary users
// keep the dev users' locale untouched.
test('auditor sees the evidence integrity, sorted state survives a reload, German terms', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const auditor = await tempUser('e2e-integrity-auditor', 'paddock.acme.auditors')
  try {
    await loginWithPassword(page, auditor.username, auditor.password)
    await expect(page).toHaveURL(/\/audit$/)
    await mainNav(page).getByRole('link', { name: 'Evidence integrity' }).click()
    await expect(page).toHaveURL(/\/audit\/integrity$/)
    await expect(page.getByRole('heading', { level: 1, name: 'Evidence integrity' })).toBeVisible()
    for (const kpi of ['sealed-through', 'manifests', 'last-run', 'last-failure']) {
      await expect(page.getByTestId('audit-integrity-kpis').getByTestId('kpi-' + kpi)).toBeVisible()
    }
    const runs = page.getByTestId('verification-runs')
    const manifests = page.getByTestId('audit-manifests')
    for (const list of [runs, manifests]) {
      await expect(list.getByTestId('list-page-size')).toBeVisible()
      await expect(list.getByTestId('list-range')).toBeVisible()
    }
    await expectAccessible(page)

    await runs.getByRole('columnheader', { name: 'Result' }).click()
    await expect(page).toHaveURL(/runs\.sort=ok/)
    await page.reload()
    await expect(page).toHaveURL(/runs\.sort=ok/)
    await expect(page.getByRole('heading', { level: 1, name: 'Evidence integrity' })).toBeVisible()

    await openUserMenu(page)
    await page.getByTestId('language-menu').click()
    await page.getByTestId('language-de').click()
    await expect(page.locator('html')).toHaveAttribute('lang', 'de')
    await expect(page.getByRole('heading', { level: 1, name: 'Nachweisintegrität' })).toBeVisible()
    await expect(mainNav(page, 'Hauptnavigation').getByRole('link', { name: 'Nachweisintegrität' })).toBeVisible()
    await expect(page.getByRole('heading', { level: 2, name: 'Prüfläufe' })).toBeVisible()
    await expect(page.getByRole('heading', { level: 2, name: 'Manifeste' })).toBeVisible()
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    await auditor.remove()
  }
})

test('operator has no evidence integrity entry and gets the no-access state', async ({ page }) => {
  const csp = watchCSP(page)
  const operator = await tempUser('e2e-integrity-operator', 'paddock.acme.operators')
  try {
    await loginWithPassword(page, operator.username, operator.password)
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    await expect(mainNav(page).getByRole('link', { name: 'Evidence integrity' })).toHaveCount(0)
    const res = await page.request.get('/api/v1/audit/integrity')
    expect(res.status()).toBe(403)
    expect((await res.json()).code).toBe('forbidden')
    await page.goto('/audit/integrity')
    await expect(page.getByTestId('audit-integrity-forbidden')).toContainText('No access to the evidence integrity')
    await expect(page.getByTestId('verification-runs')).toHaveCount(0)
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    await operator.remove()
  }
})
