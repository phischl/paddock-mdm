import { expect } from '@playwright/test'
import { loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M12 decision 27 (PDK-755): the auditor opens the access review from the navigation, switches the period,
// expands a section and downloads the CSV export under the file name the server chose; the operator has no entry and
// is told so on a direct visit.
test('auditor reads the access review, changes the period and exports', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const auditor = await tempUser('e2e-review-auditor', 'paddock.acme.auditors')
  try {
    await loginWithPassword(page, auditor.username, auditor.password)
    await mainNav(page).getByRole('link', { name: 'Access review' }).click()
    await expect(page).toHaveURL(/\/access-review$/)
    await expect(page.getByRole('heading', { level: 1, name: 'Access review' })).toBeVisible()
    for (const key of ['roles', 'changes', 'accounts', 'tokens', 'reveals', 'sessions', 'destructive', 'breakglass']) {
      await expect(page.getByTestId(`review-${key}`)).toBeVisible()
    }

    await page.getByTestId('preset-90').click()
    await expect(page).toHaveURL(/days=90/)
    await page.getByTestId('review-reveals').getByRole('button').first().click()
    await expect(page.getByTestId('review-reveals').getByTestId('list-page-size')).toBeVisible()
    await expectAccessible(page)

    await page.getByTestId('custom-from').locator('input').fill('2025-01-01')
    await page.getByTestId('custom-to').locator('input').fill('2026-11-01')
    await page.getByTestId('custom-apply').click()
    await expect(page.getByTestId('review-period-error')).toHaveText('The period may span at most 400 days.')
    await page.getByTestId('preset-30').click()
    await expect(page).toHaveURL(/days=30/)
    await expect(page.getByTestId('review-period-error')).toBeHidden()

    const download = page.waitForEvent('download')
    await page.getByTestId('export-csv').click()
    expect((await download).suggestedFilename()).toMatch(/^paddock-access-review-acme-\d{4}-\d{2}-\d{2}-\d{4}-\d{2}-\d{2}\.csv$/)
    expect(csp).toEqual([])
  } finally {
    await auditor.remove()
  }
})

test('operator has no access review entry and is refused on a direct visit', async ({ page }) => {
  test.setTimeout(180_000)
  const operator = await tempUser('e2e-review-operator', 'paddock.acme.operators')
  try {
    await loginWithPassword(page, operator.username, operator.password)
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    await expect(mainNav(page).getByRole('link', { name: 'Access review' })).toHaveCount(0)
    await page.goto('/access-review')
    await expect(page.getByTestId('review-forbidden')).toBeVisible()
    await expectAccessible(page)
  } finally {
    await operator.remove()
  }
})
