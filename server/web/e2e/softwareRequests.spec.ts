import { expect } from '@playwright/test'
import { login, loginWithPassword, tempUser } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M13c decision 10 (PDK-816): the software requests page follows the list contract (state filter in the URL) and
// is read-only for an auditor. Requests themselves come from devices; the decision dialogs are covered by the component
// tests and by the acceptance gates of the request flow.
test('software requests list keeps its filter in the URL and is read-only for an auditor', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await page.goto('/software-requests')
  await expect(page.getByRole('heading', { level: 1, name: 'Software requests' })).toBeVisible()
  const list = page.getByTestId('software-request-list')
  await list.getByTestId('list-filter-state').click()
  await page.getByRole('option', { name: 'Waiting' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/state=requested/)
  await page.reload()
  await expect(list).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])

  const auditor = await tempUser('e2e-requests-auditor', 'paddock.acme.auditors')
  try {
    await page.context().clearCookies()
    await loginWithPassword(page, auditor.username, auditor.password)
    await page.goto('/software-requests')
    await expect(page.getByTestId('software-request-list')).toBeVisible()
    await expect(page.getByTestId('approve-request')).toHaveCount(0)
    await expect(page.getByTestId('deny-request')).toHaveCount(0)
  } finally {
    await auditor.remove()
  }
})
