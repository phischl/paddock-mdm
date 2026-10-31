import { expect } from '@playwright/test'
import { login, loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M9 decision 35 (PDK-127): the findings page opens from the navigation, keeps its list state in the URL, hides
// closed findings by default and never uses a native dialog. The stack carries whatever findings earlier runs left,
// so the smoke does not depend on a particular finding.
test('organization admin opens the findings and filters them through the URL', async ({ page }) => {
  const csp = watchCSP(page)
  page.on('dialog', () => {
    throw new Error('a native dialog opened (ADR 0018)')
  })
  await login(page, 'alice@acme.test', 'dev_alice_password')

  await mainNav(page).getByRole('link', { name: 'Findings' }).click()
  await expect(page).toHaveURL(/\/findings/)
  await expect(page.getByRole('heading', { name: 'Findings', level: 1 })).toBeVisible()
  await expect(page.getByTestId('finding-list')).toBeVisible()
  await expectAccessible(page)

  await page.goto('/findings?status=false_positive&status=resolved&sort=hostname&page_size=10')
  await expect(page.getByTestId('finding-list')).toBeVisible()
  await expect(page).toHaveURL(/status=false_positive/)
  await expect(page).toHaveURL(/status=resolved/)
  await expect(page).toHaveURL(/sort=hostname/)
  await expect(page.getByTestId('finding-list').getByTestId('finding-status-open')).toHaveCount(0)

  await page.goto('/findings')
  const row = page.getByTestId('finding-list').locator('tbody tr').first()
  if (await row.getByRole('button', { name: /^Close / }).count()) {
    await row.getByRole('button', { name: /^Close / }).click()
    const dialog = page.getByTestId('finding-close-dialog')
    await expect(dialog.getByText('Facts and ticket references, no personal judgements.')).toBeVisible()
    await dialog.getByTestId('finding-close-submit').click()
    await expect(dialog.getByText('Enter a reason.')).toBeVisible()
    await expectAccessible(page)
    await dialog.getByTestId('finding-close-cancel').click()
    await expect(dialog).toBeHidden()
  }
  expect(csp).toEqual([])
})

test('operator sees accepted risk disabled in the close dialog', async ({ page }) => {
  const operator = await tempUser('e2e-findings-operator', 'paddock.acme.operators')
  try {
    await loginWithPassword(page, operator.username, operator.password)
    await page.goto('/findings')
    await expect(page.getByTestId('finding-list')).toBeVisible()
    const close = page.getByTestId('finding-list').getByRole('button', { name: /^Close / }).first()
    test.skip((await close.count()) === 0, 'the stack has no open finding to close')
    await close.click()
    await expect(page.getByTestId('finding-resolution-accepted_risk').getByRole('radio')).toBeDisabled()
    await expect(page.getByTestId('finding-accepted-risk-hint')).toBeVisible()
  } finally {
    await operator.remove()
  }
})
