import { expect, test } from '@playwright/test'
import { loginWithPassword, tempUser } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'

const csrf = { 'X-Paddock-CSRF': '1' }

// PDK-155 (plan M11 decision 22): an operator reverts a change set from the list. The Revert button shows the inverse
// plan in a modal, the confirmed revert restores the previous state, the detail links the two change sets, and the
// reverted change set's button is disabled with a tooltip. A temporary operator makes the change sets its own, so the
// list search by actor finds exactly them.
test('operator reverts a change set and cannot revert it twice', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const operator = await tempUser('e2e-revert-operator', 'paddock.acme.operators')
  const pkg = `e2e-revert-${Date.now()}`
  let holdId = ''
  try {
    await loginWithPassword(page, operator.username, operator.password)
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    const created = await page.request.post('/api/v1/package-holds', { headers: csrf, data: { package: pkg, reason: 'first' } })
    expect(created.status()).toBe(201)
    holdId = ((await created.json()) as { id: string }).id
    const updated = await page.request.patch(`/api/v1/package-holds/${holdId}`, { headers: csrf, data: { version: null, reason: 'second' } })
    expect(updated.status()).toBe(200)

    await page.goto('/change-sets?q=' + encodeURIComponent(operator.username))
    await expect(page.getByRole('heading', { level: 1, name: 'Change sets' })).toBeVisible()
    const list = page.getByTestId('change-set-list')
    await expect(list.getByTestId('change-set-revert')).toHaveCount(2)
    await expectAccessible(page)

    // Newest first: the update of the reason.
    await list.getByTestId('change-set-revert').first().click()
    const dialog = page.getByTestId('confirm-dialog')
    await expect(dialog.getByRole('heading', { name: 'Revert change set' })).toBeVisible()
    const plan = dialog.getByTestId('change-set-plan')
    await expect(plan.locator('tbody tr')).toHaveCount(1)
    await expect(plan).toContainText('package_holds')
    await expect(plan).toContainText('first')
    await expectAccessible(page)
    await dialog.getByTestId('confirm-accept').click()
    await expect(page.getByTestId('change-set-reverted')).toBeVisible()
    await expect(dialog).toBeHidden()

    const hold = await page.request.get(`/api/v1/package-holds/${holdId}`)
    expect(((await hold.json()) as { reason: string }).reason).toBe('first')

    // The revert is a change set of its own; the reverted one cannot be reverted again.
    await expect(list.getByTestId('change-set-revert')).toHaveCount(2)
    const blocked = list.getByTestId('change-set-revert-blocked')
    await expect(blocked).toHaveCount(1)
    await expect(blocked.getByRole('button', { name: /Revert the change set of/ })).toBeDisabled()
    await blocked.hover()
    await expect(page.getByRole('tooltip')).toHaveText('This change set was already reverted.')

    const rows = list.locator('tbody tr')
    await rows.nth(1).getByRole('button', { name: /Details of the change set/ }).click()
    const detail = page.getByRole('dialog', { name: 'Change set' })
    await expect(detail.getByTestId('change-set-reverted-by')).toBeVisible()
    await detail.getByTestId('change-set-reverted-by').click()
    await expect(detail.getByTestId('change-set-reverts')).toBeVisible()
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    if (holdId) await page.request.delete(`/api/v1/package-holds/${holdId}`, { headers: csrf })
    await operator.remove()
  }
})
