import { expect } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const collection = '/api/platform/v1/ip-allowlist'

// Plan M7a step 4: the platform admin switches the IP allow list on with its own address through the step-up,
// adds and removes a range through the modal, is asked to type the CIDR before removing its own entry, and switches
// the list off again; the page is accessible in every state.
test('platform admin manages the IP allow list', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'platform-admin@paddock.test', 'dev_platform_admin_password')
  const name = `e2e allow ${Date.now()}`
  cleanup.remove(collection, name)

  await page.goto('/platform/ip-allowlist')
  await expect(page.getByRole('heading', { name: 'IP allow list' })).toBeVisible()
  const status = page.getByTestId('ip-allowlist-status')
  await expect(status).toHaveAttribute('data-state', 'off')
  await expect(status).toContainText('Your current address:')
  await expectAccessible(page)

  await page.getByTestId('create-ip-allowlist-entry').click()
  const dialog = page.getByRole('dialog', { name: 'New allow list entry' })
  await dialog.getByTestId('use-my-address').click()
  const own = await dialog.locator('#ip-allowlist-cidr').inputValue()
  expect(own).toMatch(/\/(32|128)$/)
  await dialog.locator('#ip-allowlist-label').fill(`${name} own`)
  await expectAccessible(page)
  await stepUp(page, () => dialog.getByRole('button', { name: 'Create' }).click(),
    'platform-admin@paddock.test', 'dev_platform_admin_password', 'dev_platform_admin_totp_key')
  await expect(page).not.toHaveURL(/stepup/)
  await expect(status).toHaveAttribute('data-state', 'covered')
  await expect(status).toContainText(`your address is covered by ${own}`)
  const list = page.getByTestId('ip-allowlist-list')
  const ownRow = list.getByRole('row').filter({ hasText: `${name} own` })
  await expect(ownRow.getByTestId('covers-caller')).toBeVisible()

  // Within the step-up window the next writes need no further step-up.
  await page.getByTestId('create-ip-allowlist-entry').click()
  await dialog.locator('#ip-allowlist-cidr').fill('198.51.100.0/24')
  await dialog.locator('#ip-allowlist-label').fill(`${name} office`)
  await dialog.getByRole('button', { name: 'Create' }).click()
  const officeRow = list.getByRole('row').filter({ hasText: `${name} office` })
  await expect(officeRow).toBeVisible()
  await expect(status).toContainText('Enabled with 2 entries')

  await officeRow.getByRole('button', { name: 'Remove 198.51.100.0/24' }).click()
  const confirm = page.getByRole('dialog', { name: 'Remove allow list entry' })
  await expectAccessible(page)
  await confirm.getByRole('button', { name: 'Remove' }).click()
  await expect(officeRow).toHaveCount(0)
  await expect(status).toContainText('Enabled with 1 entries')

  // Removing the own entry: refused with the typed confirmation, which can be cancelled.
  await ownRow.getByRole('button', { name: `Remove ${own}` }).click()
  await confirm.getByRole('button', { name: 'Remove' }).click()
  const typed = page.getByRole('dialog', { name: 'This switches the allow list off' })
  await expect(typed).toContainText('Removing the last entry switches the allow list off for everyone.')
  await expect(typed.getByRole('button', { name: 'Confirm change' })).toBeDisabled()
  await expectAccessible(page)
  await typed.getByRole('button', { name: 'Cancel' }).click()
  await expect(ownRow).toBeVisible()
  await expect(status).toHaveAttribute('data-state', 'covered')

  await ownRow.getByRole('button', { name: `Remove ${own}` }).click()
  await confirm.getByRole('button', { name: 'Remove' }).click()
  await typed.getByLabel(`Type ${own} to confirm`).fill(own)
  await typed.getByRole('button', { name: 'Confirm change' }).click()
  await expect(ownRow).toHaveCount(0)
  await expect(status).toHaveAttribute('data-state', 'off')
  await expectAccessible(page)
  expect(csp).toEqual([])
})
