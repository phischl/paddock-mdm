import { expect, test } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'

const root = ['platform-admin@paddock.test', 'dev_platform_admin_password', 'dev_platform_admin_totp_key'] as const

// Plan M17 / PDK-1018: the platform administrator requests the deletion of a fresh organization, sees it pending
// with its date and cancels it again, so the run leaves an ordinary active organization behind.
test('platform admin requests the deletion of an organization, sees it pending and cancels it', async ({ page }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  const slug = `e2e-${Date.now().toString(36)}`
  await login(page, root[0], root[1])
  await expect(page).toHaveURL(/\/platform\/organizations$/)

  await page.getByTestId('create-organization').click()
  const create = page.getByRole('dialog', { name: 'New organization' })
  await create.getByLabel('Slug').fill(slug)
  await create.getByLabel('Name').fill(`E2E ${slug}`)
  await create.getByRole('button', { name: 'Create' }).click()
  await expect(create).toBeHidden({ timeout: 65_000 })

  await page.getByTestId('list-search').getByRole('searchbox').fill(slug)
  await expect(page.getByTestId(`org-delete-${slug}`)).toBeVisible()

  await page.getByTestId(`org-delete-${slug}`).click()
  const dialog = page.getByTestId('confirm-dialog')
  await expect(dialog.getByTestId('confirm-accept')).toBeDisabled()
  await dialog.getByTestId('confirm-reason').getByRole('textbox').fill('contract ended')
  await dialog.getByTestId('confirm-typed').getByRole('textbox').fill(slug)
  await expectAccessible(page)
  await stepUp(page, () => dialog.getByTestId('confirm-accept').click(), ...root)

  await page.getByTestId('list-search').getByRole('searchbox').fill(slug)
  await expect(page.getByTestId(`org-deletion-pending-${slug}`)).toContainText('Deletion on')
  await expect(page.getByTestId(`org-delete-${slug}`)).toBeHidden()

  await page.getByTestId(`org-cancel-deletion-${slug}`).click()
  await page.getByTestId('confirm-dialog').getByTestId('confirm-accept').click()
  await expect(page.getByTestId(`org-deletion-pending-${slug}`)).toBeHidden()
  await expect(page.getByTestId(`org-delete-${slug}`)).toBeVisible()
  expect(csp).toEqual([])
})
