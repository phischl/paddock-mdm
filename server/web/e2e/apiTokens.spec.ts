import { expect } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// Plan M6c step 5: creating an API token needs a step-up and shows the secret exactly once; after a reload it is
// nowhere in the page; revoking goes through the confirmation modal; status chips; both pages are accessible.
test('organization admin creates, sees once and revokes an API token', async ({ page, context, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const name = `e2e api token ${Date.now()}`
  cleanup.remove('/api/v1/api-tokens', name)

  await page.goto('/api-tokens')
  await expect(page.getByRole('heading', { name: 'API tokens' })).toBeVisible()
  await expectAccessible(page)

  await page.getByTestId('create-api-token').click()
  const dialog = page.getByRole('dialog', { name: 'New API token' })
  await dialog.locator('#api-token-name').fill(name)
  await expectAccessible(page)
  await stepUp(page, () => dialog.getByRole('button', { name: 'Create' }).click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')

  const secretField = page.getByTestId('api-token-secret').locator('input')
  await expect(secretField).toHaveValue(/^pdk_[A-Za-z0-9_-]{43}$/)
  const secret = await secretField.inputValue()
  await expect(page.getByText('This is the only time the token is shown.')).toBeVisible()
  await page.getByTestId('copy-api-token').click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret)
  await page.getByTestId('close-api-token').click()
  await expect(page).not.toHaveURL(/stepup/)

  const row = page.getByTestId('api-token-list').getByRole('row').filter({ hasText: name })
  await expect(row.getByTestId('api-token-status-active')).toBeVisible()
  await expect(row).toContainText(secret.slice(0, 12))
  await page.reload()
  await expect(row).toBeVisible()
  expect(await page.content()).not.toContain(secret)

  await row.getByRole('button', { name: `Revoke ${name}` }).click()
  const confirm = page.getByRole('dialog', { name: 'Revoke API token' })
  await expectAccessible(page)
  await confirm.getByRole('button', { name: 'Revoke' }).click()
  await expect(row.getByTestId('api-token-status-revoked')).toBeVisible()
  await expect(row.getByRole('button', { name: `Revoke ${name}` })).toHaveCount(0)

  await page.goto('/change-sets')
  await expect(page.getByRole('heading', { name: 'Change sets' })).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
