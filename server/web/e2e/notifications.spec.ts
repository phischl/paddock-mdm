import { expect, type Page } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const alice = ['alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key'] as const

/** Runs start; a step-up that is still valid for a while is reused, else it is completed as alice. */
async function withStepUp(page: Page, start: () => Promise<void>): Promise<void> {
  const me = await (await page.request.get('/api/v1/me')).json() as { step_up_valid_until: string | null }
  const validFor = me.step_up_valid_until ? Date.parse(me.step_up_valid_until) - Date.now() : 0
  if (validFor > 10_000) await start()
  else await stepUp(page, start, ...alice)
}

// Plan M9 decision 36: an organization administrator adds a webhook destination (the secret is shown once), replaces
// the secret and deletes the destination again with the typed name. The URL host must resolve to a public address on
// the stack that runs this spec.
test('organization admin manages a webhook destination', async ({ page }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  const name = 'e2e-hook-' + Date.now()
  await login(page, alice[0], alice[1])
  await page.goto('/settings/notifications')
  await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible()

  await page.getByTestId('create-notification').click()
  const dialog = page.getByRole('dialog', { name: 'New notification destination' })
  await dialog.getByRole('textbox', { name: 'Name', exact: true }).fill(name)
  await dialog.getByLabel('Webhook URL').fill('https://example.com/paddock-e2e')
  await expectAccessible(page)
  const submit = () => dialog.getByTestId('notification-submit').click()
  // A fresh login holds no step-up: the portal steps up, never keeps the URL meanwhile and asks for it again.
  const me = await (await page.request.get('/api/v1/me')).json() as { step_up_valid_until: string | null }
  const valid = me.step_up_valid_until !== null && Date.parse(me.step_up_valid_until) - Date.now() > 10_000
  await withStepUp(page, submit)
  if (!valid) {
    await expect(page.getByTestId('notification-reenter-url')).toBeVisible()
    await expect(page.getByRole('dialog', { name: 'New notification destination' }).getByRole('textbox', { name: 'Name', exact: true })).toHaveValue(name)
    await page.getByRole('dialog', { name: 'New notification destination' }).getByLabel('Webhook URL').fill('https://example.com/paddock-e2e')
    await submit()
  }

  const secret = page.getByTestId('notification-secret').locator('input')
  await expect(secret).not.toHaveValue('')
  await expect(page.getByText('This is the only time the signing secret')).toBeVisible()
  await page.getByTestId('close-notification-secret').click()

  await page.reload()
  await expect(page.getByTestId('notification-secret')).toHaveCount(0)
  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toContainText('https://example.com/…')
  await expect(row).toContainText('Active')

  await page.getByRole('button', { name: `Replace secret: ${name}` }).click()
  await page.getByTestId('confirm-accept').click()
  await expect(page.getByTestId('notification-secret').locator('input')).not.toHaveValue('')
  await page.getByTestId('close-notification-secret').click()

  await page.getByRole('button', { name: `Delete: ${name}` }).click()
  await page.getByTestId('confirm-typed').locator('input').fill(name)
  await page.getByTestId('confirm-accept').click()
  await expect(page.getByTestId('notification-saved')).toContainText(`${name} deleted`)
  await expect(page.getByRole('row', { name: new RegExp(name) })).toHaveCount(0)
  expect(csp).toEqual([])
})
