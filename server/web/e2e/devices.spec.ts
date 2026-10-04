import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'

/** Enrolls a simulated device with an enrollment configuration and returns the enrollment result. */
function enrollDevice(config: string, hostname: string): { device_id: string; status: string } {
  const out = execFileSync(devicesim, ['enroll', '--hostname', hostname], { input: config, encoding: 'utf8', timeout: 90_000 })
  return JSON.parse(out)
}

// Gate E2 (plan M2a §8): token shown once with a copy button, enrollment, approval, group membership, managed file
// in the effective configuration, retirement with the typed hostname; accessible and without CSP violations.
test('organization admin enrolls, configures and retires a device', async ({ page, context, cleanup }) => {
  const csp = watchCSP(page)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-${stamp}`
  const groupName = `E2E devices ${stamp}`
  const path = `/etc/paddock-e2e-${stamp}.conf`
  cleanup.remove('/api/v1/enrollment-tokens', `E2E token ${stamp}`)
  cleanup.remove('/api/v1/device-groups', groupName)
  cleanup.remove('/api/v1/managed-files', path)

  // Enrollment token: the configuration with the secret is shown once.
  await page.getByRole('link', { name: 'Enrollment tokens' }).click()
  await expect(page.getByRole('heading', { name: 'Enrollment tokens' })).toBeVisible()
  await expectAccessible(page)
  await page.getByTestId('create-token').click()
  const dialog = page.getByRole('dialog', { name: 'New enrollment token' })
  await dialog.getByLabel('Name').fill(`E2E token ${stamp}`)
  await expectAccessible(page)
  await dialog.getByRole('button', { name: 'Create' }).click()
  const configField = page.getByTestId('enrollment-config').locator('textarea')
  await expect(configField).toBeVisible()
  const config = await configField.inputValue()
  const secret = JSON.parse(config).token as string
  expect(secret.length).toBeGreaterThan(20)
  await page.getByTestId('copy-config').click()
  await expect(dialog.getByRole('status')).toHaveText('Copied to the clipboard.')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(config)
  await expectAccessible(page)
  await page.getByTestId('close-token').click()
  await expect(dialog).toBeHidden()
  await page.getByTestId('list-search').getByRole('searchbox').fill(`E2E token ${stamp}`)
  await expect(page).toHaveURL(/[?&]q=/)
  await expect(page.getByRole('cell', { name: `E2E token ${stamp}`, exact: true })).toBeVisible()
  expect(await page.content()).not.toContain(secret)
  const tokens = await page.request.get('/api/v1/enrollment-tokens?q=' + encodeURIComponent(`E2E token ${stamp}`))
  expect(await tokens.text()).not.toContain(secret)

  // The device enrolls with the manual-approval token and waits for approval.
  const enrolled = enrollDevice(config, hostname)
  expect(enrolled.status).toBe('pending')
  await page.getByRole('link', { name: 'Devices' }).click()
  await expect(page.getByRole('heading', { name: 'Devices', exact: true })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(hostname)
  const row = page.getByRole('row').filter({ hasText: hostname })
  await expect(row).toContainText('Pending approval')
  await expectAccessible(page)
  await row.getByRole('link', { name: hostname }).click()
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await expectAccessible(page)
  await page.getByTestId('device-approve').click()
  const approve = page.getByRole('dialog', { name: 'Approve device' })
  await expect(approve.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await approve.getByRole('button', { name: 'Approve' }).click()
  await expect(page.getByTestId('device-state')).toHaveText('Active')

  // Group membership and a managed file for the group.
  const res = await page.request.post('/api/v1/device-groups', { headers: { 'X-Paddock-CSRF': '1' }, data: { name: groupName } })
  expect(res.status()).toBe(201)
  await page.reload()
  await page.getByTestId('device-groups').locator('input').fill(groupName)
  await page.getByRole('option', { name: groupName }).click()
  await page.keyboard.press('Escape')
  await page.getByTestId('save-device-groups').click()
  await expect(page.getByRole('status')).toHaveText('Device groups saved.')

  await page.getByRole('link', { name: 'Managed files' }).click()
  await expect(page.getByRole('heading', { name: 'Managed files' })).toBeVisible()
  await page.getByTestId('create-managed-file').click()
  const fileDialog = page.getByRole('dialog', { name: 'New managed file' })
  await fileDialog.getByRole('combobox', { name: 'Applies to' }).fill(groupName)
  await page.getByRole('option', { name: groupName }).click()
  await fileDialog.getByLabel('Path').fill(path)
  await fileDialog.getByLabel('Content').fill('managed by the e2e test\n')
  await expectAccessible(page)
  await fileDialog.getByRole('button', { name: 'Create' }).click()
  await expect(fileDialog).toBeHidden()
  await page.getByTestId('list-search').getByRole('searchbox').fill(path)
  await expect(page).toHaveURL(/[?&]q=/)
  await expect(page.getByRole('cell', { name: path, exact: true })).toBeVisible()

  // The device detail shows the file in the effective configuration.
  await page.goto('/devices/' + enrolled.device_id)
  await expect(page.getByTestId('effective-files')).toContainText(path)
  await expect(page.getByTestId('effective-files')).toContainText(groupName)
  await expectAccessible(page)

  // Retiring requires typing the hostname.
  await page.getByTestId('device-retire').click()
  const retire = page.getByRole('dialog', { name: 'Retire device' })
  await expect(retire.getByRole('button', { name: 'Retire' })).toBeDisabled()
  await retire.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expectAccessible(page)
  await retire.getByRole('button', { name: 'Retire' }).click()
  await expect(page.getByTestId('device-state')).toHaveText('Retired')
  await expect(page.getByTestId('device-retire')).toHaveCount(0)
  expect(csp).toEqual([])
})
