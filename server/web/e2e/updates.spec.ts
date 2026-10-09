import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M5b decision 12: the update settings validate the schedule; package holds are created, changed and released
// (the release confirmed in a modal); a device's Updates card shows its holds and refuses to install a held package,
// the device group installs now for its members; the attention list filters by kind. Accessible, without CSP
// violations.
test('organization admin manages updates, holds and install now', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await expect(page).toHaveURL(/\/(attention|device-groups)$/)
  const stamp = Date.now()
  const hostname = `e2e-upd-${stamp}`
  const groupName = `E2E updates ${stamp}`
  const held = `e2e-held-${stamp}`
  const pinned = `e2e-pinned-${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', `E2E updates token ${stamp}`)
  cleanup.remove('/api/v1/device-groups', groupName)
  cleanup.remove('/api/v1/package-holds', held)
  cleanup.remove('/api/v1/package-holds', pinned)

  // Settings: a schedule outside the subset is refused in the form; the current values save.
  await mainNav(page).getByRole('link', { name: 'Updates', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Updates', exact: true })).toBeVisible()
  const schedule = page.getByTestId('regular-schedule').locator('input')
  const current = await schedule.inputValue()
  await schedule.fill('Mon..Fri 04:00')
  await page.getByTestId('save-update-settings').click()
  await expect(page.getByText('Use weekdays (Mon … Sun, comma-separated) and HH:MM').first()).toBeVisible()
  await expectAccessible(page)
  await schedule.fill(current)
  await page.getByTestId('save-update-settings').click()
  await expect(page.getByRole('main').getByRole('status')).toHaveText('Update settings saved.')

  // A device of a new group.
  const group = await page.request.post('/api/v1/device-groups', { headers: csrf, data: { name: groupName } })
  expect(group.status()).toBe(201)
  const groupID = ((await group.json()) as { id: string }).id
  const token = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: `E2E updates token ${stamp}`, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(token.status()).toBe(201)
  const config = JSON.stringify((await token.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim, ['enroll', '--hostname', hostname], { input: config, encoding: 'utf8', timeout: 90_000 })) as
    { device_id: string; status: string }
  expect(device.status).toBe('active')
  expect((await page.request.put(`/api/v1/devices/${device.device_id}/groups`, { headers: csrf, data: { device_group_ids: [groupID] } })).status()).toBe(200)

  // Package holds: one for the group, one pinned organization-wide, changed, then released after a confirmation.
  await mainNav(page).getByRole('link', { name: 'Package holds' }).click()
  await expect(page.getByRole('heading', { name: 'Package holds' })).toBeVisible()
  await page.getByTestId('create-hold').click()
  let dialog = page.getByRole('dialog', { name: 'Hold a package' })
  await dialog.getByTestId('hold-scope').click()
  await page.getByRole('option', { name: groupName }).click()
  await dialog.getByLabel('Package').fill(held)
  await dialog.getByLabel('Reason').fill('breaks the e2e app')
  await expectAccessible(page)
  await dialog.getByRole('button', { name: 'Create' }).click()
  await expect(dialog).toBeHidden()
  await page.getByTestId('create-hold').click()
  dialog = page.getByRole('dialog', { name: 'Hold a package' })
  await dialog.getByLabel('Package').fill('Not A Package')
  await dialog.getByRole('button', { name: 'Create' }).click()
  await expect(dialog.getByText('Enter a Debian package name')).toBeVisible()
  await dialog.getByLabel('Package').fill(pinned)
  await dialog.getByLabel('Version', { exact: true }).fill('1.0-1')
  await dialog.getByRole('button', { name: 'Create' }).click()
  await expect(dialog).toBeHidden()
  await page.getByTestId('list-search').getByRole('searchbox').fill(`-${stamp}`)
  await expect(page).toHaveURL(/[?&]q=/)
  const list = page.getByTestId('hold-list')
  await expect(list.getByRole('row').filter({ hasText: held })).toContainText(groupName)
  await expect(list.getByRole('row').filter({ hasText: held })).toContainText('installed version')
  await expect(list.getByRole('row').filter({ hasText: pinned })).toContainText('1.0-1')
  await page.getByRole('button', { name: `Edit ${pinned}` }).click()
  dialog = page.getByRole('dialog', { name: 'Change the hold' })
  await dialog.getByLabel('Version', { exact: true }).fill('1.0-2')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(list.getByRole('row').filter({ hasText: pinned })).toContainText('1.0-2')
  await page.getByRole('button', { name: `Delete ${pinned}` }).click()
  const confirm = page.getByRole('dialog', { name: 'Release the package?' })
  await expect(confirm.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await expectAccessible(page)
  await confirm.getByRole('button', { name: 'Delete' }).click()
  await expect(list.getByRole('row').filter({ hasText: pinned })).toHaveCount(0)
  await expectAccessible(page)

  // Device detail: the Updates card lists the hold; installing the held package is refused and names it.
  await page.goto('/devices/' + device.device_id)
  const card = page.getByTestId('device-updates')
  await expect(card.getByTestId('device-holds')).toHaveText(held)
  await expect(card.getByTestId('last-regular-run')).toHaveText('None reported yet')
  await card.getByTestId('install-now').click()
  dialog = page.getByRole('dialog', { name: `Install packages on ${hostname}` })
  await dialog.getByLabel('Packages').fill(`htop ${held}`)
  await expectAccessible(page)
  await dialog.getByTestId('install-submit').click()
  await expect(dialog.getByTestId('install-problem')).toContainText(held)
  await dialog.getByLabel('Packages').fill('htop')
  await dialog.getByTestId('install-submit').click()
  await expect(dialog).toBeHidden()
  await expect(card.getByRole('status')).toHaveText('The device installs the packages at its next check-in.')
  await expect(page.getByRole('cell', { name: 'Install packages now' })).toBeVisible()

  // Device group: install now for the members.
  await page.goto('/device-groups/' + groupID)
  await page.getByTestId('group-install-now').click()
  dialog = page.getByRole('dialog', { name: `Install packages on the devices of ${groupName}` })
  await dialog.getByLabel('Packages').fill('curl')
  await dialog.getByTestId('install-submit').click()
  await expect(dialog).toBeHidden()
  await expect(page.getByRole('main').getByRole('status')).toHaveText('1 device installs the packages at its next check-in.')

  // The attention list filters by kind and links to the devices.
  await page.getByTestId('nav-attention').click()
  await expect(page.getByRole('heading', { name: 'Attention', exact: true })).toBeVisible()
  await page.getByTestId('list-filter-kind').click()
  await page.getByRole('option', { name: 'Agent outdated' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/kind=agent_outdated/)
  await expect(page.getByTestId('attention-list')).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
