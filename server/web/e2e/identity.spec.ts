import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Gate E3 (plan M3a §6): create a local user (recovery link shown once), create a group and add the member, create
// a restricted profile with a root-equivalent command (warning shown), assign it to the group, view the user's
// effective profile with its derivation, lock the user in a modal, set the device login assignment and suspend
// logins in a modal; accessible and without CSP violations.
test('organization admin manages users, groups, profiles and device logins', async ({ page, cleanup }) => {
  test.setTimeout(240_000)
  const csp = watchCSP(page)
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now().toString(36)
  const username = `e2e-${stamp}@acme.test`
  const groupName = `E2E group ${stamp}`
  const groupSlug = `e2e-${stamp}`
  const profileName = `E2E editor ${stamp}`
  const hostname = `e2e-login-${stamp}`
  cleanup.remove('/api/v1/users', username)
  cleanup.remove('/api/v1/user-groups', groupName)
  cleanup.remove('/api/v1/permission-profiles', profileName)
  cleanup.remove('/api/v1/profile-assignments', profileName)
  cleanup.remove('/api/v1/enrollment-tokens', `E2E login token ${stamp}`)

  // Local user: the one-time recovery link is shown once with a copy button.
  await page.getByRole('link', { name: 'Users', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible()
  await expectAccessible(page)
  await page.getByTestId('create-user').click()
  const userDialog = page.getByRole('dialog', { name: 'New local user' })
  await userDialog.getByLabel('Username').fill(username)
  await userDialog.getByLabel('Display name').fill('E2E User')
  await expectAccessible(page)
  await userDialog.getByRole('button', { name: 'Create' }).click()
  const linkField = page.getByTestId('recovery-link').locator('input')
  await expect(linkField).toHaveValue(/\/if\/flow\/paddock-recovery\/\?flow_token=/)
  const link = await linkField.inputValue()
  await page.getByTestId('copy-link').click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link)
  await expectAccessible(page)
  await page.getByTestId('close-user').click()
  await expect(userDialog).toBeHidden()
  expect(await page.content()).not.toContain(link)
  await page.getByTestId('list-search').getByRole('searchbox').fill(username)
  await expect(page.getByRole('row').filter({ hasText: username })).toContainText('Local')

  // Group with the user as member.
  await page.getByRole('link', { name: 'Groups', exact: true }).click()
  await page.getByTestId('create-user-group').click()
  const groupDialog = page.getByRole('dialog', { name: 'New group' })
  await groupDialog.getByLabel('Name').fill(groupName)
  await groupDialog.getByLabel('Slug').fill(groupSlug)
  await expectAccessible(page)
  await groupDialog.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByRole('heading', { name: groupName })).toBeVisible()
  await page.getByTestId('add-member').locator('input').fill(username)
  await page.getByRole('option', { name: username }).click()
  await page.getByTestId('add-member-submit').click()
  await expect(page.getByTestId('member-list')).toContainText(username)
  await expectAccessible(page)

  // A restricted profile with a root-equivalent command: inline warning, no dialog.
  await page.getByRole('link', { name: 'Permission profiles' }).click()
  await page.getByTestId('create-profile').click()
  const profileDialog = page.getByRole('dialog', { name: 'New permission profile' })
  await profileDialog.getByLabel('Name').fill(profileName)
  await profileDialog.getByLabel('Commands').fill('/usr/bin/vim /etc/hosts')
  await expectAccessible(page)
  await profileDialog.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByRole('heading', { name: profileName })).toBeVisible()
  await expect(page.getByTestId('root-equivalent-warning')).toContainText('/usr/bin/vim /etc/hosts')

  // Assigned to the group.
  await page.getByTestId('assign-subject').locator('input').fill(groupName)
  await page.getByRole('option', { name: groupName }).click()
  await page.getByTestId('assign-submit').click()
  await expect(page.getByTestId('assignment-list')).toContainText(groupName)
  await expectAccessible(page)

  // The user's effective profile names the assignment that granted the command.
  const userId = await (async () => {
    const res = await page.request.get('/api/v1/users?q=' + encodeURIComponent(username))
    return ((await res.json()) as { items: { id: string }[] }).items[0].id
  })()
  await page.goto('/users/' + userId)
  await expect(page.getByRole('heading', { name: username })).toBeVisible()
  const derivation = page.getByTestId('derivation')
  await expect(derivation).toContainText('Command /usr/bin/vim /etc/hosts')
  await expect(derivation).toContainText(profileName)
  await expect(derivation).toContainText(groupName)
  await expect(page.getByTestId('effective-profile').getByTestId('root-equivalent-warning')).toBeVisible()
  await expectAccessible(page)

  // Lock in a modal that requires typing the username.
  await page.getByTestId('lock-user').click()
  const lock = page.getByRole('dialog', { name: 'Lock user' })
  await expect(lock.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await expect(lock.getByRole('button', { name: 'Lock' })).toBeDisabled()
  await lock.getByTestId('confirm-typed').locator('input').fill(username)
  await expectAccessible(page)
  await lock.getByRole('button', { name: 'Lock' }).click()
  await expect(page.getByTestId('user-lock-state')).toContainText('Locked since')

  // A device: the user may log in on it; then logins are suspended in a modal.
  const token = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: `E2E login token ${stamp}`, max_uses: 1, auto_approve: true, expires_at: new Date(Date.now() + 3600_000).toISOString() },
  })
  expect(token.status()).toBe(201)
  const config = JSON.stringify((await token.json()).enrollment_config)
  const enrolled = JSON.parse(execFileSync(devicesim, ['enroll', '--hostname', hostname], { input: config, encoding: 'utf8', timeout: 90_000 }))
  await page.goto('/devices/' + enrolled.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await expect(page.getByTestId('agent-too-old')).toBeVisible()
  await page.getByTestId('login-users').locator('input').fill(username)
  await page.getByRole('option', { name: username }).click()
  await page.keyboard.press('Escape')
  await page.getByTestId('save-login-assignment').click()
  await expect(page.getByRole('main').getByRole('status')).toHaveText('Login assignment saved.')
  await expectAccessible(page)
  await page.getByTestId('toggle-suspension').click()
  const suspend = page.getByRole('dialog', { name: 'Suspend logins' })
  await expect(suspend.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await expectAccessible(page)
  await suspend.getByRole('button', { name: 'Suspend logins' }).click()
  await expect(page.getByTestId('logins-suspended')).toBeVisible()

  // The device is retired again (the gates leave no active test devices behind).
  const retired = await page.request.post(`/api/v1/devices/${enrolled.device_id}/retire`, { headers: csrf })
  expect(retired.status()).toBe(200)
  expect(csp).toEqual([])
})
