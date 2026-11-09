import { expect } from '@playwright/test'
import { login, loginWithPassword, tempUser } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M13b decision 19 (PDK-804): an administrator assigns a catalog entry as available to a user group through the
// target selector; the entry's member sees it on their user page, directly or through the group, and the assignment
// list keeps its filter in the URL. An auditor reads the same user page without write controls.
test('administrator offers an application to a user group and the member’s user page lists it', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const app = `E2E Editor ${stamp}`
  const groupName = `E2E Designers ${stamp}`
  const username = `e2e-sw-${stamp}@acme.test`
  cleanup.remove('/api/v1/users', username)
  cleanup.remove('/api/v1/user-groups', groupName)
  cleanup.remove('/api/v1/software-catalog', app)
  cleanup.remove('/api/v1/software-assignments', app)

  const user = await page.request.post('/api/v1/users', { headers: csrf, data: { username, display_name: `E2E software ${stamp}` } })
  expect(user.status()).toBe(201)
  const userID = (await user.json()).user.id as string
  const group = await page.request.post('/api/v1/user-groups', { headers: csrf, data: { slug: `e2e-sw-${stamp}`, name: groupName } })
  expect(group.status()).toBe(201)
  const groupID = (await group.json()).id as string
  expect((await page.request.post(`/api/v1/user-groups/${groupID}/members`, { headers: csrf, data: { user_id: userID } })).status()).toBe(204)
  const entry = await page.request.post('/api/v1/software-catalog', {
    headers: csrf,
    data: { name: app, packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', package: 'nano' }] },
  })
  expect(entry.status()).toBe(201)
  const entryID = (await entry.json()).id as string

  await page.goto(`/software-catalog/${entryID}`)
  await expect(page.getByRole('heading', { level: 1, name: app })).toBeVisible()
  await page.getByTestId('create-assignment').click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('combobox', { name: 'Target' }).click()
  await page.getByRole('option', { name: 'User group', exact: true }).click()
  await dialog.getByTestId('save-assignment').click()
  await expect(dialog.getByText('Choose the target.')).toBeVisible()
  await dialog.getByRole('combobox', { name: 'User group' }).fill(groupName)
  await page.getByRole('option', { name: groupName }).click()
  await dialog.getByRole('combobox', { name: 'Intent' }).click()
  await page.getByRole('option', { name: 'Available' }).click()
  await expect(dialog.getByTestId('assignment-version').locator('input')).toBeDisabled()
  await dialog.getByTestId('save-assignment').click()
  await expect(dialog).toBeHidden()

  const assignments = page.getByTestId('assignment-list')
  const row = assignments.getByRole('row').filter({ hasText: `User group ${groupName}` })
  await expect(row).toContainText('Available')
  await expect(row.getByRole('button', { name: `Delete User group ${groupName}` })).toBeVisible()
  await assignments.getByTestId('list-filter-target').click()
  await page.getByRole('option', { name: 'User group' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/a\.target=user_group/)
  await page.reload()
  await expect(assignments.getByRole('row').filter({ hasText: `User group ${groupName}` })).toBeVisible()
  await expect(page.getByTestId('compile-warning-list')).toBeVisible()
  await expectAccessible(page)

  // Verification (manual) step 1 of the ticket: the member's user page lists the entry through the group.
  await page.goto(`/users/${userID}`)
  const software = page.getByTestId('user-software')
  const listed = software.getByRole('row').filter({ hasText: app })
  await expect(listed).toContainText('Available')
  await expect(listed.getByRole('link', { name: groupName })).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])

  const auditor = await tempUser('e2e-software-auditor', 'paddock.acme.auditors')
  try {
    await page.context().clearCookies()
    await loginWithPassword(page, auditor.username, auditor.password)
    await page.goto(`/users/${userID}`)
    await expect(page.getByTestId('user-software').getByRole('row').filter({ hasText: app })).toContainText(groupName)
    await expect(page.getByTestId('edit-user')).toHaveCount(0)
    await page.goto(`/software-catalog/${entryID}`)
    await expect(page.getByTestId('assignment-list').getByRole('row').filter({ hasText: `User group ${groupName}` })).toBeVisible()
    await expect(page.getByTestId('create-assignment')).toHaveCount(0)
  } finally {
    await auditor.remove()
    await page.context().clearCookies()
    await login(page, 'alice@acme.test', 'dev_alice_password')
  }
})

// Plan M13b decision 5 (PDK-804): the source form of a Flatpak remote hides what only an APT repository has and needs
// exactly one https URL; nothing is sent before that, so no step-up starts.
test('Flatpak source form asks for one remote URL and no APT fields', async ({ page }) => {
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await page.goto('/software-sources')
  await page.getByTestId('create-source').click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('textbox', { name: 'Suites' })).toBeVisible()
  await dialog.getByRole('combobox', { name: 'Kind' }).click()
  await page.getByRole('option', { name: 'Flatpak remote' }).click()
  await expect(dialog.getByRole('textbox', { name: 'Suites' })).toHaveCount(0)
  await expect(dialog.getByRole('textbox', { name: 'Components' })).toHaveCount(0)
  await expect(dialog.getByText('Architectures')).toHaveCount(0)
  await dialog.getByRole('textbox', { name: 'Name' }).fill('E2E Flathub')
  await dialog.getByRole('textbox', { name: 'Slug' }).fill('e2e-flathub')
  await dialog.getByRole('textbox', { name: 'URIs' }).fill('https://a.example.org/repo/\nhttps://b.example.org/repo/')
  await dialog.getByTestId('save-source').click()
  await expect(dialog.getByText('Enter exactly one https address, the URL of the Flatpak remote.')).toBeVisible()
  await expect(dialog.getByText('Paste one OpenPGP public key of at most 64 KiB.')).toBeVisible()
  await expect(page).toHaveURL(/\/software-sources$/)
  await expectAccessible(page)
})
