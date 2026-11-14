import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { expect } from '@playwright/test'
import { login, loginWithPassword, tempUser } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const csrf = { 'X-Paddock-CSRF': '1' }
// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'

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
  // Vuetify keeps the select's combobox input under the selection overlay, so the pointer goes to the field.
  await dialog.getByTestId('assignment-target').click()
  await page.getByRole('option', { name: 'User group', exact: true }).click()
  await expect(dialog.getByRole('combobox', { name: 'Target' })).toHaveValue('User group')
  await dialog.getByTestId('save-assignment').click()
  await expect(dialog.getByText('Choose the target.')).toBeVisible()
  await dialog.getByRole('combobox', { name: 'User group' }).fill(groupName)
  await page.getByRole('option', { name: groupName }).click()
  await dialog.getByTestId('assignment-intent').click()
  await page.getByRole('option', { name: 'Available' }).click()
  await expect(dialog.getByRole('combobox', { name: 'Intent' })).toHaveValue('Available')
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
  await dialog.getByTestId('source-kind').click()
  await page.getByRole('option', { name: 'Flatpak remote' }).click()
  await expect(dialog.getByRole('combobox', { name: 'Kind' })).toHaveValue('Flatpak remote')
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

// Plan M13c decisions 4, 7 and 8 (PDK-816): an administrator requires approval on an entry, asks for a reason before an
// urgent assignment is sent (nothing is sent, so no step-up starts), and sets and removes a device group's maintenance
// window; the removal waits for the modal confirmation. An auditor reads the window without write controls.
test('administrator sets approval, the urgent reason and a maintenance window', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const app = `E2E Approval ${stamp}`
  const groupName = `E2E Window ${stamp}`
  cleanup.remove('/api/v1/software-catalog', app)
  cleanup.remove('/api/v1/device-groups', groupName)

  await page.goto('/software-catalog')
  await page.getByTestId('create-entry').click()
  const entryDialog = page.getByRole('dialog')
  await entryDialog.getByRole('textbox', { name: 'Name' }).fill(app)
  await entryDialog.getByTestId('package-name-0').locator('input').fill('nano')
  await entryDialog.getByRole('checkbox', { name: 'Users need approval' }).check()
  await entryDialog.getByTestId('save-entry').click()
  await expect(entryDialog).toBeHidden()
  await page.getByTestId('catalog-list').getByRole('link', { name: app }).click()
  await expect(page.getByTestId('entry-approval')).toHaveText('Required')

  await page.getByTestId('create-assignment').click()
  const assignmentDialog = page.getByRole('dialog')
  await assignmentDialog.getByRole('checkbox', { name: 'Urgent: apply outside maintenance windows' }).check()
  await assignmentDialog.getByTestId('save-assignment').click()
  await expect(assignmentDialog.getByText('Enter a reason of 2 to 500 characters for an urgent assignment.')).toBeVisible()
  await expect(page).toHaveURL(/\/software-catalog\//)
  await assignmentDialog.getByRole('button', { name: 'Cancel' }).click()
  await expectAccessible(page)

  const group = await page.request.post('/api/v1/device-groups', { headers: csrf, data: { name: groupName } })
  expect(group.status()).toBe(201)
  const groupID = (await group.json()).id as string
  await page.goto(`/device-groups/${groupID}`)
  await expect(page.getByTestId('window-summary')).toContainText('No window')
  await page.getByTestId('edit-window').click()
  const windowDialog = page.getByRole('dialog')
  await windowDialog.getByTestId('window-day-6').locator('input').uncheck()
  await windowDialog.getByTestId('window-day-7').locator('input').uncheck()
  await windowDialog.getByTestId('window-start').locator('input').fill('21:30')
  await windowDialog.getByTestId('window-duration').locator('input').fill('29')
  await windowDialog.getByTestId('save-window').click()
  await expect(windowDialog.getByText('Enter 30 to 1440 minutes.')).toBeVisible()
  await windowDialog.getByTestId('window-duration').locator('input').fill('90')
  await windowDialog.getByTestId('save-window').click()
  await expect(windowDialog).toBeHidden()
  await expect(page.getByTestId('window-summary')).toContainText('Mon, Tue, Wed, Thu, Fri, from 21:30 for 1 hour 30 minutes')
  await expectAccessible(page)

  const auditor = await tempUser('e2e-window-auditor', 'paddock.acme.auditors')
  try {
    await page.context().clearCookies()
    await loginWithPassword(page, auditor.username, auditor.password)
    await page.goto(`/device-groups/${groupID}`)
    await expect(page.getByTestId('window-summary')).toContainText('from 21:30')
    await expect(page.getByTestId('edit-window')).toHaveCount(0)
    await expect(page.getByTestId('remove-window')).toHaveCount(0)
  } finally {
    await auditor.remove()
    await page.context().clearCookies()
    await login(page, 'alice@acme.test', 'dev_alice_password')
  }

  await page.goto(`/device-groups/${groupID}`)
  await page.getByTestId('remove-window').click()
  await expect(page.getByTestId('confirm-dialog')).toContainText(groupName)
  await page.getByTestId('confirm-accept').click()
  await expect(page.getByTestId('window-summary')).toContainText('No window')
  expect(csp).toEqual([])
})

// PDK-993, ticket PDK-999: the justification a user types on the device is untrusted text (maintainer answer Q7). A
// device (devicesim) asks for an approval-required entry with markup as its justification; the administrator's request
// list shows it literally, creates no element from it and runs none of its script.
test('request list shows a justification with markup as plain text', async ({ page, cleanup }) => {
  test.setTimeout(400_000)
  const csp = watchCSP(page)
  const dialogs: string[] = []
  page.on('dialog', async (d) => {
    dialogs.push(d.message())
    await d.dismiss()
  })
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const app = `E2E Justified ${stamp}`
  const groupName = `E2E Requests ${stamp}`
  const tokenName = `E2E request token ${stamp}`
  const username = `e2e-req-${stamp}@acme.test`
  const justification = '<script>alert(1)</script><img src=x onerror=alert(1)>'
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)
  cleanup.remove('/api/v1/device-groups', groupName)
  cleanup.remove('/api/v1/software-catalog', app)
  cleanup.remove('/api/v1/software-assignments', app)

  const entry = await page.request.post('/api/v1/software-catalog', {
    headers: csrf,
    data: { name: app, approval: 'required', packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', package: `e2e-req-${stamp}` }] },
  })
  expect(entry.status()).toBe(201)
  const entryID = (await entry.json()).id as string
  const group = await page.request.post('/api/v1/device-groups', { headers: csrf, data: { name: groupName } })
  expect(group.status()).toBe(201)
  const groupID = (await group.json()).id as string
  expect((await page.request.post('/api/v1/software-assignments', {
    headers: csrf, data: { catalog_entry_id: entryID, device_group_id: groupID, intent: 'available' },
  })).status()).toBe(201)
  const token = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(token.status()).toBe(201)
  const config = JSON.stringify((await token.json()).enrollment_config)

  // devicesim prints the device ID once enrolled and sends the request once its bundle offers the entry: the server
  // opens a request only for an entry the device is offered, and enrollment tokens assign no group.
  const sim = spawn(devicesim, ['software-request', '--hostname', `e2e-req-${stamp}`, '--entry', entryID, '--user', username,
    '--justification', justification], { stdio: ['pipe', 'pipe', 'inherit'] })
  sim.stdin.end(config)
  const lines = createInterface({ input: sim.stdout })[Symbol.asyncIterator]()
  const exited = new Promise<number | null>((resolve) => sim.on('close', resolve))
  const deviceID = (JSON.parse((await lines.next()).value as string) as { device_id: string }).device_id
  expect((await page.request.put(`/api/v1/devices/${deviceID}/groups`, { headers: csrf, data: { device_group_ids: [groupID] } })).status()).toBe(200)
  expect(await exited).toBe(0)
  // The worker opens the request asynchronously.
  await expect.poll(async () => {
    const r = await page.request.get(`/api/v1/software-requests?q=${encodeURIComponent(username)}`)
    return ((await r.json()) as { total: number }).total
  }, { timeout: 120_000, intervals: [2_000] }).toBe(1)

  await page.goto('/software-requests')
  await expect(page.getByRole('heading', { level: 1, name: 'Software requests' })).toBeVisible()
  const list = page.getByTestId('software-request-list')
  await list.getByTestId('list-search').getByRole('searchbox').fill(username)
  const cell = list.getByRole('row').filter({ hasText: username }).getByTestId('request-justification')
  await expect(cell).toHaveText(justification)
  await expect(cell.locator('script, img')).toHaveCount(0)
  await expectAccessible(page)
  expect(dialogs).toEqual([])
  expect(csp).toEqual([])
})
