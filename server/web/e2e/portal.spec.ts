import { expect, test, type Page } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'

test('organization admin manages a device group and sees the audit trail', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await expect(page).toHaveURL(/\/device-groups$/)
  await expect(page.getByTestId('user-role')).toHaveText('Organization administrator')
  await expectAccessible(page)

  const name = `E2E ${Date.now()}`
  const renamed = `${name} renamed`

  await page.getByTestId('create-device-group').click()
  const createDialog = page.getByRole('dialog', { name: 'New device group' })
  await createDialog.getByLabel('Name').fill(name)
  await createDialog.getByLabel('Description').fill('created by the e2e test')
  await expectAccessible(page)
  await createDialog.getByRole('button', { name: 'Create' }).click()
  await expect(createDialog).toBeHidden()
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible()

  await page.getByRole('button', { name: `Edit ${name}` }).click()
  const editDialog = page.getByRole('dialog', { name: 'Edit device group' })
  await editDialog.getByLabel('Name').fill(renamed)
  await editDialog.getByRole('button', { name: 'Save' }).click()
  await expect(editDialog).toBeHidden()
  await expect(page.getByRole('cell', { name: renamed, exact: true })).toBeVisible()

  // Deleting asks in a modal (ADR 0018): Cancel keeps the group, focus starts on Cancel.
  await page.getByRole('button', { name: `Delete ${renamed}` }).click()
  const deleteDialog = page.getByRole('dialog', { name: 'Delete device group' })
  await expect(deleteDialog).toContainText(`Delete the device group ${renamed}? This cannot be undone.`)
  await expect(deleteDialog.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await expectAccessible(page)
  await deleteDialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(deleteDialog).toBeHidden()
  await expect(page.getByRole('cell', { name: renamed, exact: true })).toBeVisible()

  await page.getByRole('button', { name: `Delete ${renamed}` }).click()
  await deleteDialog.getByRole('button', { name: 'Delete' }).click()
  await expect(deleteDialog).toBeHidden()
  await expect(page.getByRole('cell', { name: renamed, exact: true })).toHaveCount(0)

  // The audit pipeline is asynchronous (outbox → RabbitMQ → audit writer): poll the audit page, narrowed to this
  // test's group by the search.
  await page.getByRole('link', { name: 'Audit log' }).click()
  await expect(page).toHaveURL(/\/audit$/)
  await page.goto('/audit?q=' + encodeURIComponent(name))
  const expected = [
    `alice@acme.test created the device group ${name}`,
    `alice@acme.test updated the device group ${renamed}`,
    `alice@acme.test deleted the device group ${renamed}`,
  ]
  await expect(async () => {
    await page.reload()
    for (const text of expected) {
      await expect(page.getByText(text, { exact: true })).toBeVisible({ timeout: 1_000 })
    }
  }).toPass({ timeout: 60_000 })
  // The cancelled attempt left no event: exactly one deletion.
  await expect(page.getByText(`alice@acme.test deleted the device group ${renamed}`, { exact: true })).toHaveCount(1)
  await expectAccessible(page)
  expect(csp).toEqual([])
})

/** Creates device groups through the API with the signed-in browser session and returns their IDs. */
async function createGroups(page: Page, names: string[]): Promise<string[]> {
  const ids: string[] = []
  for (const name of names) {
    const res = await page.request.post('/api/v1/device-groups', { headers: { 'X-Paddock-CSRF': '1' }, data: { name } })
    expect(res.status()).toBe(201)
    ids.push((await res.json()).id)
  }
  return ids
}

async function deleteGroups(page: Page, ids: string[]): Promise<void> {
  for (const id of ids) {
    await page.request.delete('/api/v1/device-groups/' + id, { headers: { 'X-Paddock-CSRF': '1' } })
  }
}

/** Names in the first column of the list. */
function firstColumn(page: Page) {
  return page.locator('.v-data-table tbody tr td:first-child')
}

test('device group list searches, sorts, pages and keeps its state in the URL', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const prefix = `E2E list ${Date.now()}`
  const names = Array.from({ length: 12 }, (_, i) => `${prefix} ${String(i + 1).padStart(2, '0')}`)
  const ids = await createGroups(page, names)
  try {
    await page.goto('/device-groups')
    await page.getByTestId('list-search').getByRole('searchbox').fill(prefix)
    await expect(page).toHaveURL(/[?&]q=/)
    await expect(page.getByTestId('list-range')).toHaveText('1–12 of 12 results')

    // 10 items per page: page numbers appear.
    await page.getByTestId('list-page-size').click()
    await page.getByRole('option', { name: '10', exact: true }).click()
    await expect(page).toHaveURL(/page_size=10/)
    await expect(firstColumn(page)).toHaveCount(10)
    const pagination = page.getByRole('navigation', { name: 'Pagination Navigation' })
    await expect(pagination.getByRole('button', { name: 'Go to page 2' })).toBeVisible()
    await expectAccessible(page)
    await pagination.getByRole('button', { name: 'Go to page 2' }).click()
    await expect(page).toHaveURL(/page=2/)
    await expect(firstColumn(page)).toHaveText([names[10], names[11]])

    // Reload keeps page, page size and search.
    await page.reload()
    await expect(page.getByTestId('list-range')).toHaveText('11–12 of 12 results')
    await expect(page.getByTestId('list-search').getByRole('searchbox')).toHaveValue(prefix)

    // Sorting by name descending starts again at page 1.
    await page.getByRole('columnheader', { name: 'Name' }).click()
    await expect(page).toHaveURL(/sort=-name/)
    await expect(page).not.toHaveURL(/page=2/)
    await expect(firstColumn(page).first()).toHaveText(names[11])

    // A search without hits shows the empty state.
    await page.getByTestId('list-search').getByRole('searchbox').fill(prefix + ' none')
    await expect(page.getByText('No results match the search or filters.')).toBeVisible()
    await expectAccessible(page)
  } finally {
    await deleteGroups(page, ids)
  }
  expect(csp).toEqual([])
})

test('audit log filters by outcome and keeps the filter on reload', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'bob@acme.test', 'dev_bob_password')
  await expect(page).toHaveURL(/\/audit$/)
  await page.getByTestId('list-filter-outcome').click()
  await page.getByRole('option', { name: 'Success' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/outcome=success/)
  const outcomes = page.locator('.v-data-table tbody td .outcome')
  await expect(async () => {
    const texts = await outcomes.allTextContents()
    expect(texts.length).toBeGreaterThan(0)
    expect(new Set(texts)).toEqual(new Set(['Success']))
  }).toPass({ timeout: 15_000 })
  await page.reload()
  await expect(page).toHaveURL(/outcome=success/)
  await expect(page.getByTestId('list-filter-outcome')).toContainText('Success')
  await page.getByRole('columnheader', { name: 'Time' }).click()
  await expect(page).toHaveURL(/sort=occurred_at/)
  await expectAccessible(page)
  expect(csp).toEqual([])
})

test('auditor sees the audit log but cannot create device groups', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'bob@acme.test', 'dev_bob_password')
  await expect(page).toHaveURL(/\/audit$/)
  await expect(page.getByTestId('audit-table')).toBeVisible()
  await expectAccessible(page)
  await page.getByRole('link', { name: 'Device groups' }).click()
  await expect(page.getByRole('heading', { name: 'Device groups' })).toBeVisible()
  await expect(page.getByTestId('create-device-group')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /^Edit / })).toHaveCount(0)
  await expectAccessible(page)
  expect(csp).toEqual([])
})

test('platform admin sees the organizations page', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'platform-admin@paddock.test', 'dev_platform_admin_password')
  await expect(page).toHaveURL(/\/platform\/organizations$/)
  await expect(page.getByRole('cell', { name: 'acme', exact: true })).toBeVisible()
  await expectAccessible(page)

  await page.getByTestId('list-search').getByRole('searchbox').fill('glob')
  await expect(page).toHaveURL(/q=glob/)
  await expect(page.getByRole('cell', { name: 'globex', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'acme', exact: true })).toHaveCount(0)
  await page.getByTestId('list-search').getByRole('searchbox').fill('')
  await page.getByTestId('list-filter-status').click()
  await page.getByRole('option', { name: 'Suspended' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/status=suspended/)
  await expect(page.getByRole('cell', { name: 'acme', exact: true })).toHaveCount(0)
  await page.goto('/platform/organizations?sort=-slug')
  await expect(page.getByRole('columnheader', { name: 'Slug' })).toHaveAttribute('aria-sort', 'descending')
  await expectAccessible(page)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expectAccessible(page)
  expect(csp).toEqual([])
})

test('login denied page is accessible', async ({ page }) => {
  const csp = watchCSP(page)
  const res = await page.goto('/login-denied?reason=not_authorized')
  const policy = res?.headers()['content-security-policy'] ?? ''
  expect(policy).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/]+={0,2}'/)
  expect(policy).not.toContain('unsafe-inline')
  await expect(page.getByTestId('login-denied-message')).toContainText('not authorized')
  await expectAccessible(page)
  expect(csp).toEqual([])
})
