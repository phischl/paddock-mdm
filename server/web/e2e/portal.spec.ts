import { expect, test, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { login } from './auth'

/** Fails on serious or critical axe violations. */
async function expectAccessible(page: Page): Promise<void> {
  // Check the settled page: transitions (dialogs fading in) start a frame after the triggering click, so wait for
  // two frames, then for every finite animation; endless ones (loaders) never finish.
  await page.evaluate(async () => {
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))
    const finite = document.getAnimations().filter((a) => a.effect?.getComputedTiming().iterations !== Infinity)
    await Promise.all(finite.map((a) => a.finished.catch(() => undefined)))
  })
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
  const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  expect(blocking.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([])
}

/** Records CSP violations reported by the browser. */
function watchCSP(page: Page): string[] {
  const violations: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error' && /Content Security Policy/i.test(msg.text())) violations.push(msg.text())
  })
  return violations
}

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

  await page.getByRole('button', { name: `Delete ${renamed}` }).click()
  const deleteDialog = page.getByRole('dialog', { name: 'Delete device group' })
  await expectAccessible(page)
  await deleteDialog.getByRole('button', { name: 'Delete' }).click()
  await expect(deleteDialog).toBeHidden()
  await expect(page.getByRole('cell', { name: renamed, exact: true })).toHaveCount(0)

  // The audit pipeline is asynchronous (outbox → RabbitMQ → audit writer): poll the audit page.
  await page.getByRole('link', { name: 'Audit log' }).click()
  await expect(page).toHaveURL(/\/audit$/)
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
