import { execFileSync } from 'node:child_process'
import { expect, type Page } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

/**
 * Waits until the session's last step-up is older than the maximum auth age (development: 15 s, GET /api/v1/me) and
 * its TOTP code is out of date: Authentik would otherwise answer the next step-up without asking or refuse the reused
 * code, and each revocation needs a step-up of its own.
 */
async function authAgePassed(page: Page): Promise<void> {
  await expect.poll(async () => {
    const { step_up: s } = (await (await page.request.get('/api/v1/me')).json()) as { step_up: { at: string | null; max_auth_age_seconds: number } }
    if (s.at === null) return true
    const at = Date.parse(s.at)
    return Date.now() - at > (s.max_auth_age_seconds + 1) * 1000 && Math.floor(Date.now() / 30_000) > Math.floor(at / 30_000)
  }, { timeout: 90_000, intervals: [2_000] }).toBe(true)
}

// Plan M4c step 6: Lock and Destroy need a reason, a step-up and the typed hostname; a Destroy shows up in the
// device's revocation timeline and waits on the Revocations page, where its requester can only cancel it (another
// administrator approves). The Lock dialog is cancelled: an issued Lock would count towards alice's revocation limit
// (3 per hour) and freeze her after a few runs; gate R1 issues Locks. Accessible, no CSP violations.
test('organization admin requests and cancels revocations of a device', async ({ page, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-rv-${stamp}`
  const tokenName = `E2E revocation token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim, ['enroll', '--hostname', hostname], { input: config, encoding: 'utf8', timeout: 90_000 })) as
    { device_id: string; status: string }
  expect(device.status).toBe('active')

  await page.goto('/devices/' + device.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  const card = page.getByTestId('revocation')
  await expect(card.getByTestId('revocation-disabled')).toHaveCount(0)
  await expectAccessible(page)

  // Lock: reason, step-up, typed hostname.
  await card.getByLabel('Reason').fill('E2E: laptop reported stolen')
  await stepUp(page, () => card.getByTestId('revocation-lock').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const lock = page.getByRole('dialog', { name: 'Lock the device' })
  await expect(lock.getByRole('button', { name: 'Lock device' })).toBeDisabled()
  await lock.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expect(lock.getByRole('button', { name: 'Lock device' })).toBeEnabled()
  await expectAccessible(page)
  await lock.getByRole('button', { name: 'Cancel' }).click()
  await expect(lock).toBeHidden()
  await expect(card.getByTestId('revocation-requested')).toHaveCount(0)
  await expect(card.getByTestId('revocation-timeline')).toHaveCount(0)
  await expect(page).not.toHaveURL(/stepup/)

  // Destroy: waits for a second administrator.
  await authAgePassed(page)
  await card.getByLabel('Reason').fill('E2E: decommissioned')
  await stepUp(page, () => card.getByTestId('revocation-destroy').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const destroy = page.getByRole('dialog', { name: 'Destroy the device' })
  await expect(destroy).toContainText('A second administrator must approve this request')
  await destroy.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expect(destroy.getByRole('button', { name: 'Destroy device' })).toBeEnabled()
  await destroy.getByRole('button', { name: 'Destroy device' }).click()
  await expect(card.getByTestId('revocation-requested')).toContainText('waits for the approval of a second administrator')
  await expect(card.getByTestId('revocation-timeline').getByRole('row').filter({ hasText: 'Destroy' })).toContainText('Requested')

  // The revocations page: the requester may cancel, not approve.
  await mainNav(page).getByRole('link', { name: 'Revocations' }).click()
  await expect(page.getByRole('heading', { name: 'Revocations' })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(hostname)
  await expect(page).toHaveURL(/[?&]q=/)
  const row = page.getByTestId('revocation-list').getByRole('row').filter({ hasText: 'Destroy' })
  await expect(row).toContainText('Waiting for approval')
  await expect(row.getByTestId('revocation-approve')).toHaveCount(0)
  await expectAccessible(page)
  await authAgePassed(page)
  await stepUp(page, () => row.getByTestId('revocation-cancel').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const cancel = page.getByRole('dialog', { name: 'Cancel the destroy' })
  await cancel.getByTestId('confirm-typed').locator('input').fill(hostname)
  await cancel.getByRole('button', { name: 'Cancel request' }).click()
  await expect(page.getByTestId('revocation-reviewed')).toHaveText(`The destroy of ${hostname} was cancelled.`)
  await expect(page.getByTestId('revocation-list').getByRole('row').filter({ hasText: 'Destroy' })).toContainText('Cancelled')
  expect(csp).toEqual([])
})

// The dead man's switch settings name the consequence; a short period is warned about (plan M4c decision 15).
test("organization admin sees the dead man's switch warning", async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await mainNav(page).getByRole('link', { name: "Dead man's switch" }).click()
  await expect(page.getByTestId('dms-warning')).toHaveText(
    'If Paddock is unreachable for longer than this period, every device with the switch enabled locks itself.')
  await page.getByTestId('dms-period').locator('input').fill('10')
  await expect(page.getByTestId('dms-short-period')).toBeVisible()
  await page.getByTestId('dms-period').locator('input').fill('3')
  await expect(page.getByText('Enter a whole number of days from 7 to 365.')).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
