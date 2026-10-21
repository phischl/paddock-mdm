import { execFileSync } from 'node:child_process'
import { expect, type Page } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// An unencrypted disk whose layout can be encrypted in place on a device that still uses initramfs-tools (plan M8e
// decisions 3 and 34).
const health = JSON.stringify({
  reconcile: 'ok',
  disk: {
    state: 'not_encrypted', keyslots: 0, boot_separate: true,
    conversion: { eligible: true, layout: 'lvm', release: '24.04', initramfs: 'initramfs-tools', initramfs_removes: ['brltty', 'initramfs-tools'] },
  },
})

/** Waits until a new step-up is possible: the last one is older than the maximum authentication age and its TOTP window. */
async function authAgePassed(page: Page): Promise<void> {
  await expect.poll(async () => {
    const { step_up: s } = (await (await page.request.get('/api/v1/me')).json()) as { step_up: { at: string | null; max_auth_age_seconds: number } }
    if (s.at === null) return true
    const at = Date.parse(s.at)
    return Date.now() - at > (s.max_auth_age_seconds + 1) * 1000 && Math.floor(Date.now() / 30_000) > Math.floor(at / 30_000)
  }, { timeout: 90_000, intervals: [2_000] }).toBe(true)
}

// Plan M8e decisions 24, 25 and 8: an eligible device offers the in-place encryption; the request needs a step-up,
// the backup acknowledgement, a reason and the typed hostname; the card then follows the request, which is cancelled
// before the device received it. Accessible, no CSP violations.
test('organization admin requests and cancels the in-place encryption of a device', async ({ page, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-enc-${stamp}`
  const tokenName = `E2E encryption token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim, ['disk', '--hostname', hostname, '--health', health], { input: config, encoding: 'utf8', timeout: 90_000 })) as
    { device_id: string }

  // The worker stores the check-in's health asynchronously.
  const card = page.getByTestId('disk-encryption')
  await expect(async () => {
    await page.goto('/devices/' + device.device_id)
    await expect(card.getByTestId('disk-convert-eligible')).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await expect(card.getByTestId('disk-convert-eligible')).toContainText('Its disk layout allows encrypting it in place')
  await expectAccessible(page)

  await stepUp(page, () => card.getByRole('button', { name: 'Encrypt this device…' }).click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const dialog = page.getByRole('dialog', { name: `Encrypt ${hostname} in place` })
  const accept = dialog.getByRole('button', { name: 'Encrypt at the next restart' })
  await expect(dialog).toContainText('this removes the packages brltty, initramfs-tools')
  await expect(dialog).toContainText('The background encryption takes minutes to hours')
  await dialog.getByTestId('encrypt-reason').getByRole('textbox').fill('E2E: policy')
  await dialog.getByTestId('encrypt-typed').locator('input').fill(hostname)
  await expect(accept).toBeDisabled()
  await dialog.getByRole('checkbox', { name: /a current backup of this device exists/ }).check()
  await expect(accept).toBeEnabled()
  await expectAccessible(page)
  await accept.click()
  await expect(dialog).toBeHidden()
  await expect(card.getByTestId('disk-convert-notice')).toHaveText('Encryption requested.')
  await expect(card.getByTestId('disk-convert-phase')).toHaveText('Encryption requested — Pending. The device prepares itself at its next check-in.')
  await expect(page).not.toHaveURL(/stepup/)

  // Cancel before the device received the command: a new step-up and the typed hostname.
  await authAgePassed(page)
  await stepUp(page, () => card.getByRole('button', { name: 'Cancel encryption' }).click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const cancel = page.getByRole('dialog', { name: `Cancel the encryption of ${hostname}` })
  await expect(cancel.getByRole('button', { name: 'Cancel encryption' })).toBeDisabled()
  await cancel.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expectAccessible(page)
  await cancel.getByRole('button', { name: 'Cancel encryption' }).click()
  await expect(card.getByTestId('disk-convert-notice')).toHaveText('Encryption cancelled.')
  await expect(card.getByTestId('disk-convert-phase')).toContainText('the disk is unchanged')
  await expect(card.getByRole('button', { name: 'Encrypt this device…' })).toBeVisible()
  expect(csp).toEqual([])
})
