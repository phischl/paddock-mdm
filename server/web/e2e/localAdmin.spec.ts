import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M4a step 6: Rotate now lists a command; Reveal needs a step-up (password and TOTP) and the typed hostname,
// shows the escrowed password with a copy button and hides it after 60 s; accessible and without CSP violations.
test('organization admin rotates and reveals the local administrator password', async ({ page, context, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-la-${stamp}`
  const tokenName = `E2E local admin token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  // A simulated device that escrowed and confirmed its first password.
  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim, ['local-admin', '--hostname', hostname], { input: config, encoding: 'utf8', timeout: 150_000 })) as
    { device_id: string; password: string }

  await page.goto('/devices/' + device.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  const card = page.getByTestId('local-admin')
  await expect(card.getByTestId('local-admin-active')).toHaveText('1')
  await expectAccessible(page)

  // Rotate now: confirmed in a dialog, listed as a pending command.
  await card.getByTestId('local-admin-rotate').click()
  const rotate = page.getByRole('dialog', { name: 'Rotate the local administrator password' })
  await rotate.getByRole('button', { name: 'Rotate now' }).click()
  await expect(card.getByRole('status')).toHaveText('The device rotates the password with its next check-in.')
  await expect(page.getByTestId('command-list').getByRole('row').filter({ hasText: 'Rotate the local administrator password' }))
    .toContainText('Pending')

  // Reveal: step-up, typed hostname, password with copy button.
  await stepUp(page, () => card.getByTestId('local-admin-reveal').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const confirm = page.getByRole('dialog', { name: 'Reveal the local administrator password' })
  await expect(confirm.getByRole('button', { name: 'Reveal password' })).toBeDisabled()
  await confirm.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expectAccessible(page)
  await confirm.getByRole('button', { name: 'Reveal password' }).click()
  const revealed = page.getByTestId('revealed-dialog')
  await expect(revealed.getByTestId('revealed-active').locator('input')).toHaveValue(device.password)
  await expectAccessible(page)
  await revealed.getByTestId('copy-active').click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(device.password)
  await expect(page).not.toHaveURL(/stepup/)

  // The password is hidden after 60 s and is nowhere in the page.
  await expect(revealed).toBeHidden({ timeout: 75_000 })
  expect(await page.content()).not.toContain(device.password)
  expect(csp).toEqual([])
})
