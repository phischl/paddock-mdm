import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M11 decisions 42 and 43: an adopted device shows its chips and the report-only banner, the device list filters
// it, and enabling enforcement is confirmed in a modal with the typed hostname.
test('organization admin enables enforcement on an adopted device', async ({ page, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-adopt-${stamp}`
  const tokenName = `E2E adoption token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim, ['enroll', '--hostname', hostname, '--enrollment-method', 'adopted'],
    { input: config, encoding: 'utf8', timeout: 90_000 })) as { device_id: string }

  // The device list filters by the adoption state; the filter is URL state.
  await page.goto('/devices?' + new URLSearchParams({ q: hostname, config_mode: 'report_only', enrollment_method: 'adopted' }).toString())
  await expect(page.getByRole('link', { name: hostname })).toBeVisible()
  await page.goto('/devices?' + new URLSearchParams({ q: hostname, config_mode: 'enforce' }).toString())
  await expect(page.getByRole('link', { name: hostname })).toHaveCount(0)

  await page.goto('/devices/' + device.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await expect(page.getByTestId('device-enrollment-method')).toHaveText('Adopted')
  await expect(page.getByTestId('device-report-only')).toHaveText('Report-only')
  await expectAccessible(page)

  await page.getByTestId('tab-apply-status').click()
  await expect(page.getByTestId('apply-report-only')).toBeVisible()
  await expectAccessible(page)

  await page.getByTestId('tab-overview').click()
  await page.getByTestId('enforce-device').click()
  const dialog = page.getByRole('dialog', { name: `Enable enforcement on ${hostname}?` })
  await expect(dialog).toContainText('never the last administrator')
  await expect(dialog.getByRole('button', { name: 'Enable enforcement' })).toBeDisabled()
  await dialog.getByTestId('confirm-typed').locator('input').fill(hostname)
  await expectAccessible(page)
  await dialog.getByRole('button', { name: 'Enable enforcement' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Enforcement is enabled' })).toBeVisible()
  await expect(page.getByTestId('device-report-only')).toHaveCount(0)
  await expect(page.getByTestId('enforce-device')).toHaveCount(0)
  await expectAccessible(page)
  expect(csp).toEqual([])
})
