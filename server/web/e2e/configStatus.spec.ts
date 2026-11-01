import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M11 decision 15: a device that reported a failed resource lists it in its Apply status tab (filterable, the
// state in the URL) and the Configuration status page counts it fleet-wide.
test('organization admin sees failed resources on the device and on the fleet page', async ({ page, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-cfg-${stamp}`
  const tokenName = `E2E config status token ${stamp}`
  const failedID = `unit:e2e-fail-${stamp}.service`
  const okID = `file:/etc/e2e-ok-${stamp}.conf`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim,
    ['config-report', '--hostname', hostname, '--resource', `${okID}=applied`, '--resource', `${failedID}=failed:unit not found`],
    { input: config, encoding: 'utf8', timeout: 150_000 })) as { device_id: string }

  // The worker records the report asynchronously.
  await expect.poll(async () => {
    const r = await page.request.get(`/api/v1/devices/${device.device_id}/config-status`)
    return ((await r.json()) as { total: number }).total
  }, { timeout: 120_000, intervals: [2_000] }).toBe(2)

  await page.goto('/devices/' + device.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await page.getByTestId('tab-apply-status').click()
  await expect(page).toHaveURL(new RegExp(`/devices/${device.device_id}/apply-status`))
  const list = page.getByTestId('apply-status-list')
  await expect(list.getByRole('row').filter({ hasText: failedID })).toContainText('unit not found')
  await expect(list.getByRole('row').filter({ hasText: failedID })).toContainText('Failed')
  await expect(list.getByRole('row').filter({ hasText: okID })).toContainText('Applied')
  await expect(page.getByTestId('bundle-history-list').getByRole('row').filter({ hasText: 'Applied' })).not.toHaveCount(0)
  await expectAccessible(page)

  // The filter is URL state, so a reload must keep it.
  await list.getByTestId('list-filter-status').click()
  await page.getByRole('option', { name: 'Failed' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/status=failed/)
  await expect(list.getByRole('row').filter({ hasText: okID })).toHaveCount(0)
  await page.reload()
  await expect(page).toHaveURL(/status=failed/)
  await expect(list.getByRole('row').filter({ hasText: failedID })).toBeVisible()
  await expect(list.getByRole('row').filter({ hasText: okID })).toHaveCount(0)

  // The fleet page counts the failed resource.
  await page.goto('/device-groups')
  await mainNav(page).getByRole('link', { name: 'Configuration status', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Configuration status', exact: true })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(failedID)
  const row = page.getByTestId('config-status-list').getByRole('row').filter({ hasText: failedID })
  await expect(row.getByTestId('config-status-failed')).toHaveText('1')
  await expectAccessible(page)
  expect(csp).toEqual([])
})
