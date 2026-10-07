import { execFileSync } from 'node:child_process'
import { expect } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// Plan M5a decision 10: a device that reported its packages through Fleet shows them in its Software tab and on the
// organization's Software page; the Vulnerabilities pages filter by severity (unknown included, Fleet free reports
// no score) and the start page carries the vulnerability tile; accessible and without CSP violations.
test('organization admin sees the software and vulnerabilities of devices', async ({ page, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-inv-${stamp}`
  const pkg = `paddock-e2e-${stamp}`
  const tokenName = `E2E inventory token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  // The start page tile counts devices with critical or high findings and those with findings of unknown severity.
  await expect(page).toHaveURL(/\/device-groups$/)
  const tile = page.getByTestId('vulnerability-tile')
  await expect(tile.getByRole('link', { name: /critical or high findings/ })).toBeVisible()
  await expect(tile.getByRole('link', { name: /findings of unknown severity/ })).toBeVisible()
  await expectAccessible(page)

  // A simulated device whose osquery host reported two packages to Fleet; the worker syncs within a round.
  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)
  const device = JSON.parse(execFileSync(devicesim,
    ['inventory', '--hostname', hostname, '--package', `${pkg}=1.0-1`, '--package', 'apport=2.28.3-0ubuntu0.1'],
    { input: config, encoding: 'utf8', timeout: 150_000 })) as { device_id: string }
  await expect.poll(async () => {
    const sw = await page.request.get(`/api/v1/devices/${device.device_id}/software`)
    return ((await sw.json()) as { total: number }).total
  }, { timeout: 180_000, intervals: [5_000] }).toBe(2)

  // Device detail: the Software tab lists the packages, searchable, with the state in the URL.
  await page.goto('/devices/' + device.device_id)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await page.getByTestId('tab-software').click()
  await expect(page).toHaveURL(new RegExp(`/devices/${device.device_id}/software`))
  const software = page.getByTestId('device-software-list')
  await expect(software.getByRole('row').filter({ hasText: pkg })).toContainText('1.0-1')
  await expect(software.getByRole('row').filter({ hasText: 'apport' })).toContainText('deb_packages')
  await page.getByTestId('list-search').getByRole('searchbox').fill(pkg)
  await expect(page).toHaveURL(/[?&]q=/)
  await expect(software.getByRole('row').filter({ hasText: 'apport' })).toHaveCount(0)
  await expectAccessible(page)

  // The Vulnerabilities tab filters by severity.
  await page.getByTestId('tab-vulnerabilities').click()
  await expect(page).toHaveURL(new RegExp(`/devices/${device.device_id}/vulnerabilities`))
  await expect(page.getByTestId('device-vulnerability-list')).toBeVisible()
  await page.getByTestId('list-filter-severity').click()
  await page.getByRole('option', { name: 'Unknown' }).click()
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL(/severity=unknown/)
  await expectAccessible(page)

  // The organization's Software page counts the device.
  await page.goto('/device-groups')
  await page.getByRole('link', { name: 'Software', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Software', exact: true })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(pkg)
  const row = page.getByTestId('software-list').getByRole('row').filter({ hasText: pkg })
  await expect(row).toContainText('1.0-1')
  await expect(row).toContainText('Without matched CVEs')
  await page.getByRole('columnheader', { name: 'Devices' }).click()
  await expect(page).toHaveURL(/sort=device_count/)
  await expectAccessible(page)

  // The organization's Vulnerabilities page with the severity filter of the tile.
  await page.goto('/device-groups')
  await tile.getByRole('link', { name: /findings of unknown severity/ }).click()
  await expect(page).toHaveURL(/\/vulnerabilities\?.*severity=unknown/)
  await expect(page.getByRole('heading', { name: 'Vulnerabilities', exact: true })).toBeVisible()
  await expect(page.getByTestId('list-filter-severity')).toContainText('Unknown')
  await expectAccessible(page)
  expect(csp).toEqual([])
})
