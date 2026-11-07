import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { expect } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

// The reference device client (test/acceptance/cmd/devicesim), built by `make e2e`.
const devicesim = process.env.PADDOCK_E2E_DEVICESIM ?? '../../bin/devicesim'
const csrf = { 'X-Paddock-CSRF': '1' }

// ADR 0048 decision 4, plan M12 decision 14: an administrator requests a diagnostics bundle on the device page with a
// reason, the device (devicesim) uploads it, the download runs the step-up and serves the archive the device sealed,
// and the purge is confirmed in a dialog. The auditor sees neither the tab, the page nor the navigation entry.
test('organization admin requests, downloads and purges a diagnostics bundle', async ({ page, cleanup }) => {
  test.setTimeout(400_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const stamp = Date.now()
  const hostname = `e2e-diag-${stamp}`
  const tokenName = `E2E diagnostics token ${stamp}`
  cleanup.remove('/api/v1/enrollment-tokens', tokenName)

  const res = await page.request.post('/api/v1/enrollment-tokens', {
    headers: csrf,
    data: { name: tokenName, expires_at: new Date(stamp + 3600_000).toISOString(), max_uses: 1, auto_approve: true },
  })
  expect(res.status()).toBe(201)
  const config = JSON.stringify((await res.json()).enrollment_config)

  // devicesim prints the device ID once enrolled and keeps checking in until the collection is requested.
  const sim = spawn(devicesim, ['diagnostics', '--hostname', hostname], { stdio: ['pipe', 'pipe', 'inherit'] })
  sim.stdin.end(config)
  const lines = createInterface({ input: sim.stdout })[Symbol.asyncIterator]()
  const exited = new Promise<number | null>((resolve) => sim.on('close', resolve))
  const deviceID = (JSON.parse((await lines.next()).value as string) as { device_id: string }).device_id

  await page.goto('/devices/' + deviceID)
  await expect(page.getByRole('heading', { name: hostname })).toBeVisible()
  await page.getByTestId('tab-diagnostics').click()
  await expect(page).toHaveURL(new RegExp(`/devices/${deviceID}/diagnostics`))
  await page.getByTestId('diagnostics-request').click()
  const dialog = page.getByRole('dialog', { name: 'Request diagnostics' })
  await expect(dialog.getByTestId('diagnostics-request-text')).toHaveText(
    'Paddock will collect its own logs and configuration from this device — nothing else. The user is told on the device. ' +
    'Give a reason; it is shown to the user and recorded.')
  await dialog.getByTestId('diagnostics-reason').locator('textarea').first().fill('VPN fails since Monday')
  await expectAccessible(page)
  await dialog.getByTestId('diagnostics-request-submit').click()
  await expect(page.getByTestId('diagnostics-requested')).toBeVisible()

  const sum = (JSON.parse((await lines.next()).value as string) as { archive_sha256: string }).archive_sha256
  expect(await exited).toBe(0)
  // The worker verifies the upload asynchronously.
  await expect.poll(async () => {
    const r = await page.request.get(`/api/v1/devices/${deviceID}/diagnostics?state=stored`)
    return ((await r.json()) as { total: number }).total
  }, { timeout: 180_000, intervals: [3_000] }).toBe(1)

  await page.reload()
  const list = page.getByTestId('diagnostics-list')
  await expect(list.getByTestId('diagnostics-state-stored')).toBeVisible()
  // devicesim has no desktop session: the bundle reports notified_sessions 0 (PDK-878).
  await expect(list.getByTestId('diagnostics-not-notified')).toHaveText('User not notified')
  await expectAccessible(page)
  const download = page.waitForEvent('download')
  await stepUp(page, () => list.getByTestId('diagnostics-download').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const file = await download
  expect(file.suggestedFilename()).toMatch(new RegExp(`^paddock-diagnostics-${hostname}-[0-9a-f-]+\\.tar\\.gz$`))
  expect(createHash('sha256').update(await readFile(await file.path())).digest('hex')).toBe(sum)
  await expect(page).not.toHaveURL(/stepup/)

  // The fleet page lists the bundle; the purge is confirmed in a dialog.
  await mainNav(page).getByRole('link', { name: 'Diagnostics', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Diagnostics bundles' })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(hostname)
  const row = page.getByTestId('diagnostics-list').getByRole('row').filter({ hasText: hostname })
  await expect(row.getByTestId('diagnostics-state-stored')).toBeVisible()
  await expectAccessible(page)
  await row.getByTestId('diagnostics-purge').click()
  await page.getByRole('dialog', { name: 'Purge diagnostics bundle' }).getByRole('button', { name: 'Purge' }).click()
  await expect(row.getByTestId('diagnostics-state-purged')).toBeVisible()
  expect(csp).toEqual([])
})

test('auditor sees no diagnostics tab, page or navigation entry', async ({ page }) => {
  const csp = watchCSP(page)
  await login(page, 'bob@acme.test', 'dev_bob_password')
  await expect(page).toHaveURL(/\/audit$/)
  await expect(mainNav(page).getByRole('link', { name: 'Diagnostics', exact: true })).toHaveCount(0)
  const devices = await page.request.get('/api/v1/devices?page_size=10')
  const first = ((await devices.json()) as { items: { id: string }[] }).items[0]
  if (first) {
    await page.goto('/devices/' + first.id)
    await expect(page.getByTestId('tab-apply-status')).toBeVisible()
    await expect(page.getByTestId('tab-diagnostics')).toHaveCount(0)
  }
  await page.goto('/diagnostics')
  await expect(page).toHaveURL(/\/audit$/)
  expect((await page.request.get('/api/v1/diagnostics')).status()).toBe(403)
  expect(csp).toEqual([])
})
