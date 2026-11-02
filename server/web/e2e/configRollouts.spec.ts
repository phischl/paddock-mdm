import { expect, type Page } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'
import { test } from './cleanup'

const csrf = { 'X-Paddock-CSRF': '1' }

/** Switches staged rollouts on (waves 10, 50, 100, one minute each as a development stack allows) or off. */
async function setRollouts(page: Page, enabled: boolean): Promise<void> {
  const res = await page.request.put('/api/v1/settings/rollout', {
    headers: csrf,
    data: { enabled, waves: [10, 50, 100], min_wave_minutes: 1, failure_threshold_percent: 50, failure_threshold_min: 100 },
  })
  expect(res.status()).toBe(200)
}

/** Completes the rollouts other specs left open: an open rollout refuses every further staged write. */
async function completeOpenRollouts(page: Page): Promise<void> {
  const open = await page.request.get('/api/v1/config-rollouts?status=running&status=halted&page_size=100')
  for (const r of ((await open.json()) as { items: { id: string }[] }).items) {
    await page.request.post(`/api/v1/config-rollouts/${r.id}/complete`, { headers: csrf })
  }
}

// PDK-159 (plan M11 decision 36): a staged change set starts a rollout; the rollout page shows the wave strip and the
// counts, and every wave action is confirmed in a modal (halt with a reason, complete naming its consequence).
test('organization admin follows a staged rollout and acts on its waves', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await expect(page).toHaveURL(/\/$/)
  const held = `e2e-rollout-${Date.now()}`
  cleanup.remove('/api/v1/package-holds', held)
  try {
    await completeOpenRollouts(page)
    await setRollouts(page, true)
    const created = await page.request.post('/api/v1/package-holds', { headers: csrf, data: { package: held, reason: 'e2e' } })
    expect(created.status()).toBe(201)

    await mainNav(page).getByRole('link', { name: 'Configuration rollouts', exact: true }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Configuration rollouts' })).toBeVisible()
    const row = page.getByTestId('config-rollout-list').locator('tbody tr').first()
    await expect(row.getByTestId('config-rollout-status')).toHaveText('Running')
    await expect(row).toContainText('Wave 1 of 3 (10 %)')
    await expectAccessible(page)

    // The change set of the write names its rollout and links to it.
    await page.goto('/change-sets')
    const chip = page.getByTestId('change-set-list').getByTestId('change-set-rollout').first()
    await expect(chip).toHaveText('Staged')
    await expect(page.getByTestId('change-set-rollout-link').first()).toBeVisible()
    await page.getByTestId('change-set-rollout-link').first().click()
    await expect(page.getByRole('heading', { level: 1, name: 'Configuration rollout' })).toBeVisible()

    await expect(page.getByTestId('config-rollout-status')).toHaveText('Running')
    await expect(page.getByTestId('wave-1')).toHaveAttribute('aria-current', 'step')
    await expect(page.getByTestId('config-rollout-wave')).toHaveText('Wave 1 of 3 (10 %)')
    await expect(page.getByTestId('change-set-plan')).toContainText('package_holds')
    await expect(page.getByTestId('config-rollout-devices')).toBeVisible()
    await expectAccessible(page)

    await page.getByTestId('config-rollout-advance').click()
    const dialog = page.getByTestId('confirm-dialog')
    await expect(dialog.getByRole('heading', { name: 'Advance to the next wave' })).toBeVisible()
    await expectAccessible(page)
    await dialog.getByTestId('confirm-accept').click()
    await expect(page.getByTestId('config-rollout-wave')).toHaveText('Wave 2 of 3 (50 %)')
    await expect(page.getByTestId('wave-2')).toHaveAttribute('aria-current', 'step')

    // Halt needs a reason: the button stays disabled until one is typed.
    await page.getByTestId('config-rollout-halt').click()
    const accept = dialog.getByTestId('confirm-accept')
    await expect(accept).toBeDisabled()
    await dialog.getByTestId('confirm-reason').getByRole('textbox').fill('E2E: pausing')
    await accept.click()
    await expect(page.getByTestId('config-rollout-status')).toHaveText('Halted')
    await expect(page.getByTestId('config-rollout-halted-reason')).toHaveText('E2E: pausing')
    await expectAccessible(page)

    await page.getByTestId('config-rollout-resume').click()
    await dialog.getByTestId('confirm-accept').click()
    await expect(page.getByTestId('config-rollout-status')).toHaveText('Running')

    await page.getByTestId('config-rollout-complete').click()
    await expect(dialog).toContainText('Every device receives this change at its next check-in')
    await dialog.getByTestId('confirm-accept').click()
    await expect(page.getByTestId('config-rollout-status')).toHaveText('Completed')
    await expect(page.getByTestId('config-rollout-complete')).toHaveCount(0)

    // No horizontal page scroll on a phone.
    await page.setViewportSize({ width: 375, height: 812 })
    await expectAccessible(page)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    expect(csp).toEqual([])
  } finally {
    await setRollouts(page, false)
  }
})

// PDK-159 (plan M11 decision 37): the urgent opt-out shows only while rollouts are enabled, needs a reason, and runs
// the step-up the server asks for before the write succeeds; the change set then shows urgent and the reason.
test('organization admin applies an urgent change with a reason and a step-up', async ({ page, cleanup }) => {
  test.setTimeout(180_000)
  const csp = watchCSP(page)
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await expect(page).toHaveURL(/\/$/)
  const held = `e2e-urgent-${Date.now()}`
  cleanup.remove('/api/v1/package-holds', held)
  try {
    await completeOpenRollouts(page)
    await setRollouts(page, false)
    await page.goto('/package-holds')
    await page.getByTestId('create-hold').click()
    await expect(page.getByTestId('hold-package')).toBeVisible()
    await expect(page.getByTestId('urgent-opt-out')).toHaveCount(0)
    await page.keyboard.press('Escape')

    await setRollouts(page, true)
    await page.goto('/package-holds')
    await page.getByTestId('create-hold').click()
    await page.getByTestId('hold-package').locator('input').fill(held)
    const urgent = page.getByTestId('urgent-checkbox').getByRole('checkbox')
    await expect(urgent).not.toBeChecked()
    await expectAccessible(page)
    await urgent.check()
    await page.getByTestId('save-hold').click()
    await expect(page.getByText('Enter a reason of 2 to 500 characters.')).toBeVisible()
    await page.getByTestId('urgent-reason').getByRole('textbox').fill('E2E: urgent fix')
    await stepUp(page, () => page.getByTestId('save-hold').click(), 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
    await expect(page.getByTestId('hold-list')).toContainText(held)

    await page.goto('/change-sets')
    const list = page.getByTestId('change-set-list')
    await expect(list.getByTestId('change-set-rollout').first()).toHaveText('Urgent')
    await list.getByRole('button', { name: /Details of the change set/ }).first().click()
    await expect(page.getByTestId('change-set-urgent-reason')).toContainText('E2E: urgent fix')
    await expectAccessible(page)
    expect(csp).toEqual([])
  } finally {
    await setRollouts(page, false)
  }
})
