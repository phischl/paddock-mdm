import { expect, type Page } from '@playwright/test'
import { login, stepUp } from './auth'
import { expectAccessible, watchCSP } from './checks'
import { test } from './cleanup'

const root = ['platform-admin@paddock.test', 'dev_platform_admin_password', 'dev_platform_admin_totp_key'] as const

/** Runs start; a step-up that is still valid for a while is reused, else it is completed as the platform admin. */
async function withStepUp(page: Page, start: () => Promise<void>): Promise<void> {
  const me = await (await page.request.get('/api/v1/me')).json() as { step_up_valid_until: string | null }
  const validFor = me.step_up_valid_until ? Date.parse(me.step_up_valid_until) - Date.now() : 0
  if (validFor > 10_000) await start()
  else await stepUp(page, start, ...root)
}

// Plan M15 decisions 27 and 29: the targets list, the key dialog with a wrong and a right confirmation (the positions
// come from the API response of the generation), and no browser dialogs. The spec generates one key and needs a stack
// without a key that waits for its confirmation (the start button is disabled while one does).
test('platform admin generates and confirms the backup key', async ({ page }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  const dialogs: string[] = []
  page.on('dialog', (d) => { dialogs.push(d.type()); void d.dismiss() })
  await login(page, ...root.slice(0, 2) as [string, string])
  await page.goto('/platform/backup?tab=targets')
  await expect(page.getByRole('heading', { name: 'Backup' })).toBeVisible()
  await expect(page.getByTestId('backup-target-list')).toBeVisible()
  await expectAccessible(page)

  await page.getByTestId('backup-tab-key').click()
  const generated = page.waitForResponse((r) => r.url().endsWith('/api/platform/v1/backup/key') && r.request().method() === 'POST' && r.status() === 201)
  await withStepUp(page, async () => {
    await page.getByTestId('backup-key-start').click()
    await page.getByTestId('backup-key-generate').click()
  })
  const key = await (await generated).json() as { key: string; positions: number[] }
  const dialog = page.getByTestId('backup-key-dialog')
  await expect(page.getByTestId('backup-key-text').locator('input')).toHaveValue(key.key)
  await expect(page.getByTestId('backup-key-cancel')).toHaveCount(0)
  await expectAccessible(page)
  await page.getByTestId('backup-key-next').click()
  await expect(dialog).not.toContainText(key.key)

  const type = async (chars: string[]) => {
    for (const [i, c] of chars.entries()) await page.getByTestId(`backup-key-char-${i}`).fill(c)
    await page.getByTestId('backup-key-confirm').click()
  }
  await type(key.positions.map(() => '#'))
  await expect(page.getByTestId('backup-key-attempts')).toContainText('2 attempts left')
  await type(key.positions.map((p) => key.key[p - 1]))
  await expect(dialog).toHaveCount(0)

  await page.reload()
  await expect(page.getByTestId('backup-key-fingerprint')).toBeVisible()
  await expect(page.getByText(key.key)).toHaveCount(0)
  expect(dialogs).toEqual([])
  expect(csp).toEqual([])
})

test('the targets list and the key tab are keyboard reachable and accessible', async ({ page }) => {
  await login(page, ...root.slice(0, 2) as [string, string])
  await page.goto('/platform/backup')
  await expect(page.getByTestId('backup-key-banner')).toBeVisible()
  await expectAccessible(page)
  await page.getByTestId('backup-tab-targets').click()
  await expect(page).toHaveURL(/tab=targets/)
  await page.getByTestId('create-backup-target').click()
  await expect(page.getByRole('dialog', { name: 'Add a backup target' })).toBeVisible()
  await expectAccessible(page)
})

/**
 * Whether the local repository holds a successful run of every kind a plan of all components needs, as the server
 * checks it. The server refuses any other plan (409 invalid_state); a stack started without BACKUP=1, like CI's, never
 * has one.
 */
async function backupsReady(page: Page): Promise<boolean> {
  for (const kind of ['postgres', 'authentik', 'openbao', 'fleet', 'escrow']) {
    const res = await page.request.get(`/api/platform/v1/backup/runs?kind=${kind}&outcome=succeeded&page_size=10`)
    expect(res.status()).toBe(200)
    if ((await res.json() as { total: number }).total === 0) return false
  }
  return true
}

// Plan M15 decisions 25 and 27: a restore plan is only sent with the typed word; the created plan shows its host command.
// Needs a stack without an open restore plan (only one plan is open at a time). The typed word is checked on every
// stack; sending the plan needs successful backups, as the backup gates' requireBackupStack does.
test('the restore plan dialog requires the typed word, shows the host command and the plan is cancelled', async ({ page }) => {
  test.setTimeout(120_000)
  const dialogs: string[] = []
  page.on('dialog', (d) => { dialogs.push(d.type()); void d.dismiss() })
  await login(page, ...root.slice(0, 2) as [string, string])
  await page.goto('/platform/backup?tab=restore')
  await expect(page.getByTestId('backup-plan-list')).toBeVisible()
  await page.getByTestId('backup-plan-restore-tab').click()
  const submit = page.getByTestId('backup-restore-submit')
  await expect(page.getByTestId('backup-restore-consequence')).toContainText("replaces the control plane's databases")
  await expect(submit).toBeDisabled()
  await expectAccessible(page)
  await page.locator('#backup-restore-word').fill('restor')
  await expect(submit).toBeDisabled()
  await page.locator('#backup-restore-word').fill('restore')
  await expect(submit).toBeEnabled()
  const ready = await backupsReady(page)
  if (!ready) expect(dialogs).toEqual([])
  test.skip(!ready, 'sending a plan needs successful backups: start the stack with `make up BACKUP=1`, run `make dev-seed BACKUP=1` and let every kind back up once')
  await withStepUp(page, () => submit.click())
  await expect(page.getByTestId('backup-restore-command')).toContainText('restore')
  await expect(page.getByTestId('backup-restore-expiry')).toContainText('expires in')
  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByTestId('backup-restore-dialog')).toHaveCount(0)

  // Cancels the plan again so that the one-open-plan rule stays clean for later runs. A running plan, and with it the
  // Abandon action, cannot be reached from the portal: only the host starts a restore (covered by the component tests).
  const cancel = page.locator('[data-testid^="backup-plan-cancel-"]').first()
  await withStepUp(page, async () => {
    await cancel.click()
    const dialog = page.getByTestId('confirm-dialog')
    await expect(dialog.getByRole('heading', { name: 'Cancel the restore plan' })).toBeVisible()
    await dialog.getByTestId('confirm-accept').click()
  })
  await expect(page.getByTestId('backup-plan-list')).toContainText('Expired')
  expect(dialogs).toEqual([])
})
