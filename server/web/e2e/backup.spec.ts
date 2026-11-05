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
  const generated = page.waitForResponse((r) => r.url().endsWith('/api/platform/v1/backup/key') && r.request().method() === 'POST')
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
