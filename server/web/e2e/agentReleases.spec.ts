import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, mainNav, watchCSP } from './checks'

// The release uploader (test/acceptance/cmd/agentrelease), built by `make e2e`.
const agentrelease = process.env.PADDOCK_E2E_AGENTRELEASE ?? '../../bin/agentrelease'

/** Uploads a signed (fake) agent binary as a published release and starts its rollout with the defaults. */
function releaseWithRollout(version: string): void {
  const dir = mkdtempSync(join(tmpdir(), 'paddock-e2e-'))
  const binary = join(dir, 'paddockd')
  writeFileSync(binary, `fake paddockd ${version}\n`)
  execFileSync(agentrelease, ['--version', version, '--artifact', `amd64=${binary}`, '--rollout', '--halt-running'], {
    encoding: 'utf8', timeout: 120_000,
  })
}

// Plan M2b §8: the agent releases page lists releases, shows the rollout of a release and halts it in a modal.
test('platform admin halts an agent rollout', async ({ page }) => {
  const csp = watchCSP(page)
  const version = `0.0.${Date.now()}-e2e`
  releaseWithRollout(version)
  await login(page, 'platform-admin@paddock.test', 'dev_platform_admin_password')

  await mainNav(page).getByRole('link', { name: 'Agent releases' }).click()
  await expect(page.getByRole('heading', { name: 'Agent releases' })).toBeVisible()
  await page.getByTestId('list-search').getByRole('searchbox').fill(version)
  await expect(page).toHaveURL(/q=/)
  const row = page.getByRole('row').filter({ hasText: version })
  await expect(row).toContainText('Published')
  await expect(row).toContainText('Running')
  await expectAccessible(page)

  await row.getByRole('link', { name: version }).click()
  await expect(page.getByRole('heading', { name: `Agent ${version}` })).toBeVisible()
  await expect(page.getByTestId('rollout-status')).toHaveText('Running')
  await expect(page.getByTestId('rollout-wave')).toContainText('Wave 1 of 4')
  await expect(page.getByTestId('release-artifacts')).toContainText('amd64')
  await expectAccessible(page)

  await page.getByTestId('rollout-halt').click()
  const dialog = page.getByRole('dialog', { name: 'Halt the rollout?' })
  await expect(dialog).toContainText(`No more devices will be offered agent ${version}.`)
  await expectAccessible(page)
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByTestId('rollout-status')).toHaveText('Running')

  await page.getByTestId('rollout-halt').click()
  await dialog.getByRole('button', { name: 'Halt rollout' }).click()
  await expect(page.getByTestId('rollout-status')).toHaveText('Halted')
  await expect(page.getByTestId('rollout-resume')).toBeVisible()
  await expectAccessible(page)
  expect(csp).toEqual([])
})
