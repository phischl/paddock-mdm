import { expect, type Page } from '@playwright/test'
import { login, loginWithPassword, stepUp, tempUser } from './auth'
import { expectAccessible, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

const alice = ['alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key'] as const
const root = ['platform-admin@paddock.test', 'dev_platform_admin_password', 'dev_platform_admin_totp_key'] as const

/**
 * Runs start, which triggers an action that needs a step-up. When the session's last step-up is still valid for a
 * while (GET /api/v1/me step_up_valid_until), the portal does not start a new one and the action runs at once;
 * otherwise the step-up is completed as user (stepUp would wait forever for a step-up the portal never starts).
 */
async function withStepUp(page: Page, start: () => Promise<void>, user: readonly [string, string, string]): Promise<void> {
  const me = await (await page.request.get('/api/v1/me')).json() as { step_up_valid_until: string | null }
  const validFor = me.step_up_valid_until ? Date.parse(me.step_up_valid_until) - Date.now() : 0
  if (validFor > 10_000) await start()
  else await stepUp(page, start, ...user)
}

/**
 * Saves the policy form shown on page: confirmation, then the step-up the save needs, then the success message. With
 * demandStepUp the session must hold no valid step-up and the save must start one, so that each test proves the
 * portal demands it; later saves reuse a step-up that is still valid.
 */
async function savePolicy(page: Page, user: readonly [string, string, string], demandStepUp = false): Promise<void> {
  await page.getByTestId('save-mcp').click()
  const confirm = page.getByRole('dialog', { name: 'Save MCP policy?' })
  await expectAccessible(page)
  const save = () => confirm.getByRole('button', { name: 'Save policy' }).click()
  if (demandStepUp) {
    const me = await (await page.request.get('/api/v1/me')).json() as { step_up_valid_until: string | null }
    expect(me.step_up_valid_until === null || Date.parse(me.step_up_valid_until) <= Date.now()).toBe(true)
    await stepUp(page, save, ...user)
  } else {
    await withStepUp(page, save, user)
  }
  await expect(page.getByTestId('mcp-saved')).toBeVisible()
}

// Plan M14 §9.4: the organization's MCP policy (defaults hint while none is saved, a selection of two tools that
// survives a reload) and the administrator's own write access (enable with a step-up, disable without one). The policy
// is switched off again at the end, so the organization is left with the MCP off.
test('organization admin sets the MCP policy and their own write access', async ({ page }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  await login(page, alice[0], alice[1])

  const saved = await (await page.request.get('/api/v1/settings/mcp')).json() as { enabled: boolean; updated_at: string | null }
  await page.goto('/settings/mcp')
  await expect(page.getByRole('heading', { name: 'AI assistants (MCP)' })).toBeVisible()
  await expect(page.getByTestId('mcp-connect-hint')).toContainText('paddockctl mcp login')
  // Only an installation in which nobody saved a policy yet shows the defaults hint; the acceptance gates save one.
  if (saved.updated_at === null) await expect(page.getByTestId('mcp-defaults-hint')).toBeVisible()
  else {
    await expect(page.getByTestId('mcp-defaults-hint')).toHaveCount(0)
    test.info().annotations.push({ type: 'skip', description: 'defaults hint: acme already has a saved MCP policy (the acceptance gates save one)' })
  }
  if (!saved.enabled) await expect(page.getByTestId('mcp-disabled-hint')).toBeVisible()
  await expectAccessible(page)

  await page.getByTestId('mcp-enabled').getByRole('checkbox').check()
  await page.getByTestId('mcp-mode-selected').getByRole('radio').check()
  const picker = page.getByTestId('mcp-tool-picker')
  await expect(picker).toBeVisible()
  for (const tool of ['listDevices', 'getDevice']) {
    await picker.getByRole('checkbox', { name: tool, exact: true }).check()
  }
  await expect(picker.getByTestId('mcp-tool-portal-only').first()).toBeVisible()
  await expectAccessible(page)
  await savePolicy(page, alice, true)

  await page.reload()
  await expect(page.getByTestId('mcp-enabled').getByRole('checkbox')).toBeChecked()
  await expect(page.getByTestId('mcp-mode-selected').getByRole('radio')).toBeChecked()
  for (const tool of ['listDevices', 'getDevice']) {
    await expect(picker.getByRole('checkbox', { name: tool, exact: true })).toBeChecked()
  }
  await expect(page.getByTestId('mcp-defaults-hint')).toHaveCount(0)
  await expectAccessible(page)

  await openUserMenu(page)
  await page.getByTestId('mcp-write-menu').click()
  const dialog = page.getByTestId('mcp-write-dialog')
  await expect(dialog).toBeVisible()
  await expectAccessible(page)
  const enabled = (await (await page.request.get('/api/v1/me')).json() as { mcp_write_enabled: boolean }).mcp_write_enabled
  if (!enabled) {
    await expect(dialog.getByTestId('mcp-write-state')).toHaveText('Write access is disabled.')
    await dialog.getByTestId('mcp-write-enable').click()
    const confirm = page.getByRole('dialog', { name: 'Enable write access for AI assistants?' })
    await expectAccessible(page)
    await withStepUp(page, () => confirm.getByRole('button', { name: 'Enable write access' }).click(), alice)
  }
  await expect(page.getByTestId('mcp-write-dialog').getByTestId('mcp-write-state')).toContainText('Write access is enabled since')
  await expectAccessible(page)
  await page.getByTestId('mcp-write-dialog').getByTestId('mcp-write-disable').click()
  await page.getByRole('dialog', { name: 'Disable write access for AI assistants?' }).getByRole('button', { name: 'Disable write access' }).click()
  await expect(page.getByTestId('mcp-write-dialog').getByTestId('mcp-write-state')).toHaveText('Write access is disabled.')
  await page.getByTestId('mcp-write-close').click()

  // Leave the organization with the MCP off.
  await page.goto('/settings/mcp')
  await page.getByTestId('mcp-enabled').getByRole('checkbox').uncheck()
  await page.getByTestId('mcp-mode-all').getByRole('radio').check()
  await savePolicy(page, alice)
  await expect(page.getByTestId('mcp-disabled-hint')).toBeVisible()

  // The audit log marks events of an MCP session (seeded by the acceptance gate TestMCP).
  const events = await (await page.request.get('/api/v1/audit-events?code=device_group.created&page_size=100')).json() as
    { items: { source: string; actor: { client?: string }; target?: { display?: string } }[] }
  const mcpEvent = events.items.find((e) => e.source === 'mcp' && e.actor.client && e.target?.display)
  if (mcpEvent) {
    await page.goto(`/audit?code=device_group.created&q=${encodeURIComponent(mcpEvent.target!.display!)}`)
    await expect(page.getByTestId('actor-source').first()).toHaveText('MCP')
    await expect(page.getByTestId('actor-client').first()).toBeVisible()
    await expectAccessible(page)
  } else {
    test.info().annotations.push({ type: 'skip', description: 'no MCP event in the last 7 days: run make acceptance T=TestMCP first' })
  }
  expect(csp).toEqual([])
})

test('platform admin saves the platform MCP policy', async ({ page }) => {
  test.setTimeout(240_000)
  const csp = watchCSP(page)
  await login(page, root[0], root[1])
  await page.goto('/platform/mcp')
  await expect(page.getByRole('heading', { name: 'AI assistants (MCP)' })).toBeVisible()
  await expectAccessible(page)
  await page.getByTestId('mcp-enabled').getByRole('checkbox').check()
  await page.getByTestId('mcp-mode-all').getByRole('radio').check()
  await savePolicy(page, root, true)
  await page.reload()
  await expect(page.getByTestId('mcp-enabled').getByRole('checkbox')).toBeChecked()
  await expectAccessible(page)

  await page.getByTestId('mcp-enabled').getByRole('checkbox').uncheck()
  await savePolicy(page, root)
  await expect(page.getByTestId('mcp-disabled-hint')).toBeVisible()
  expect(csp).toEqual([])
})

test('auditor has no MCP write access entry', async ({ page }) => {
  const auditor = await tempUser('e2e-mcp-auditor', 'paddock.acme.auditors')
  try {
    await loginWithPassword(page, auditor.username, auditor.password)
    await openUserMenu(page)
    await expect(page.getByTestId('logout')).toBeVisible()
    await expect(page.getByTestId('mcp-write-menu')).toHaveCount(0)
    await expectAccessible(page)
  } finally {
    await auditor.remove()
  }
})
