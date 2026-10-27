import { expect, request, type Cookie, type Page } from '@playwright/test'
import { loginWithPassword, switchRole, tempUser, type TempUser } from './auth'
import { expectAccessible, mainNav, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

const platformGroup = 'paddock.platform.admins'

/** Starts the switch from the user menu and confirms it in the dialog. */
async function switchFromMenu(page: Page, user: TempUser, label: string, checkDialog = false): Promise<void> {
  await switchRole(page, async () => {
    await openUserMenu(page)
    await expect(page.getByTestId('switch-role')).toHaveText(label)
    await page.getByTestId('switch-role').click()
    const dialog = page.getByTestId('confirm-dialog')
    await expect(dialog).toContainText('Your current session ends and privileged actions need a new step-up.')
    if (checkDialog) await expectAccessible(page)
    await dialog.getByTestId('confirm-accept').click()
  }, user.username, user.password)
}

/** Checks the role caption, the switch offered and that the new session has no step-up. */
async function expectSession(page: Page, role: string, offered: string): Promise<void> {
  await expect(page.locator('.pd-user-role')).toHaveText(role)
  await openUserMenu(page)
  await expect(page.getByTestId('user-role')).toHaveText(role)
  await expect(page.getByTestId('user-stepup')).toHaveText('No current identity confirmation')
  await expect(page.getByTestId('switch-role')).toHaveText(offered)
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('switch-role')).toBeHidden()
}

/** Answers GET /api/v1/me with the given cookies only: a session the switch ended answers 401. */
async function meStatus(page: Page, cookies: Cookie[]): Promise<number> {
  const ctx = await request.newContext({
    baseURL: new URL(page.url()).origin,
    ignoreHTTPSErrors: true,
    storageState: { cookies, origins: [] },
  })
  try {
    return (await ctx.get('/api/v1/me')).status()
  } finally {
    await ctx.dispose()
  }
}

// ADR 0045 decision 3, PDK-450 acceptance criterion 7: one identity in the platform group and one organization's
// admins group signs in to the organization, switches to platform administration through the user menu and back;
// each switch is a new session without a step-up that ends the previous one. After the platform role is taken away,
// the switch is refused with role_not_granted and the organization session stays usable.
test('two-role identity switches between organization and platform administration', async ({ page }) => {
  test.setTimeout(240_000)
  const csp = watchCSP(page)
  const user = await tempUser('e2e-role-switch', platformGroup, 'paddock.acme.admins')
  try {
    await loginWithPassword(page, user.username, user.password)
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    await expectSession(page, 'Organization administrator', 'Switch to Platform administrator')
    const organizationSession = await page.context().cookies(new URL(page.url()).origin)

    await switchFromMenu(page, user, 'Switch to Platform administrator', true)
    await expect(mainNav(page).getByRole('link', { name: 'Organizations' })).toBeVisible()
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toHaveCount(0)
    await expectSession(page, 'Platform administrator', 'Switch to Organization administrator (acme)')
    expect(await meStatus(page, organizationSession)).toBe(401)
    const platformSession = await page.context().cookies(new URL(page.url()).origin)

    await switchFromMenu(page, user, 'Switch to Organization administrator (acme)')
    await expect(mainNav(page).getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    await expect(mainNav(page).getByRole('link', { name: 'Organizations' })).toHaveCount(0)
    await expectSession(page, 'Organization administrator', 'Switch to Platform administrator')
    expect(await meStatus(page, platformSession)).toBe(401)

    await user.leave(platformGroup)
    await switchFromMenu(page, user, 'Switch to Platform administrator')
    await expect(page).toHaveURL(/\/login-denied\?reason=role_not_granted$/)
    await expect(page.getByTestId('login-denied-message')).toHaveText(
      'The role you chose is no longer granted to your account. Your current session is unchanged; sign in again to continue.')
    await expectAccessible(page)
    const me = await page.request.get('/api/v1/me')
    expect(me.status()).toBe(200)
    expect((await me.json()).role).toBe('org_admin')
    expect(csp).toEqual([])
  } finally {
    await user.remove()
  }
})
