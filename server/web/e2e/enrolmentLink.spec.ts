import { expect, type Page } from '@playwright/test'
import { login, stepUp, tempUser } from './auth'
import { expectAccessible, mainNav, openUserMenu, watchCSP } from './checks'
import { test } from './cleanup'

const platformDetail = 'platform administrators receive their setup link from the host operator'

async function openUser(page: Page, username: string, users: string): Promise<void> {
  await mainNav(page, users === 'Users' ? 'Main navigation' : 'Hauptnavigation').getByRole('link', { name: users, exact: true }).click()
  await page.getByTestId('list-search').getByRole('searchbox').fill(username)
  await page.getByRole('row').filter({ hasText: username }).getByRole('link').first().click()
  await expect(page.getByRole('heading', { name: username })).toBeVisible()
}

async function noHorizontalScroll(page: Page): Promise<void> {
  const { scrollWidth, innerWidth } = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth }))
  expect(scrollWidth).toBeLessThanOrEqual(innerWidth)
}

// PDK-1027 frontend verify (stack phase): the one-time sign-in setup link on the user page, the MFA announcement
// banner, error and empty states, English and German, a phone viewport.
test('organization admin creates a one-time sign-in setup link', async ({ page, context, cleanup }) => {
  test.setTimeout(300_000)
  const csp = watchCSP(page)
  const consoleErrors: string[] = []
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
  page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message))
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await login(page, 'alice@acme.test', 'dev_alice_password')
  const username = `e2e-link-${Date.now().toString(36)}@acme.test`
  cleanup.remove('/api/v1/users', username)

  // The announcement banner: the real state first, then the count and the empty variants through a stubbed /me.
  const realBanner = await page.getByTestId('mfa-enrolment-notice').count()
  test.info().annotations.push({ type: 'banner-on-stack', description: realBanner ? 'visible' : 'absent' })
  const stubNotice = async (notice: { until: string; pending: number } | null): Promise<void> => {
    await page.unroute('**/api/v1/me')
    await page.route('**/api/v1/me', async (route) => {
      if (route.request().method() !== 'GET') return route.continue()
      const res = await route.fetch()
      await route.fulfill({ response: res, json: { ...(await res.json()), mfa_enrolment_notice: notice } })
    })
    await page.evaluate(() => localStorage.removeItem('paddock.mfaEnrolmentNotice.dismissed'))
    await page.goto('/')
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible()
  }
  const until = new Date(Date.now() + 20 * 86400_000).toISOString()
  await stubNotice({ until, pending: 3 })
  const banner = page.getByTestId('mfa-enrolment-notice')
  await expect(banner).toContainText('3 administrators have not set up a passkey yet')
  await expect(banner).toContainText('one-time sign-in setup link')
  await expectAccessible(page)
  await page.setViewportSize({ width: 375, height: 800 })
  await noHorizontalScroll(page)
  await expect(banner).toBeVisible()
  await page.setViewportSize({ width: 1280, height: 800 })
  await stubNotice({ until, pending: 1 })
  await expect(banner).toContainText('1 administrator has not set up a passkey yet')
  await stubNotice({ until, pending: 0 })
  await expect(banner).toContainText('Every administrator now signs in with a passkey.')
  await banner.getByRole('button', { name: 'Dismiss' }).click()
  await expect(banner).toBeHidden()
  await page.reload()
  await expect(banner).toBeHidden()
  await stubNotice(null)
  await expect(banner).toHaveCount(0)
  await page.unroute('**/api/v1/me')

  // A local user to create the link for.
  await mainNav(page).getByRole('link', { name: 'Users', exact: true }).click()
  await page.getByTestId('create-user').click()
  const userDialog = page.getByRole('dialog', { name: 'New local user' })
  await userDialog.getByLabel('Username').fill(username)
  await userDialog.getByLabel('Display name').fill('E2E Link User')
  await userDialog.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByTestId('recovery-link')).toBeVisible()
  await page.getByTestId('close-user').click()
  await openUser(page, username, 'Users')
  await expect(page.getByTestId('enrolment-link-help')).toContainText('A sign-in setup link lets the account set up a passkey')
  await expectAccessible(page)

  // Cancel in the dialog changes nothing and starts no request.
  let linkRequests = 0
  page.on('request', (r) => { if (r.url().includes('/enrolment-link')) linkRequests++ })
  const button = page.getByTestId('enrolment-link')
  await expect(button).toHaveAccessibleName('Create sign-in setup link')
  await button.click()
  const confirm = page.getByRole('dialog', { name: 'Sign-in setup link' })
  await expect(confirm).toContainText('Create a one-time sign-in setup link for ' + username)
  await expectAccessible(page)
  await confirm.getByRole('button', { name: 'Cancel' }).click()
  await expect(confirm).toBeHidden()
  expect(linkRequests).toBe(0)

  // Failed request: a platform administrator refusal shows its own text, any other refusal the generic one.
  await page.route('**/api/v1/users/*/enrolment-link', (route) => route.fulfill({
    status: 409, contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'about:blank', title: 'Conflict', status: 409, code: 'invalid_state', detail: platformDetail }),
  }))
  await button.click()
  await page.getByRole('dialog', { name: 'Sign-in setup link' }).getByRole('button', { name: 'Create sign-in setup link' }).click()
  await expect(page.getByText('Platform administrators receive their sign-in setup link from the host operator.')).toBeVisible()
  await expectAccessible(page)
  await page.unroute('**/api/v1/users/*/enrolment-link')
  await page.route('**/api/v1/users/*/enrolment-link', (route) => route.fulfill({
    status: 500, contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'about:blank', title: 'Internal', status: 500, code: 'internal' }),
  }))
  await button.click()
  await page.getByRole('dialog', { name: 'Sign-in setup link' }).getByRole('button', { name: 'Create sign-in setup link' }).click()
  await expect(page.getByRole('alert').filter({ hasText: /./ }).first()).toBeVisible()
  await page.unroute('**/api/v1/users/*/enrolment-link')

  // The real flow: confirm, step-up (password and TOTP), the link is shown once, the copy works.
  await stepUp(page, async () => {
    await button.click()
    await page.getByRole('dialog', { name: 'Sign-in setup link' }).getByRole('button', { name: 'Create sign-in setup link' }).click()
  }, 'alice@acme.test', 'dev_alice_password', 'dev_alice_totp_key')
  const shown = page.getByRole('dialog', { name: 'Sign-in setup link' })
  const linkField = shown.getByTestId('enrolment-link-value').locator('input')
  await expect(linkField).toHaveValue(/\/if\/flow\/paddock-recovery\/\?flow_token=/)
  await expect(shown).toContainText('is shown only now')
  const link = await linkField.inputValue()
  await expectAccessible(page)
  await shown.getByTestId('copy-enrolment-link').click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link)
  await expect(page).not.toHaveURL(/stepup/)
  await page.setViewportSize({ width: 375, height: 800 })
  await noHorizontalScroll(page)
  await expect(shown.getByTestId('close-enrolment-link')).toBeVisible()
  await page.setViewportSize({ width: 1280, height: 800 })
  await shown.getByTestId('close-enrolment-link').click()
  await expect(shown).toBeHidden()
  expect(await page.content()).not.toContain(link)
  await page.reload()
  expect(await page.content()).not.toContain(link)
  await expect(page.getByRole('heading', { name: username })).toBeVisible()

  // Keyboard: the button is reachable and operable.
  await button.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog', { name: 'Sign-in setup link' })).toBeVisible()
  await page.keyboard.press('Escape')

  // German texts; the language is restored afterwards (it persists on the account).
  try {
    await openUserMenu(page)
    await page.getByTestId('language-menu').click()
    await page.getByTestId('language-de').click()
    await expect(page.locator('html')).toHaveAttribute('lang', 'de')
    await page.keyboard.press('Escape')
    await page.reload()
    await expect(page.getByTestId('enrolment-link-help')).toContainText('Ein Link zur Einrichtung der Anmeldung')
    await expect(button).toHaveText('Link zur Einrichtung der Anmeldung erstellen')
    await button.click()
    const de = page.getByRole('dialog', { name: 'Link zur Einrichtung der Anmeldung' })
    await expect(de).toContainText('Einen einmaligen Link zur Einrichtung der Anmeldung für ' + username)
    await expectAccessible(page)
    await de.getByRole('button', { name: 'Abbrechen' }).click()
    await page.route('**/api/v1/me', async (route) => {
      if (route.request().method() !== 'GET') return route.continue()
      const res = await route.fetch()
      await route.fulfill({ response: res, json: { ...(await res.json()), mfa_enrolment_notice: { until, pending: 2 } } })
    })
    await page.evaluate(() => localStorage.removeItem('paddock.mfaEnrolmentNotice.dismissed'))
    await page.goto('/')
    await expect(page.getByTestId('mfa-enrolment-notice')).toContainText('2 Administratoren haben noch keinen Passkey')
    await expect(page.getByTestId('mfa-enrolment-notice').getByRole('button', { name: /Schließen|Ausblenden/ })).toBeVisible()
    await expectAccessible(page)
    await page.unroute('**/api/v1/me')
  } finally {
    await page.goto('/')
    await openUserMenu(page)
    await page.getByTestId('language-menu').click()
    await page.getByTestId('language-en').click()
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  }
  expect(csp).toEqual([])
  expect(consoleErrors.filter((e) => !/status of (409|500)|Failed to load resource/.test(e))).toEqual([])
})

// Permission-denied state: an operator has no setup-link action and no help text on the user page.
test('operator sees no sign-in setup link action', async ({ page, cleanup }) => {
  const operator = await tempUser('e2e-link-operator', 'paddock.acme.operators')
  try {
    const { loginWithPassword } = await import('./auth')
    await loginWithPassword(page, operator.username, operator.password)
    void cleanup
    await mainNav(page).getByRole('link', { name: 'Users', exact: true }).click()
    await page.getByRole('row').nth(1).getByRole('link').first().click()
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByTestId('enrolment-link')).toHaveCount(0)
    await expect(page.getByTestId('enrolment-link-help')).toHaveCount(0)
    await expectAccessible(page)
  } finally {
    await operator.remove()
  }
})
