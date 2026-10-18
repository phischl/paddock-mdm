import { expect } from '@playwright/test'
import { login } from './auth'
import { test } from './cleanup'

// Public pages follow the browser language (plan M8f decision 21): without a session the portal starts in the
// language the browser asks for; once signed in, the account's stored language wins.
test.use({ locale: 'de-DE' })

test('public pages speak the browser language until the account language is known', async ({ page }) => {
  await page.goto('/login-denied?reason=mfa_required')
  await expect(page.getByTestId('login-denied-message')).toContainText('Ihre Anmeldung enthielt keinen zweiten Faktor.')
  await expect(page.locator('html')).toHaveAttribute('lang', 'de')

  // alice's stored language is English (dev seed).
  await login(page, 'alice@acme.test', 'dev_alice_password')
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
})
