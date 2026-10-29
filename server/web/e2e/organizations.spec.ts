import { expect, test } from '@playwright/test'
import { login } from './auth'
import { expectAccessible, watchCSP } from './checks'

// Organizations cannot be deleted; each run creates one with a unique slug (plan M8x decision 24).
test('platform admin creates an organization with a domain and edits its domains', async ({ page }) => {
  const csp = watchCSP(page)
  const slug = `e2e-${Date.now().toString(36)}`
  await login(page, 'platform-admin@paddock.test', 'dev_platform_admin_password')
  await expect(page).toHaveURL(/\/platform\/organizations$/)

  await page.getByTestId('create-organization').click()
  const create = page.getByRole('dialog', { name: 'New organization' })
  await create.getByLabel('Slug').fill(slug)
  await create.getByLabel('Name').fill(`E2E ${slug}`)
  await create.getByLabel('Domains (one per line)').fill(`${slug.toUpperCase()}.test`)
  await expectAccessible(page)
  await create.getByRole('button', { name: 'Create' }).click()
  // The create waits for the identity provider setup, bounded at 60 s (app.ProvisioningBudget); the dialog shows a
  // progress hint meanwhile. This step follows that product bound plus a margin for the domains PATCH (PDK-407).
  await expect(create).toBeHidden({ timeout: 65_000 })

  await page.getByTestId('list-search').getByRole('searchbox').fill(slug)
  await expect(page).toHaveURL(new RegExp(`q=${slug}`))
  await expect(page.getByTestId(`org-domains-text-${slug}`)).toHaveText(`${slug}.test`)

  await page.getByTestId(`org-domains-${slug}`).click()
  const edit = page.getByRole('dialog', { name: `Domains of E2E ${slug}` })
  await expect(edit.getByLabel('Domains (one per line)')).toHaveValue(`${slug}.test`)
  await expectAccessible(page)
  await edit.getByLabel('Domains (one per line)').fill(`${slug}.test\nmail.${slug}.test`)
  await edit.getByRole('button', { name: 'Save' }).click()
  await expect(edit).toBeHidden()
  await expect(page.getByTestId(`org-domains-text-${slug}`)).toHaveText(`${slug}.test, mail.${slug}.test`)
  expect(csp).toEqual([])
})
