import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import Organizations from '../views/Organizations.vue'
import type { Organization } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { parseDomains, validateDomains } from '../lib/validation'

const acme: Organization = {
  id: 'o1', slug: 'acme', name: 'Acme', status: 'active', domains: ['acme.test'], created_at: '2026-10-01T00:00:00Z',
}
const createOrganization = vi.fn<(slug: string, name: string) => Promise<Organization | string>>()
const updateOrganizationDomains = vi.fn<(id: string, domains: string[]) => Promise<string | null>>()
const listed = vi.fn()

vi.mock('../lib/organizations', async (original) => ({
  ...(await original<typeof import('../lib/organizations')>()),
  listOrganizations: () => {
    listed()
    return Promise.resolve({ items: [acme], page: 1, page_size: 25, total: 1, total_capped: false, sort: 'slug' })
  },
  createOrganization: (slug: string, name: string) => createOrganization(slug, name),
  updateOrganizationDomains: (id: string, domains: string[]) => updateOrganizationDomains(id, domains),
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  createOrganization.mockReset()
  updateOrganizationDomains.mockReset()
  listed.mockReset()
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountView(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/platform/organizations', component: Organizations }] })
  await router.push('/platform/organizations')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

function fill(selector: string, value: string): void {
  const el = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement
  el.value = value
  el.dispatchEvent(new Event('input'))
}

async function submit(selector: string): Promise<void> {
  ;(document.querySelector(selector)?.closest('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

async function openCreate(w: VueWrapper, domains: string): Promise<void> {
  await w.get('[data-testid="create-organization"]').trigger('click')
  await flushPromises()
  fill('#org-slug', 'example')
  fill('#org-name', 'Example')
  fill('#org-domains', domains)
  await flushPromises()
}

describe('organization domains (plan M8x decisions 21–24)', () => {
  it('creates the organization, then saves its trimmed, lower-cased domains', async () => {
    createOrganization.mockResolvedValue({ ...acme, id: 'new', slug: 'example', domains: [] })
    updateOrganizationDomains.mockResolvedValue(null)
    const w = await mountView()
    await openCreate(w, '  Example.ORG \n\nmail.example.org')
    await submit('#org-domains')
    expect(createOrganization).toHaveBeenCalledWith('example', 'Example')
    expect(updateOrganizationDomains).toHaveBeenCalledWith('new', ['example.org', 'mail.example.org'])
    expect(document.querySelector('.v-overlay--active #org-domains')).toBeNull()
  })

  it('creates an organization without domains without a PATCH', async () => {
    createOrganization.mockResolvedValue({ ...acme, id: 'new', slug: 'example', domains: [] })
    const w = await mountView()
    await openCreate(w, '')
    await submit('#org-domains')
    expect(createOrganization).toHaveBeenCalledOnce()
    expect(updateOrganizationDomains).not.toHaveBeenCalled()
  })

  it('keeps the dialog open with both texts when the domains are not saved', async () => {
    createOrganization.mockResolvedValue({ ...acme, id: 'new', slug: 'example', domains: [] })
    updateOrganizationDomains.mockResolvedValue('domain_taken')
    const w = await mountView()
    const before = listed.mock.calls.length
    await openCreate(w, 'acme.test')
    await submit('#org-domains')
    const alert = document.querySelector('.form-error[role="alert"]')?.textContent ?? ''
    expect(alert).toContain('One of these domains belongs to another organization.')
    expect(alert).toContain('The organization was created, but its domains were not saved.')
    expect(document.querySelector('.v-overlay--active #org-domains')).not.toBeNull()
    expect(listed.mock.calls.length).toBeGreaterThan(before)
  })

  it('refuses invalid domains before submitting', async () => {
    const w = await mountView()
    await openCreate(w, 'foo')
    await submit('#org-domains')
    expect(createOrganization).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter lowercase DNS names, one per line, at most 20 without duplicates.')
  })

  it('edits the domains of a row', async () => {
    updateOrganizationDomains.mockResolvedValue(null)
    const w = await mountView()
    expect(w.get('[data-testid="org-domains-text-acme"]').text()).toBe('acme.test')
    await w.get('[data-testid="org-domains-acme"]').trigger('click')
    await flushPromises()
    const area = document.querySelector('#org-edit-domains') as HTMLTextAreaElement
    expect(area.value).toBe('acme.test')
    fill('#org-edit-domains', 'acme.test\nACME.example')
    await submit('#org-edit-domains')
    expect(updateOrganizationDomains).toHaveBeenCalledWith('o1', ['acme.test', 'acme.example'])
    expect(document.querySelector('#org-edit-domains')).toBeNull()
  })

  it('shows the domain_taken text in the edit dialog', async () => {
    updateOrganizationDomains.mockResolvedValue('domain_taken')
    const w = await mountView()
    await w.get('[data-testid="org-domains-acme"]').trigger('click')
    await flushPromises()
    await submit('#org-edit-domains')
    expect(document.querySelector('.form-error[role="alert"]')?.textContent).toContain('One of these domains belongs to another organization.')
    expect(document.querySelector('#org-edit-domains')).not.toBeNull()
  })
})

describe('validateDomains', () => {
  it('accepts lowercase DNS names after trimming and lower-casing', () => {
    expect(validateDomains(' Example.ORG \n\nsub.example.org\n')).toBe('')
    expect(parseDomains(' Example.ORG \n\nsub.example.org\n')).toEqual(['example.org', 'sub.example.org'])
    expect(validateDomains('')).toBe('')
  })

  it('refuses invalid names, duplicates and more than 20 names', () => {
    expect(validateDomains('foo')).toBe('validation.domainsInvalid')
    expect(validateDomains('-a.example')).toBe('validation.domainsInvalid')
    expect(validateDomains('a.example\nA.example')).toBe('validation.domainsInvalid')
    const many = Array.from({ length: 21 }, (_, i) => `d${i}.example`).join('\n')
    expect(validateDomains(many)).toBe('validation.domainsInvalid')
    expect(validateDomains(Array.from({ length: 20 }, (_, i) => `d${i}.example`).join('\n'))).toBe('')
    expect(validateDomains('a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.' + 'd'.repeat(62) + '.org'))
      .toBe('validation.domainsInvalid')
  })
})
