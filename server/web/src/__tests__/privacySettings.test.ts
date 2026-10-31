import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import PrivacySettings from '../views/PrivacySettings.vue'
import type { PrivacySettings as Settings, PrivacySettingsUpdate } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const stored: Settings = {
  retired_inventory_days: 30, audit_search_recorded: false, inventory_view_recorded: false, updated_at: '2026-10-30T08:00:00Z',
}
const save = vi.fn<(s: PrivacySettingsUpdate) => Promise<Settings | string>>()
vi.mock('../lib/privacy', async (original) => ({
  ...(await original<typeof import('../lib/privacy')>()),
  getPrivacySettings: () => Promise.resolve({ ...stored }),
  savePrivacySettings: (s: PrivacySettingsUpdate) => save(s),
}))

let wrapper: VueWrapper | null = null

beforeEach(() => save.mockReset())
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountAs(role: string): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/privacy', component: PrivacySettings }] })
  await router.push('/settings/privacy')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

function days(): HTMLInputElement {
  return document.querySelector('#retired-inventory-days') as HTMLInputElement
}

async function setDays(value: string): Promise<void> {
  days().value = value
  days().dispatchEvent(new Event('input'))
  await flushPromises()
}

async function submit(): Promise<void> {
  ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

describe('PrivacySettings (plan M10 decision 10)', () => {
  it('lets an administrator change the settings and confirms with a snackbar', async () => {
    save.mockImplementation((s) => Promise.resolve({ ...s, updated_at: '2026-10-30T09:00:00Z' }))
    const w = await mountAs('org_admin')
    expect(days().value).toBe('30')
    expect(days().matches(':disabled')).toBe(false)
    expect(w.text()).toContain('Keep the inventory of retired devices')
    expect(w.text()).toContain('deleted that many days after retirement')
    await setDays('14')
    ;(document.querySelector('#audit-search-recorded') as HTMLInputElement).click()
    await flushPromises()
    await submit()
    expect(save).toHaveBeenCalledWith({ retired_inventory_days: 14, audit_search_recorded: true, inventory_view_recorded: false })
    expect(document.body.textContent).toContain('The privacy settings were saved.')
  })

  it('refuses days out of range inline without saving', async () => {
    const w = await mountAs('org_admin')
    for (const value of ['0', '366']) {
      await setDays(value)
      await submit()
      expect(w.text()).toContain('Enter a whole number of days from 1 to 365.')
    }
    expect(save).not.toHaveBeenCalled()
  })

  it('shows a refusal of the server inline', async () => {
    save.mockResolvedValue('forbidden')
    const w = await mountAs('org_admin')
    await submit()
    expect(w.find('[role="alert"]').exists()).toBe(true)
    expect(document.body.textContent).not.toContain('The privacy settings were saved.')
  })

  it.each(['org_operator', 'org_auditor'])('is read-only for %s', async (role) => {
    const w = await mountAs(role)
    expect(days().value).toBe('30')
    expect(days().matches(':disabled')).toBe(true)
    expect((document.querySelector('#audit-search-recorded') as HTMLInputElement).matches(':disabled')).toBe(true)
    expect(w.find('[data-testid="save-privacy-settings"]').exists()).toBe(false)
    expect(w.find('[data-testid="privacy-read-only"]').text()).toContain('Only organization administrators')
  })
})
