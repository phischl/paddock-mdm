import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import PermissionProfiles from '../views/PermissionProfiles.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import type { PermissionProfile } from '../api/client'
import type { ProfileInput } from '../lib/profiles'
import { useSessionStore } from '../stores/session'

const shell: PermissionProfile = {
  id: 'p1', name: 'shell', class: 'restricted', commands: ['/usr/bin/bash'], require_password: true,
  timestamp_timeout_min: 5, lecture: 'once', root_equivalent: true, effective_class: 'full',
  root_equivalent_commands: ['/usr/bin/bash'], invalid_commands: [], root_grant_confirmed_at: null, created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}
const createProfile = vi.fn<(input: ProfileInput) => Promise<PermissionProfile | string>>()

vi.mock('../lib/profiles', async (original) => ({
  ...(await original<typeof import('../lib/profiles')>()),
  listProfiles: () => Promise.resolve({ items: [shell], page: 1, page_size: 25, total: 1, total_capped: false, sort: 'name' }),
  createProfile: (input: ProfileInput) => createProfile(input),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  createProfile.mockReset()
  assign.mockReset()
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/profiles', search: '' }, writable: true,
  })
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountList(): Promise<{ w: VueWrapper; path: () => string }> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/profiles', name: 'permission-profiles', component: PermissionProfiles },
      { path: '/profiles/:id', name: 'permission-profile', component: { render: () => null } },
    ],
  })
  await router.push('/profiles')
  await router.isReady()
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return { w: wrapper, path: () => router.currentRoute.value.fullPath }
}

function submitButton(): HTMLButtonElement {
  return document.querySelector('.v-dialog form button[type="submit"]') as HTMLButtonElement
}

describe('PermissionProfiles', () => {
  it('disables the submit button and shows progress while the create request runs (plan M8x decision 27)', async () => {
    let resolve: (v: PermissionProfile | string) => void = () => {}
    createProfile.mockReturnValueOnce(new Promise((r) => { resolve = r }))
    const { w } = await mountList()
    await w.find('[data-testid="create-profile"]').trigger('click')
    await flushPromises()
    const name = document.querySelector('#create-profile-name') as HTMLInputElement
    name.value = 'logs'
    name.dispatchEvent(new Event('input'))
    const commands = document.querySelector('#create-profile-commands') as HTMLTextAreaElement
    commands.value = '/usr/bin/journalctl'
    commands.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(createProfile).toHaveBeenCalledTimes(1)
    expect(submitButton().hasAttribute('disabled')).toBe(true)
    expect(submitButton().querySelector('[role="progressbar"]')).not.toBeNull()
    resolve('invalid_request')
    await flushPromises()
    expect(submitButton().hasAttribute('disabled')).toBe(false)
    expect(submitButton().querySelector('[role="progressbar"]')).toBeNull()
  })

  it('shows the effective class of a root-equivalent restricted profile', async () => {
    const { w } = await mountList()
    expect(w.find('[data-testid="profile-effective-class"]').text()).toBe('Full (effective)')
  })

  it('confirms the root grant, steps up and repeats the creation on return (ADR 0034 decision 1)', async () => {
    createProfile.mockResolvedValueOnce('step_up_required')
    const { w } = await mountList()
    await w.find('[data-testid="create-profile"]').trigger('click')
    await flushPromises()
    const name = document.querySelector('#create-profile-name') as HTMLInputElement
    name.value = 'shell'
    name.dispatchEvent(new Event('input'))
    const commands = document.querySelector('#create-profile-commands') as HTMLTextAreaElement
    commands.value = '/usr/bin/bash'
    commands.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(createProfile).toHaveBeenCalledTimes(1)
    expect(pendingConfirm.value?.options.requireTypedText).toBe('shell')
    expect(pendingConfirm.value?.options.message).toContain('hands out root')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fprofiles')
    wrapper?.unmount()

    createProfile.mockResolvedValueOnce(shell)
    const resumed = await mountList()
    expect(createProfile).toHaveBeenCalledTimes(2)
    expect(createProfile.mock.calls[1][0]).toMatchObject({ name: 'shell', class: 'restricted', commands: ['/usr/bin/bash'] })
    await vi.waitFor(() => expect(resumed.path()).toBe('/profiles/p1'))
  })

  it('reports a refused step-up', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'profile-create', target: 'new', payload: {}, at: Date.now() }))
    Object.defineProperty(window, 'location', { value: { ...window.location, search: '?stepup=failed' }, writable: true })
    await mountList()
    expect(createProfile).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('identity confirmation failed')
  })
})
