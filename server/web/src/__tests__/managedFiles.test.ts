import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import ManagedFiles from '../views/ManagedFiles.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import type { ManagedFile } from '../api/client'
import type { FileInput } from '../lib/managedConfig'
import { useSessionStore } from '../stores/session'

const cron: ManagedFile = {
  id: 'f1', device_group_id: null, path: '/etc/cron.d/backup', mode: '0644', owner: 'root', group: 'root', content: 'x',
  tier: 'sensitive', sensitive_confirmed_at: null, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const saveManagedFile = vi.fn<(id: string | null, input: FileInput) => Promise<string | null>>()

vi.mock('../lib/managedConfig', async (original) => ({
  ...(await original<typeof import('../lib/managedConfig')>()),
  listManagedFiles: () => Promise.resolve({ items: [cron], page: 1, page_size: 25, total: 1, total_capped: false, sort: 'path' }),
  saveManagedFile: (id: string | null, input: FileInput) => saveManagedFile(id, input),
}))
vi.mock('../lib/devices', async (original) => ({ ...(await original<typeof import('../lib/devices')>()), allGroups: () => Promise.resolve([]) }))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  saveManagedFile.mockReset()
  assign.mockReset()
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/managed-files', search: '' }, writable: true,
  })
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountList(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/managed-files', component: ManagedFiles }] })
  await router.push('/managed-files')
  await router.isReady()
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

async function createFile(w: VueWrapper, path: string): Promise<void> {
  await w.find('[data-testid="create-managed-file"]').trigger('click')
  await flushPromises()
  const field = document.querySelector('#file-path') as HTMLInputElement
  field.value = path
  field.dispatchEvent(new Event('input'))
  const content = document.querySelector('#file-content') as HTMLTextAreaElement
  content.value = '0 3 * * * root /usr/local/bin/backup'
  content.dispatchEvent(new Event('input'))
  await flushPromises()
  ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

function submitButton(): HTMLButtonElement {
  return document.querySelector('.v-dialog form button[type="submit"]') as HTMLButtonElement
}

describe('ManagedFiles: non-ASCII paths and the operator roots (plan M8x decisions 43 and 44)', () => {
  it('links to the operator roots', async () => {
    const w = await mountList()
    const hint = w.get('[data-testid="operator-roots-hint"]')
    expect(hint.text()).toContain('Operators create and change files only below the operator roots')
    expect(hint.get('a').attributes('href')).toBe('/settings/managed-files')
    expect(hint.get('a').text()).toBe('Configure operator roots')
  })

  it('names a path outside ASCII and still submits it', async () => {
    saveManagedFile.mockResolvedValue(null)
    const w = await mountList()
    await w.find('[data-testid="create-managed-file"]').trigger('click')
    await flushPromises()
    const field = document.querySelector('#file-path') as HTMLInputElement
    field.value = '/etc/myapp/app.conf'
    field.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(document.querySelector('[data-testid="path-non-ascii"]')).toBeNull()
    await createFile(w, '/etc/myapp/konfiguration-ä.conf')
    expect(document.querySelector('[data-testid="path-non-ascii"]')?.textContent).toContain('The path contains characters outside ASCII.')
    expect(saveManagedFile).toHaveBeenCalledTimes(1)
    expect(saveManagedFile.mock.calls[0][1]).toMatchObject({ path: '/etc/myapp/konfiguration-ä.conf' })
  })
})

describe('ManagedFiles', () => {
  it('disables the submit button and shows progress while the create request runs (plan M8x decision 27)', async () => {
    let resolve: (v: string | null) => void = () => {}
    saveManagedFile.mockReturnValueOnce(new Promise((r) => { resolve = r }))
    const w = await mountList()
    await createFile(w, '/etc/myapp/app.conf')
    expect(saveManagedFile).toHaveBeenCalledTimes(1)
    expect(submitButton().hasAttribute('disabled')).toBe(true)
    expect(submitButton().querySelector('[role="progressbar"]')).not.toBeNull()
    resolve('invalid_request')
    await flushPromises()
    expect(submitButton().hasAttribute('disabled')).toBe(false)
    expect(submitButton().querySelector('[role="progressbar"]')).toBeNull()
  })

  it('shows the tier of every file', async () => {
    const w = await mountList()
    expect(w.find('[data-testid="managed-file-tier"]').text()).toBe('Sensitive')
  })

  it('steps up for a sensitive path and repeats the creation on return (ADR 0034 decision 2)', async () => {
    saveManagedFile.mockResolvedValueOnce('step_up_required')
    const w = await mountList()
    await createFile(w, '/etc/cron.d/x')
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fmanaged-files')
    wrapper?.unmount()

    saveManagedFile.mockResolvedValueOnce(null)
    await mountList()
    expect(saveManagedFile).toHaveBeenCalledTimes(2)
    expect(saveManagedFile.mock.calls[1][0]).toBeNull()
    expect(saveManagedFile.mock.calls[1][1]).toMatchObject({ path: '/etc/cron.d/x' })
  })

  it('explains a refusal for a role other than organization administrator inline', async () => {
    saveManagedFile.mockResolvedValueOnce('forbidden')
    const w = await mountList()
    await createFile(w, '/etc/cron.d/x')
    expect(assign).not.toHaveBeenCalled()
    expect(document.querySelector('[data-testid="sensitive-forbidden"]')?.textContent).toContain('need an organization administrator')
    expect(w.exists()).toBe(true)
  })
})
