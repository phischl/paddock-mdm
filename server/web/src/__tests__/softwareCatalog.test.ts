import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import SoftwareCatalog from '../views/SoftwareCatalog.vue'
import { useSessionStore } from '../stores/session'
import type { SoftwareCatalogEntry } from '../api/client'
import type { EntryInput } from '../lib/software'

const entry: SoftwareCatalogEntry = {
  id: 'e1', name: 'Editor', description: '', category: 'Tools', source_id: null, source_slug: '', has_icon: false, approval: 'none',
  packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', package: 'nano' }], assignment_count: 3,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const save = vi.hoisted(() => vi.fn())

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listSoftwareCatalog: () => Promise.resolve({ items: [entry], page: 1, page_size: 25, total: 1, total_capped: false, sort: 'name' }),
  allSoftwareSources: () => Promise.resolve([]),
  catalogCategories: () => Promise.resolve(['Tools']),
  saveCatalogEntry: (id: string | null, input: EntryInput) => save(id, input),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountCatalog(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/software-catalog', component: { render: () => null } }, { path: '/software-catalog/:id', name: 'software-catalog-entry', component: { render: () => null } }],
  })
  await router.push('/software-catalog')
  wrapper = mount(() => h(VApp, null, { default: () => h(SoftwareCatalog) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

const el = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)

describe('SoftwareCatalog', () => {
  it('lists the entries with their package and assignment counts', async () => {
    await mountCatalog('org_auditor')
    const text = el('catalog-list')?.textContent ?? ''
    expect(text).toContain('Editor')
    expect(text).toContain('Tools')
  })

  it('offers no create button to an auditor', async () => {
    await mountCatalog('org_auditor')
    expect(el('create-entry')).toBeNull()
  })

  it('creates an entry from the dialog and reloads', async () => {
    save.mockResolvedValue(null)
    await mountCatalog('org_operator')
    el('create-entry')?.click()
    await flushPromises()
    const name = document.querySelector('#entry-name') as HTMLInputElement
    name.value = 'Browser'
    name.dispatchEvent(new Event('input'))
    const pkg = document.querySelector('[data-testid="package-name-0"] input') as HTMLInputElement
    pkg.value = 'firefox'
    pkg.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(save).toHaveBeenCalledTimes(1)
    expect(save.mock.calls[0][0]).toBeNull()
    expect(save.mock.calls[0][1]).toMatchObject({ name: 'Browser', packages: [{ package: 'firefox' }] })
  })
})
