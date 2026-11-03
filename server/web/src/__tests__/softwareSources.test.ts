import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import SoftwareSources from '../views/SoftwareSources.vue'
import { useSessionStore } from '../stores/session'
import type { SoftwareSourceSummary } from '../api/client'

const vendor: SoftwareSourceSummary = {
  id: 's1', slug: 'vendor', name: 'Vendor', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'], architectures: [],
  fingerprint: 'ABCD'.repeat(10), weak_key: false, entry_count: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-02T00:00:00Z',
}

const mocks = vi.hoisted(() => ({
  deleteSoftwareSource: vi.fn(),
  saveSoftwareSource: vi.fn(),
  getSoftwareSource: vi.fn(),
  startStepUp: vi.fn(),
  resumeStepUp: vi.fn(),
}))

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listSoftwareSources: () => Promise.resolve({ items: [vendor], page: 1, page_size: 25, total: 1, total_capped: false, sort: 'name' }),
  deleteSoftwareSource: mocks.deleteSoftwareSource,
  saveSoftwareSource: mocks.saveSoftwareSource,
  getSoftwareSource: mocks.getSoftwareSource,
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: mocks.startStepUp,
  resumeStepUp: mocks.resumeStepUp,
}))

// App.vue hosts the single ConfirmDialog in the portal; the test hosts it the same way.
const Host = defineComponent({
  setup: () => () => h(VApp, null, {
    default: () => [
      h(SoftwareSources),
      pendingConfirm.value
        ? h(ConfirmDialog, {
          key: pendingConfirm.value.id,
          modelValue: true,
          ...pendingConfirm.value.options,
          onConfirm: (answer: { reason: string }) => settleConfirm(answer),
          onCancel: () => settleConfirm(false),
        })
        : null,
    ],
  }),
})

let wrapper: VueWrapper | null = null

beforeEach(() => {
  vi.resetAllMocks()
  mocks.resumeStepUp.mockReturnValue(null)
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
})

async function mountSources(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)', component: { render: () => null } }] })
  await router.push('/software-sources')
  wrapper = mount(Host, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

const el = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)
const byLabel = (label: string) => document.body.querySelector<HTMLElement>(`[aria-label="${label}"]`)

async function typeName(name: string): Promise<void> {
  const input = el('confirm-typed')?.querySelector('input') as HTMLInputElement
  input.value = name
  input.dispatchEvent(new Event('input'))
  await flushPromises()
}

describe('SoftwareSources', () => {
  it('lists the sources with the fingerprint in blocks of four for an administrator', async () => {
    await mountSources('org_admin')
    expect(document.body.textContent).toContain('Vendor')
    expect(document.body.textContent).toContain('ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD')
    expect(document.body.textContent).toContain('Entries')
    expect(el('create-source')).not.toBeNull()
    expect(byLabel('Edit Vendor')).not.toBeNull()
  })

  it.each(['org_auditor', 'org_operator'])('shows the list but no create, edit or delete control to %s', async (role) => {
    await mountSources(role)
    expect(document.body.textContent).toContain('Vendor')
    expect(el('create-source')).toBeNull()
    expect(byLabel('Edit Vendor')).toBeNull()
    expect(byLabel('Delete Vendor')).toBeNull()
  })

  it('asks for the typed name before it deletes', async () => {
    mocks.deleteSoftwareSource.mockResolvedValue(null)
    await mountSources('org_admin')
    byLabel('Delete Vendor')?.click()
    await flushPromises()
    const accept = el('confirm-accept') as HTMLButtonElement
    expect(accept.disabled).toBe(true)
    await typeName('Vend')
    expect((el('confirm-accept') as HTMLButtonElement).disabled).toBe(true)
    await typeName('Vendor')
    ;(el('confirm-accept') as HTMLButtonElement).click()
    await flushPromises()
    expect(mocks.deleteSoftwareSource).toHaveBeenCalledWith('s1')
  })

  it('shows in_use inline when the source is referenced', async () => {
    mocks.deleteSoftwareSource.mockResolvedValue('in_use')
    await mountSources('org_admin')
    byLabel('Delete Vendor')?.click()
    await flushPromises()
    await typeName('Vendor')
    ;(el('confirm-accept') as HTMLButtonElement).click()
    await flushPromises()
    expect(document.body.querySelector('[role="alert"]')?.textContent).toContain('This source is used by a catalog entry.')
  })

  it('starts the step-up when the delete needs one and remembers the target', async () => {
    mocks.deleteSoftwareSource.mockResolvedValue('step_up_required')
    await mountSources('org_admin')
    byLabel('Delete Vendor')?.click()
    await flushPromises()
    await typeName('Vendor')
    ;(el('confirm-accept') as HTMLButtonElement).click()
    await flushPromises()
    expect(mocks.startStepUp).toHaveBeenCalledWith('software-source.delete', 'list', { id: 's1' })
  })

  it('completes a save after the step-up (one write, no delete)', async () => {
    const input = { slug: 'v', name: 'V', uris: [], suites: [], components: [], architectures: [], signingKey: 'k', fingerprint: 'f' }
    mocks.resumeStepUp.mockImplementation((action: string) => (action === 'software-source.save' ? { failed: false, payload: { id: null, input, keyChanged: true } } : null))
    mocks.saveSoftwareSource.mockResolvedValue(null)
    await mountSources('org_admin')
    await vi.waitFor(() => expect(mocks.saveSoftwareSource).toHaveBeenCalledTimes(1))
    expect(mocks.saveSoftwareSource).toHaveBeenCalledWith(null, input, true)
    expect(mocks.deleteSoftwareSource).not.toHaveBeenCalled()
  })

  it('reports a refused step-up instead of repeating the write', async () => {
    mocks.resumeStepUp.mockImplementation((action: string) => (action === 'software-source.save' ? { failed: true } : null))
    await mountSources('org_admin')
    await vi.waitFor(() => expect(document.body.querySelector('.form-error')?.textContent).toContain('identity confirmation failed'))
    expect(mocks.saveSoftwareSource).not.toHaveBeenCalled()
  })

  it('reopens the dialog with the typed input and the refusal under the fingerprint field after a refused resumed save', async () => {
    const input = {
      slug: 'vendor', name: 'Vendor', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'], architectures: [],
      signingKey: 'KEY-TEXT-STAYS', fingerprint: 'ABCD'.repeat(10),
    }
    mocks.resumeStepUp.mockImplementation((action: string) => (action === 'software-source.save' ? { failed: false, payload: { id: null, input, keyChanged: true } } : null))
    mocks.saveSoftwareSource.mockResolvedValue('fingerprint_mismatch')
    await mountSources('org_admin')
    await vi.waitFor(() => expect(document.body.querySelector('#source-fingerprint')).not.toBeNull())
    expect((document.body.querySelector('#source-key') as HTMLTextAreaElement).value).toBe('KEY-TEXT-STAYS')
    expect((document.body.querySelector('#source-name') as HTMLInputElement).value).toBe('Vendor')
    expect(document.body.querySelector('.v-dialog')?.textContent).toContain("The key's fingerprint does not match the one you entered.")
    expect(document.body.querySelector('.page > .form-error')).toBeNull()
  })

  it('loads the stored source as the base of a refused resumed edit', async () => {
    const input = {
      slug: 'vendor', name: 'Vendor 2', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'], architectures: [],
      signingKey: 'NEW-KEY', fingerprint: 'ABCD'.repeat(10),
    }
    mocks.resumeStepUp.mockImplementation((action: string) => (action === 'software-source.save' ? { failed: false, payload: { id: 's1', input, keyChanged: true } } : null))
    mocks.saveSoftwareSource.mockResolvedValue('invalid_request')
    mocks.getSoftwareSource.mockResolvedValue({ ...vendor, signing_key: 'OLD-KEY' })
    await mountSources('org_admin')
    await vi.waitFor(() => expect(document.body.querySelector('#source-key')).not.toBeNull())
    expect(mocks.getSoftwareSource).toHaveBeenCalledWith('s1')
    expect((document.body.querySelector('#source-key') as HTMLTextAreaElement).value).toBe('NEW-KEY')
    expect((document.body.querySelector('#source-name') as HTMLInputElement).value).toBe('Vendor 2')
  })
})
