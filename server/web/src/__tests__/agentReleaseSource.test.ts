import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AgentReleaseCheck, AgentReleaseDetail, AgentReleaseSource } from '../api/client'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import AgentReleases from '../views/AgentReleases.vue'

const mocks = vi.hoisted(() => ({
  getAgentReleaseSource: vi.fn(),
  checkAgentReleaseSource: vi.fn(),
  importAgentRelease: vi.fn(),
  startStepUp: vi.fn(),
  resumeStepUp: vi.fn(),
}))

vi.mock('../lib/agentReleases', async (original) => ({
  ...(await original<typeof import('../lib/agentReleases')>()),
  listAgentReleases: () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-created_at' }),
  getComponentTargets: () => Promise.resolve([]),
  getAgentReleaseSource: mocks.getAgentReleaseSource,
  checkAgentReleaseSource: mocks.checkAgentReleaseSource,
  importAgentRelease: mocks.importAgentRelease,
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: mocks.startStepUp,
  resumeStepUp: mocks.resumeStepUp,
}))

const enabled: AgentReleaseSource = { enabled: true, repository: 'acme/paddock', url: 'https://github.com/acme/paddock' }
const importable = (latest: string): AgentReleaseCheck =>
  ({ importable: true, latest, published_at: '2026-10-20T09:00:00Z', newest_stored: '1.0.0' }) as AgentReleaseCheck
const imported = (version: string): AgentReleaseDetail => ({ release: { version } }) as AgentReleaseDetail

// App.vue hosts the single ConfirmDialog in the portal; the test hosts it the same way.
const Host = defineComponent({
  setup: () => () => h(VApp, null, {
    default: () => [
      h(AgentReleases),
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

// The view reloads the list through its exposed reload() after an import.
const listStub = defineComponent({ setup: (_, { expose }) => { expose({ reload: () => Promise.resolve() }); return () => null } })

let wrapper: VueWrapper | null = null

beforeEach(() => {
  vi.resetAllMocks()
  mocks.getAgentReleaseSource.mockResolvedValue(enabled)
  mocks.resumeStepUp.mockReturnValue(null)
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
})

async function mountReleases(): Promise<void> {
  setActivePinia(createPinia())
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/agent-releases/:version', name: 'agent-release', component: { render: () => null } },
      { path: '/:p(.*)', component: { render: () => null } },
    ],
  })
  await router.push('/agent-releases')
  wrapper = mount(Host, { global: { plugins: [createPortalI18n(), vuetify, router], stubs: { DataList: listStub } }, attachTo: document.body })
  await flushPromises()
}

const el = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)
const text = (testid: string) => el(testid)?.textContent?.replace(/\s+/g, ' ').trim()

async function click(testid: string): Promise<void> {
  el(testid)?.click()
  await flushPromises()
}

async function checkAndOpenImport(version: string): Promise<void> {
  mocks.checkAgentReleaseSource.mockResolvedValueOnce(importable(version))
  await mountReleases()
  await click('release-source-check')
  await click('release-source-import')
}

describe('release source panel (PDK-428)', () => {
  it('renders nothing for a disabled source', async () => {
    mocks.getAgentReleaseSource.mockResolvedValue({ enabled: false, repository: null, url: null })
    await mountReleases()
    expect(el('release-source')).toBeNull()
    expect(mocks.checkAgentReleaseSource).not.toHaveBeenCalled()
  })

  it('shows the repository but checks only on click', async () => {
    mocks.checkAgentReleaseSource.mockResolvedValue(importable('1.1.0'))
    await mountReleases()
    expect(text('release-source-repository')).toBe('acme/paddock')
    expect(mocks.checkAgentReleaseSource).not.toHaveBeenCalled()
    await click('release-source-check')
    expect(mocks.checkAgentReleaseSource).toHaveBeenCalledTimes(1)
  })

  it('offers the import of an importable version', async () => {
    mocks.checkAgentReleaseSource.mockResolvedValue(importable('1.1.0'))
    await mountReleases()
    await click('release-source-check')
    expect(text('release-source-result')).toMatch(/^Version 1\.1\.0 is available \(published .+\)$/)
    expect(text('release-source-import')).toBe('Import 1.1.0')
  })

  it('says so when nothing newer exists and offers no import', async () => {
    mocks.checkAgentReleaseSource.mockResolvedValue({ importable: false, reason: 'not_newer', latest: '1.0.0', newest_stored: '1.0.0' })
    await mountReleases()
    await click('release-source-check')
    expect(text('release-source-result')).toBe('No newer release; the newest published release is 1.0.0')
    expect(el('release-source-import')).toBeNull()
  })

  it('shows the problem text when the check fails', async () => {
    mocks.checkAgentReleaseSource.mockResolvedValue('release_source_unavailable')
    await mountReleases()
    await click('release-source-check')
    expect(text('release-source-problem')).toBe('The release source did not answer. Check the connection and try again.')
    expect(el('release-source-problem')?.getAttribute('role')).toBe('alert')
    expect(el('release-source-import')).toBeNull()
  })

  it('does not import when the dialog is cancelled', async () => {
    await checkAndOpenImport('1.1.0')
    expect(el('confirm-dialog')?.textContent).toContain('Import agent 1.1.0?')
    await click('confirm-cancel')
    expect(mocks.importAgentRelease).not.toHaveBeenCalled()
    expect(el('confirm-dialog')).toBeNull()
  })

  it('checks again after the server found the version not newer', async () => {
    mocks.importAgentRelease.mockResolvedValue('release_not_newer')
    await checkAndOpenImport('1.1.0')
    mocks.checkAgentReleaseSource.mockResolvedValueOnce({ importable: false, reason: 'not_newer', latest: '1.1.0', newest_stored: '1.1.0' })
    await click('confirm-accept')
    expect(mocks.importAgentRelease).toHaveBeenCalledWith('1.1.0')
    expect(text('release-source-problem')).toBe('This version is not newer than the newest published release.')
    expect(mocks.checkAgentReleaseSource).toHaveBeenCalledTimes(2)
    expect(text('release-source-result')).toBe('No newer release; the newest published release is 1.1.0')
  })

  it('sends the browser through the step-up when the import needs one', async () => {
    mocks.importAgentRelease.mockResolvedValue('step_up_required')
    await checkAndOpenImport('1.1.0')
    await click('confirm-accept')
    expect(mocks.startStepUp).toHaveBeenCalledWith('agent-release-import', 'source', { version: '1.1.0' })
    expect(el('release-source-problem')).toBeNull()
  })

  it('shows the failed step-up and checks again', async () => {
    mocks.resumeStepUp.mockReturnValue({ failed: true })
    mocks.checkAgentReleaseSource.mockResolvedValue(importable('1.1.0'))
    await mountReleases()
    expect(text('release-source-problem')).toContain('The identity confirmation failed.')
    expect(mocks.checkAgentReleaseSource).toHaveBeenCalledTimes(1)
    expect(mocks.importAgentRelease).not.toHaveBeenCalled()
  })

  it('repeats the import after a successful step-up and links the release', async () => {
    mocks.resumeStepUp.mockReturnValue({ failed: false, payload: { version: '1.1.0' } })
    mocks.importAgentRelease.mockResolvedValue(imported('1.1.0'))
    await mountReleases()
    expect(mocks.importAgentRelease).toHaveBeenCalledWith('1.1.0')
    expect(mocks.startStepUp).not.toHaveBeenCalled()
    expect(text('release-source-success')).toContain('Agent 1.1.0 is published.')
    expect(el('release-source-success')?.querySelector('a')?.getAttribute('href')).toBe('/agent-releases/1.1.0')
  })
})
