import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { ComponentTarget } from '../api/client'
import { createPortalI18n } from '../i18n'
import { componentFilter } from '../lib/devices'
import { componentStatus } from '../lib/status'
import { vuetify } from '../plugins/vuetify'
import AgentReleases from '../views/AgentReleases.vue'

let targets: ComponentTarget[] = []
vi.mock('../lib/agentReleases', async (original) => ({
  ...(await original<typeof import('../lib/agentReleases')>()),
  listAgentReleases: () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-created_at' }),
  getComponentTargets: () => Promise.resolve(targets),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountReleases(): Promise<void> {
  setActivePinia(createPinia())
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)', component: { render: () => null } }] })
  await router.push('/agent-releases')
  wrapper = mount(() => h(VApp, null, { default: () => h(AgentReleases) }),
    { global: { plugins: [createPortalI18n(), vuetify, router], stubs: { DataList: true } }, attachTo: document.body })
  await flushPromises()
}

const text = (testid: string) => document.querySelector(`[data-testid="${testid}"]`)?.textContent?.replace(/\s+/g, ' ').trim()

describe('rollout targets (PDK-236)', () => {
  it('lists every target with its source', async () => {
    targets = [
      { component: 'fleetd', version: '1.43.0', source: 'agent_release', updated_at: '2026-10-18T09:00:00Z' },
      { component: 'himmelblau', version: '4.0.4', source: 'PADDOCK_HIMMELBLAU_VERSION', updated_at: '2026-10-18T09:00:00Z' },
      { component: 'paddockd', version: '0.1.0', source: 'agent_release', updated_at: '2026-10-18T09:00:00Z' },
    ]
    await mountReleases()
    const row = (c: string) => [...document.querySelectorAll(`[data-testid="target-${c}"] dt, [data-testid="target-${c}"] dd`)]
      .map((e) => e.textContent?.replace(/\s+/g, ' ').trim())
    expect(row('himmelblau')).toEqual(['Himmelblau', '4.0.4 (PADDOCK_HIMMELBLAU_VERSION)'])
    expect(row('paddockd')).toEqual(['Agent (paddockd)', '0.1.0 (agent_release)'])
    expect(text('rollout-targets-none')).toBeUndefined()
    expect(text('rollout-targets')).toContain('Set with PADDOCK_HIMMELBLAU_VERSION of the compiler')
    expect(text('rollout-targets-hint')).toContain('Target = last completed release.')
  })

  it('says so while no release completed a rollout', async () => {
    targets = [{ component: 'himmelblau', version: '4.0.4', source: 'PADDOCK_HIMMELBLAU_VERSION', updated_at: '2026-10-18T09:00:00Z' }]
    await mountReleases()
    expect(text('rollout-targets-none')).toBe('No agent release has completed a rollout yet.')
  })
})

describe('component list helpers', () => {
  it('maps the statuses and offers the outdated filter', () => {
    expect(componentStatus('outdated')).toEqual({ status: 'warn', label: 'devices.components.status.outdated' })
    expect(componentStatus('ok').status).toBe('ok')
    expect(componentStatus('missing').status).toBe('neutral')
    expect(componentFilter.kind === 'enum' && componentFilter.key).toBe('component_outdated')
    expect(componentFilter.hint).toBe('devices.components.targetHint')
  })
})
