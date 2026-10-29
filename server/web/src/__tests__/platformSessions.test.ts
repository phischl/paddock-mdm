import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { VApp } from 'vuetify/components'
import PlatformSessions from '../views/PlatformSessions.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

let answer: number | string = 3
let calls = 0
vi.mock('../lib/sessions', async (original) => ({
  ...(await original<typeof import('../lib/sessions')>()),
  endAllSessions: () => {
    calls++
    return Promise.resolve(answer)
  },
}))
const started: string[] = []
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string) => started.push(action),
  resumeStepUp: () => null,
}))

const assigned: string[] = []
let wrapper: VueWrapper | null = null

beforeEach(() => {
  answer = 3
  calls = 0
  started.length = 0
  assigned.length = 0
  vi.stubGlobal('location', { ...window.location, assign: (to: string) => assigned.push(to) })
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
  vi.unstubAllGlobals()
})

async function mountView(): Promise<VueWrapper> {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/platform/sessions', component: { render: () => null } }] })
  await router.push('/platform/sessions')
  wrapper = mount(() => h(VApp, null, { default: () => h(PlatformSessions) }),
    { global: { plugins: [createPortalI18n(), vuetify, router] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('end all sessions (plan M8s decision 16)', () => {
  it('asks for the typed confirmation END and does nothing when cancelled', async () => {
    const w = await mountView()
    expect(w.text()).toContain('Portal sessions')
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    expect(pendingConfirm.value?.options).toMatchObject({ requireTypedText: 'END', destructive: true, confirmLabel: 'End all sessions' })
    settleConfirm(false)
    await flushPromises()
    expect(calls).toBe(0)
  })

  it('ends every session and returns to the login, the own session included', async () => {
    const w = await mountView()
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(calls).toBe(1)
    expect(assigned).toEqual(['/'])
  })

  it('starts the step-up when the server asks for one and shows other problems', async () => {
    answer = 'step_up_required'
    const w = await mountView()
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(started).toEqual(['sessions-end-all'])
    answer = 'session_store_unavailable'
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[role="alert"]').text()).toBe('The portal cannot reach its session store. Try again in a moment.')
    expect(assigned).toEqual([])
  })

  it('says the portal sessions are ended when the identity provider could not end its sessions', async () => {
    answer = 'upstream_unavailable'
    const w = await mountView()
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[role="alert"]').text()).toBe(
      "The portal sessions were ended, but the identity provider's sessions could not be ended. Run End all sessions again.")
    expect(assigned).toEqual([])
  })

  it('keeps the generic text for other failures', async () => {
    answer = 'forbidden'
    const w = await mountView()
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[role="alert"]').text()).toBe('You are not allowed to do this.')
    answer = 'internal'
    await w.find('[data-testid="end-all-sessions"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[role="alert"]').text()).toBe('Something went wrong. Please try again.')
    expect(assigned).toEqual([])
  })
})
