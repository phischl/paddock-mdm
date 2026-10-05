import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import LocalAdminCard from '../components/LocalAdminCard.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { settleConfirm, pendingConfirm } from '../composables/useConfirm'
import { resumeStepUp, startStepUp } from '../lib/stepUp'
import { rotationOverdue } from '../lib/localAdmin'
import { useSessionStore } from '../stores/session'

const state = {
  username: 'paddock-admin', active_generation: 2, pending_generation: null, last_rotated_at: '2026-10-01T08:00:00Z',
  next_rotation_at: '2026-10-31T08:00:00Z', last_rotation_error: null,
}

describe('step-up resume', () => {
  beforeEach(() => sessionStorage.clear())

  it('repeats the pending action once for its page and reports a refused step-up', () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', { value: { ...window.location, assign, href: 'https://admin.test/devices/d1?page=2', search: '' }, writable: true })
    startStepUp('reveal', 'd1', { x: 1 })
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fdevices%2Fd1%3Fpage%3D2')
    expect(resumeStepUp('reveal', 'd2')).toBeNull()
    expect(resumeStepUp('reveal', 'd1')).toEqual({ failed: false, payload: { x: 1 } })
    expect(resumeStepUp('reveal', 'd1')).toBeNull()
    startStepUp('reveal', 'd1')
    Object.defineProperty(window, 'location', { value: { ...window.location, search: '?stepup=failed' }, writable: true })
    expect(resumeStepUp('reveal', 'd1')).toEqual({ failed: true })
  })
})

const reveal = vi.fn(async (...args: [string, string]) => (args.length ? { passwords: [{ generation: 2, state: 'active' as const, password: 'S3cret-Pass' }] } : { passwords: [] }))
vi.mock('../lib/localAdmin', async (original) => ({
  ...(await original<typeof import('../lib/localAdmin')>()),
  getLocalAdmin: () => Promise.resolve(state),
  revealLocalAdmin: (id: string, hostname: string) => reveal(id, hostname),
}))

describe('local administrator card', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    sessionStorage.clear()
    setActivePinia(createPinia())
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('reveals after the step-up and the typed hostname, and hides the password after 60 s', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'reveal', target: 'd1', payload: null, at: Date.now() }))
    Object.defineProperty(window, 'location', { value: { ...window.location, href: 'https://admin.test/devices/d1', search: '' }, writable: true })
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
    await router.push('/devices/d1')
    const App = () => h(VApp, null, { default: () => h(LocalAdminCard, { deviceId: 'd1', hostname: 'lt-1', active: true }) })
    const wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
    await flushPromises()
    // The pending reveal asks for the typed hostname before anything is revealed.
    expect(pendingConfirm.value?.options.requireTypedText).toBe('lt-1')
    expect(reveal).not.toHaveBeenCalled()
    settleConfirm(true)
    await flushPromises()
    expect(reveal).toHaveBeenCalledWith('d1', 'lt-1')
    expect(document.body.textContent).toContain('hidden in 60 seconds')
    const field = document.querySelector('[data-testid="revealed-active"] input') as HTMLInputElement
    expect(field.value).toBe('S3cret-Pass')
    vi.advanceTimersByTime(60_000)
    await flushPromises()
    expect(document.querySelector('[data-testid="revealed-active"] input')).toBeNull()
    expect(document.body.innerHTML).not.toContain('S3cret-Pass')
    wrapper.unmount()
  })

  it('marks an overdue rotation', () => {
    expect(rotationOverdue({ ...state, next_rotation_at: '2026-01-01T00:00:00Z' }, new Date('2026-10-05T00:00:00Z'))).toBe(true)
    expect(rotationOverdue(state, new Date('2026-10-05T00:00:00Z'))).toBe(false)
  })
})
