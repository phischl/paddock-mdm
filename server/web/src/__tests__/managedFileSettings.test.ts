import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import ManagedFileSettings from '../views/ManagedFileSettings.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'

let roots = ['/etc/myapp/']
const setOperatorRoots = vi.fn<(r: string[]) => Promise<string | null>>()
vi.mock('../lib/managedConfig', async (original) => ({
  ...(await original<typeof import('../lib/managedConfig')>()),
  getOperatorRoots: () => Promise.resolve(roots),
  setOperatorRoots: (r: string[]) => setOperatorRoots(r),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  setOperatorRoots.mockReset()
  assign.mockReset()
  roots = ['/etc/myapp/']
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/settings/managed-files', search: '' }, writable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountSettings(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/managed-files', component: ManagedFileSettings }] })
  await router.push('/settings/managed-files')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('ManagedFileSettings (ADR 0034 amendment 2026-10-16)', () => {
  it('confirms, steps up and saves the roots after the return', async () => {
    setOperatorRoots.mockResolvedValueOnce('step_up_required')
    const w = await mountSettings()
    const field = document.querySelector('#operator-roots') as HTMLTextAreaElement
    expect(field.value).toBe('/etc/myapp/')
    field.value = '/etc/myapp/\n/opt/vendor/\n'
    field.dispatchEvent(new Event('input'))
    await flushPromises()
    await w.find('[data-testid="save-roots"]').trigger('submit')
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(pendingConfirm.value?.options.message).toContain('2 operator roots')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(setOperatorRoots).toHaveBeenCalledWith(['/etc/myapp/', '/opt/vendor/'])
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fmanaged-files')
    wrapper?.unmount()

    setOperatorRoots.mockResolvedValueOnce(null)
    const resumed = await mountSettings()
    expect(setOperatorRoots).toHaveBeenLastCalledWith(['/etc/myapp/', '/opt/vendor/'])
    expect(resumed.find('[data-testid="roots-saved"]').exists()).toBe(true)
  })
})
