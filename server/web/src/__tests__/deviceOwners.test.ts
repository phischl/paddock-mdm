import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import DeviceOwners from '../components/DeviceOwners.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

const setDeviceOwners = vi.fn<(id: string, users: string[]) => Promise<string | null>>()

vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  setDeviceOwners: (id: string, users: string[]) => setDeviceOwners(id, users),
}))
vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  allUsers: () => Promise.resolve([
    { id: 'u1', username: 'alice@acme.test' }, { id: 'u2', username: 'bob@acme.test' },
  ]),
}))

const owners = [{ id: 'u1', username: 'alice@acme.test', display_name: 'Alice' }]
let wrapper: VueWrapper | null = null

async function render(props: { owners: typeof owners; canWrite: boolean }, onSaved = () => {}): Promise<void> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { render: () => null } }, { path: '/users/:id', name: 'user', component: { render: () => null } }],
  })
  await router.push('/')
  const App = () => h(VApp, null, { default: () => h(DeviceOwners, { deviceId: 'd1', ...props, onSaved }) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router] }, attachTo: document.body })
  await flushPromises()
}

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  setDeviceOwners.mockReset()
})

describe('device owners panel (PDK-220)', () => {
  it('shows read-only owner chips that link to the users for readers', async () => {
    await render({ owners, canWrite: false })
    const panel = document.querySelector('[data-testid="device-owners"]')
    expect(panel?.querySelector('h2')?.textContent?.trim()).toBe('Owners')
    expect(panel?.textContent).toContain('Owners have no login or sudo rights through this setting.')
    const link = panel?.querySelector('a.chip-link')
    expect(link?.textContent?.trim()).toBe('alice@acme.test')
    expect(link?.getAttribute('href')).toBe('/users/u1')
    expect(document.querySelector('[data-testid="save-device-owners"]')).toBeNull()
  })

  it('says when no owner is assigned', async () => {
    await render({ owners: [], canWrite: false })
    expect(document.querySelector('[data-testid="device-owners-none"]')?.textContent?.trim()).toBe('No owner assigned.')
  })

  it('saves the selected owners and confirms it for writers', async () => {
    setDeviceOwners.mockResolvedValue(null)
    const saved = vi.fn()
    await render({ owners, canWrite: true }, saved)
    ;(document.querySelector('[data-testid="save-device-owners"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(setDeviceOwners).toHaveBeenCalledWith('d1', ['u1'])
    expect(saved).toHaveBeenCalledOnce()
    expect(document.querySelector('[data-testid="device-owners"] [role="status"]')?.textContent?.trim()).toBe('Owners saved.')
  })

  it('shows the problem when saving fails', async () => {
    setDeviceOwners.mockResolvedValue('invalid_request')
    const saved = vi.fn()
    await render({ owners, canWrite: true }, saved)
    ;(document.querySelector('[data-testid="save-device-owners"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(saved).not.toHaveBeenCalled()
    expect(document.querySelector('[data-testid="device-owners"] [role="alert"]')).not.toBeNull()
  })
})
