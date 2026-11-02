import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import EnforceCard from '../components/EnforceCard.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { configModeFilter, enrollmentMethodFilter, listDevices } from '../lib/devices'
import type { ListFilter } from '../lib/listQuery'
import { vuetify } from '../plugins/vuetify'

const post = vi.hoisted(() => vi.fn())
const get = vi.hoisted(() => vi.fn())
vi.mock('../api/client', async (original) => ({
  ...(await original<typeof import('../api/client')>()),
  api: { POST: post, GET: get },
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  post.mockReset()
})

async function mountCard(reportOnly = true) {
  setActivePinia(createPinia())
  const changed = vi.fn()
  wrapper = mount(VApp, {
    slots: { default: () => h(EnforceCard, { deviceId: 'd1', hostname: 'lt-adopted', reportOnly, onChanged: changed }) },
    global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body,
  })
  await flushPromises()
  return { w: wrapper, changed }
}

describe('EnforceCard (plan M11 decisions 42 and 43)', () => {
  it('asks in the modal for the typed hostname with the consequence sentence, then enforces and announces it', async () => {
    post.mockResolvedValue({ data: {} })
    const { w, changed } = await mountCard()
    await w.find('[data-testid="enforce-device"]').trigger('click')
    await flushPromises()
    const asked = pendingConfirm.value?.options
    expect(asked?.requireTypedText).toBe('lt-adopted')
    expect(asked?.destructive).toBe(true)
    expect(asked?.message).toContain('remove unexpected members of privileged groups (never the last administrator)')
    expect(asked?.message).toContain('quarantine foreign sudoers files')
    expect(post).not.toHaveBeenCalled()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(post).toHaveBeenCalledWith('/api/v1/devices/{id}/enforce', {
      params: { path: { id: 'd1' }, header: { 'X-Paddock-CSRF': '1' } }, body: { hostname: 'lt-adopted' },
    })
    expect(changed).toHaveBeenCalledOnce()
    expect(w.find('[role="status"]').text()).toContain('Enforcement is enabled')
  })

  it('does nothing when cancelled and shows a refusal inline', async () => {
    const { w, changed } = await mountCard()
    await w.find('[data-testid="enforce-device"]').trigger('click')
    await flushPromises()
    settleConfirm(false)
    await flushPromises()
    expect(post).not.toHaveBeenCalled()
    post.mockResolvedValue({ error: { code: 'invalid_state' } })
    await w.find('[data-testid="enforce-device"]').trigger('click')
    await flushPromises()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(changed).not.toHaveBeenCalled()
    expect(w.find('[role="alert"]').exists()).toBe(true)
  })

  it('renders nothing for an enforced device', async () => {
    const { w } = await mountCard(false)
    expect(w.find('[data-testid="enforce-card"]').exists()).toBe(false)
  })
})

describe('device list adoption filters (plan M11 decision 43)', () => {
  it('offers the methods and modes and passes them to the list query', async () => {
    const values = (f: ListFilter) => (f.kind === 'enum' ? f.options.map((o) => o.value) : [])
    expect(values(enrollmentMethodFilter)).toEqual(['autoinstall', 'adopted', 'unknown'])
    expect(values(configModeFilter)).toEqual(['enforce', 'report_only'])
    get.mockResolvedValue({ data: { items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'hostname' } })
    await listDevices({ page: 1, page_size: 25, sort: 'hostname', enrollment_method: ['adopted'], config_mode: ['report_only'] })
    const query = get.mock.calls[0][1].params.query
    expect(query.enrollment_method).toEqual(['adopted'])
    expect(query.config_mode).toEqual(['report_only'])
  })
})
