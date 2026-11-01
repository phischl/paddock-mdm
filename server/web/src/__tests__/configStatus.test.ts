import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h, provide, ref } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceBundle, DeviceDetail, DeviceResourceStatus } from '../api/client'
import { createPortalI18n } from '../i18n'
import { isReportOnly, listConfigStatus, listDeviceBundles, listDeviceConfigStatus, resourceStateView } from '../lib/configStatus'
import { deviceDetailKey, type DevicePage } from '../lib/deviceDetailPage'
import { vuetify } from '../plugins/vuetify'
import DeviceApplyStatus from '../views/DeviceApplyStatus.vue'

const get = vi.hoisted(() => vi.fn())
vi.mock('../api/client', async (original) => ({
  ...(await original<typeof import('../api/client')>()),
  api: { GET: get },
}))

const empty = { items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'resource_id' }
const base = { page: 1, page_size: 25 as const }

beforeEach(() => {
  get.mockReset()
  get.mockResolvedValue({ data: empty })
})

describe('apply status lists', () => {
  it('passes search, sort and the status filter of the device list', async () => {
    await listDeviceConfigStatus('d1')({ ...base, sort: '-occurred_at', q: 'nginx', status: ['failed'] })
    expect(get).toHaveBeenCalledWith('/api/v1/devices/{id}/config-status', {
      params: { path: { id: 'd1' }, query: { page: 1, page_size: 25, sort: '-occurred_at', q: 'nginx', status: ['failed'] } },
    })
  })

  it('reads the bundle history and the fleet view', async () => {
    await listDeviceBundles('d1')({ ...base, sort: '-version' })
    expect(get.mock.calls[0][0]).toBe('/api/v1/devices/{id}/bundles')
    await listConfigStatus({ ...base, sort: '-failed', status: ['failed'] })
    expect(get.mock.calls[1]).toEqual(['/api/v1/config-status', {
      params: { query: { page: 1, page_size: 25, sort: '-failed', q: undefined, status: ['failed'] } },
    }])
  })

  it('turns a problem into a list error', async () => {
    get.mockResolvedValue({ error: { code: 'forbidden' } })
    await expect(listConfigStatus({ ...base, sort: '-failed' })).rejects.toMatchObject({ code: 'forbidden' })
  })
})

describe('resourceStateView', () => {
  it('maps the statuses to chip colours', () => {
    expect(resourceStateView('applied').status).toBe('ok')
    expect(resourceStateView('drift_corrected').status).toBe('info')
    expect(resourceStateView('pending').status).toBe('warn')
    expect(resourceStateView('failed')).toEqual({ status: 'critical', label: 'configStatus.states.failed' })
  })
})

describe('isReportOnly', () => {
  it('is false while the device carries no mode and true for report_only', () => {
    expect(isReportOnly({} as DeviceDetail)).toBe(false)
    expect(isReportOnly({ config_mode: 'enforce' } as unknown as DeviceDetail)).toBe(false)
    expect(isReportOnly({ config_mode: 'report_only' } as unknown as DeviceDetail)).toBe(true)
  })
})

describe('DeviceApplyStatus', () => {
  let wrapper: VueWrapper | null = null
  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  const resources: DeviceResourceStatus[] = [
    { resource_id: 'unit:foo.service', type: 'unit', status: 'failed', message: 'unit not found', changes: [], bundle_version: 4, occurred_at: '2026-10-10T12:00:00Z' },
    { resource_id: 'file:/etc/foo.conf', type: 'file', status: 'pending', message: '', changes: ['write /etc/foo.conf'], bundle_version: 4, occurred_at: '2026-10-10T12:00:00Z' },
  ]
  const bundles: DeviceBundle[] = [
    { version: 4, created_at: '2026-10-10T11:00:00Z', schema_version: 3, config_rollout_id: null, report: { outcome: 'applied', mode: 'enforce', changed: 1, error_count: 1, reason: null, occurred_at: '2026-10-10T12:00:00Z' } },
    { version: 3, created_at: '2026-10-09T11:00:00Z', schema_version: 3, config_rollout_id: null, report: null },
  ]

  async function mountTab(device: Record<string, unknown>) {
    get.mockImplementation((path: string) =>
      Promise.resolve({ data: { ...empty, items: path.endsWith('/bundles') ? bundles : resources } }),
    )
    const pinia = createPinia()
    setActivePinia(pinia)
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id/apply-status', name: 'device-apply-status', component: DeviceApplyStatus }] })
    await router.push('/devices/d1/apply-status')
    const page = { device: ref({ id: 'd1', config_status: { applied: 3, failed: 1, pending: 1, drift_corrected: 0 }, ...device }) } as unknown as DevicePage
    const Frame = defineComponent({
      setup() {
        provide(deviceDetailKey, page)
        return () => h(VApp, null, { default: () => h(DeviceApplyStatus) })
      },
    })
    wrapper = mount(Frame, { global: { plugins: [createPortalI18n(), vuetify, pinia, router] }, attachTo: document.body })
    await flushPromises()
  }

  it('shows the counts, the failure message and the bundle history', async () => {
    await mountTab({})
    expect(document.querySelector('[data-testid="apply-counts"]')?.textContent).toContain('1 failed')
    const rows = [...document.querySelectorAll('[data-testid="apply-status-list"] tbody tr')].map((r) => r.textContent)
    expect(rows.some((r) => r?.includes('unit:foo.service') && r.includes('Failed') && r.includes('unit not found'))).toBe(true)
    const history = document.querySelector('[data-testid="bundle-history-list"]')?.textContent ?? ''
    expect(history).toContain('Applied')
    expect(history).toContain('Not reported')
    expect(document.querySelector('[data-testid="apply-report-only"]')).toBeNull()
  })

  it('expands a pending row to its planned changes', async () => {
    await mountTab({})
    const pending = [...document.querySelectorAll('[data-testid="apply-status-list"] tbody tr')].find((r) => r.textContent?.includes('file:/etc/foo.conf'))!
    pending.querySelector<HTMLButtonElement>('[data-testid="list-expand"]')!.click()
    await flushPromises()
    expect(document.querySelector('[data-testid="apply-status-list"]')?.textContent).toContain('write /etc/foo.conf')
  })

  it('shows the report-only banner for a device in report-only mode', async () => {
    await mountTab({ config_mode: 'report_only' })
    expect(document.querySelector('[data-testid="apply-report-only"]')).not.toBeNull()
  })
})
