import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h, provide, ref } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceDetail, DeviceUpdates, RevocationRequest } from '../api/client'
import DeviceHeader from '../components/DeviceHeader.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { deviceDetailKey, type DevicePage } from '../lib/deviceDetailPage'
import { healthRows, lockedByRevocation, paneOnly, paneQuery } from '../lib/deviceHealth'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const rotated: string[] = []
vi.mock('../lib/localAdmin', async (original) => ({
  ...(await original<typeof import('../lib/localAdmin')>()),
  rotateLocalAdmin: (id: string) => {
    rotated.push(id)
    return Promise.resolve(null)
  },
}))

const agentUpdate = vi.fn<(id: string) => Promise<{ problem: string; detail?: string } | null>>()
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  requestAgentUpdate: (id: string) => agentUpdate(id),
}))

const now = '2026-10-10T12:00:00Z'
function deviceOf(over: Partial<DeviceDetail> = {}): DeviceDetail {
  return {
    id: 'd1', hostname: 'acme-lt-0142', state: 'active', contact: 'ok', hardware_uuid: null, machine_id: null,
    os_release: { VERSION_ID: '24.04' }, enrollment_token_id: null, enrolled_at: now, state_changed_at: now, bundle_version: 3,
    last_contact_at: now, applied_bundle_version: 3, agent_version: '1.9.1', groups: [], identity_keys: [], logins_suspended: false,
    login_assignment: { users: [], groups: [] }, schema_versions: [], login_management: true, login_status: { login: null, sudo: null },
    sudo_flavor: null, presumed_self_locked_at: null, presumed_lost_at: null, ...over,
  } as DeviceDetail
}
const updates: DeviceUpdates = { last_security_run: null, last_regular_run: null, reboot_required: false, holds: [], conflicts: [] }
const lock = (status: RevocationRequest['status'], at = now): RevocationRequest =>
  ({ id: 'r-' + status + at, device_id: 'd1', hostname: 'acme-lt-0142', action: 'lock', status, requested_at: at, reason: '', approvals: [] }) as never

describe('device health and header helpers (plan M7c decision 29)', () => {
  it('derives one chip per health row from the device, the disk, the updates and the open conditions', () => {
    const rows = healthRows({ device: deviceOf(), diskState: 'compliant', updates, conditions: [] })
    expect(rows.map((r) => [r.key, r.view.status])).toEqual([
      ['contact', 'ok'], ['encryption', 'ok'], ['agent', 'ok'], ['security', 'neutral'], ['reboot', 'ok'], ['login', 'neutral'], ['sudo', 'neutral'],
    ])
    const bad = healthRows({
      device: deviceOf({
        agent_version: null, contact: 'presumed_lost',
        login_status: { login: { type: 'login.apply_failed', occurred_at: now, params: {} }, sudo: { type: 'sudo.applied', occurred_at: now, params: {} } },
      } as Partial<DeviceDetail>),
      diskState: 'not_encrypted',
      updates: { ...updates, reboot_required: true, last_security_run: { type: 'updates.run', occurred_at: now, params: { result: 'failed' } } },
      conditions: ['agent_outdated', 'sudo_apply_failed'],
    })
    expect(Object.fromEntries(bad.map((r) => [r.key, r.view.status]))).toEqual({
      contact: 'critical', encryption: 'critical', agent: 'warn', security: 'warn', reboot: 'warn', login: 'warn', sudo: 'warn',
    })
  })

  it('marks a device locked only while its latest Lock is issued, delivered or confirmed', () => {
    expect(lockedByRevocation([])).toBe(false)
    expect(lockedByRevocation([lock('confirmed')])).toBe(true)
    expect(lockedByRevocation([lock('requested')])).toBe(false)
    expect(lockedByRevocation([lock('delivered', '2026-10-01T00:00:00Z'), lock('cancelled')])).toBe(false)
  })

  it('carries the device list query into the pane and keeps only the pane keys', () => {
    expect(paneQuery({ q: 'acme', state: ['active'], sort: '-hostname', page: '2', disk_state: 'compliant' })).toEqual({
      'pane.q': 'acme', 'pane.state': ['active'], 'pane.sort': '-hostname', 'pane.page': '2',
    })
    expect(paneOnly({ 'pane.q': 'acme', q: 'x' })).toEqual({ 'pane.q': 'acme' })
  })
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  rotated.length = 0
})

async function mountHeader(device: DeviceDetail, role = 'org_admin', actions: string[] = [], revocations: RevocationRequest[] = []) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
  const changed = vi.fn(() => Promise.resolve())
  const run = vi.fn()
  const page = {
    device: ref(device), actions: ref(actions), diskState: ref('compliant'), revocations: ref(revocations), changed, run,
  } as unknown as DevicePage
  const Frame = defineComponent({
    setup() {
      provide(deviceDetailKey, page)
      return () => h(VApp, null, { default: () => h(DeviceHeader) })
    },
  })
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { render: () => null } }, { path: '/devices', name: 'devices', component: { render: () => null } }] })
  await router.push('/')
  wrapper = mount(Frame, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return { w: wrapper, changed, run }
}

const buttons = () => [...document.querySelectorAll('[data-testid="device-header"] .v-btn')].map((b) => b.getAttribute('data-testid'))

describe('device header band (plan M7c decision 29)', () => {
  it('shows the breadcrumb, the hostname as h1, the status chips and the meta line', async () => {
    const { w } = await mountHeader(deviceOf({ logins_suspended: true }), 'org_admin', ['retire'], [lock('confirmed')])
    expect(w.find('nav[aria-label="Breadcrumb"]').text()).toContain('Devices')
    expect(w.find('h1').text()).toBe('acme-lt-0142')
    expect(w.find('[data-testid="device-state"]').text()).toBe('Online')
    expect(w.findAll('.pd-chip').map((c) => c.text())).toEqual(['Online', 'Encrypted', 'Logins suspended', 'Locked'])
    expect(w.text()).toContain('agent 1.9.1')
  })

  it('names no recent contact and explains the contact states in the state chip tooltip (plan M8x decision 61)', async () => {
    const { w } = await mountHeader(deviceOf({ contact: 'unseen' }))
    expect(w.find('[data-testid="device-state"]').text()).toBe('No recent contact')
    expect(w.findAll('.pd-chip')[0].attributes('title')).toBe(
      'Online: a check-in within the last 15 minutes. No recent contact: none for more than 15 minutes, below the silence threshold of the organization.')
  })

  it('offers Install updates and Rotate for an active device, never Retire, Lock or Destroy', async () => {
    await mountHeader(deviceOf(), 'org_admin', ['retire'])
    expect(buttons()).toEqual(['install-now', 'update-agent', 'local-admin-rotate'])
    expect(document.querySelector('[data-testid="install-now"]')?.textContent?.trim()).toBe('Install updates…')
  })

  it('offers approve and reject for a pending device and nothing to auditors', async () => {
    await mountHeader(deviceOf({ state: 'pending', contact: 'never' }), 'org_admin', ['approve', 'reject'])
    expect(buttons()).toEqual(['device-approve', 'device-reject'])
    wrapper?.unmount()
    await mountHeader(deviceOf(), 'org_auditor', [])
    expect(buttons()).toEqual([])
  })

  it('rotates after the confirmation, announces it and tells the page to reload', async () => {
    const { w, changed } = await mountHeader(deviceOf(), 'org_admin')
    await w.find('[data-testid="local-admin-rotate"]').trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options.title).toBe('Rotate the local administrator password')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(rotated).toEqual(['d1'])
    expect(changed).toHaveBeenCalled()
    expect(w.find('[role="status"]').text()).toBe('The device rotates the password with its next check-in.')
  })

  it('asks before Update agent now, sends the request and shows the open request (PDK-226)', async () => {
    agentUpdate.mockResolvedValue(null)
    const { w, changed } = await mountHeader(deviceOf(), 'org_operator')
    await w.find('[data-testid="update-agent"]').trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options.title).toBe('Update the agent now')
    expect(pendingConfirm.value?.options.destructive).toBeFalsy()
    expect(pendingConfirm.value?.options.message).toContain('to acme-lt-0142 at its next check-in')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(agentUpdate).toHaveBeenCalledWith('d1')
    expect(changed).toHaveBeenCalled()
    wrapper?.unmount()
    await mountHeader(deviceOf({ agent_update_requested_version: '2.0.0', agent_update_requested_at: now } as Partial<DeviceDetail>))
    expect(document.querySelector('[data-testid="update-agent-requested"]')?.textContent).toContain('Update to 2.0.0 requested')
  })

  it('names the refusal of a device that already runs the release', async () => {
    agentUpdate.mockResolvedValue({ problem: 'invalid_state', detail: 'the device already runs 2.0.0' })
    const { w } = await mountHeader(deviceOf(), 'org_admin')
    await w.find('[data-testid="update-agent"]').trigger('click')
    await flushPromises()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[role="status"]').text()).toBe('The device already runs the offered release.')
  })
})
