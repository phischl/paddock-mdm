import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import UpgradeCard from '../components/UpgradeCard.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import type { Me } from '../api/client'
import type { UpgradeCheck } from '../lib/upgradeCheck'

const platform: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'root@paddock.test', display_name: 'Root',
  role: 'platform_admin', organization: null, locale: 'en', theme: 'system', revocation_enabled: false,
  client_ip: '198.51.100.7', step_up_valid_until: null, server_version: '0.1.0-alpha.9', alternate_role: null,
  channel: 'portal', mcp_write_enabled: false, mcp_write_enabled_at: null,
}
const orgAdmin: Me = {
  ...platform, role: 'org_admin', organization: { id: 'o1', slug: 'acme', name: 'Acme', domains: ['acme.test'] },
}

const report: UpgradeCheck = {
  generated_at: '2026-11-06T10:00:00Z',
  target_version: '0.1.0-alpha.9',
  window: ['0.1.0-alpha.7', '0.1.0-alpha.8', '0.1.0-alpha.9'],
  items: [
    { name: 'migrations', status: 'PASS', detail: 'database at 00110' },
    { name: 'agents', status: 'WARN', detail: '2 of 120 active devices run 0.1.0-alpha.6: lt-01, lt-02' },
    { name: 'backups', status: 'WARN', detail: 'target nas has no recent success for kind postgres' },
    { name: 'openbao', status: 'INFO', detail: 'unsealed; automatic unseal off' },
    { name: 'pending', status: 'PASS', detail: 'nothing pending' },
    { name: 'sessions', status: 'INFO', detail: '1 platform administrator signed in' },
  ],
  agents_outside: [
    { device_id: 'd1', hostname: 'lt-01', agent_version: '0.1.0-alpha.6' },
    { device_id: 'd2', hostname: 'lt-02', agent_version: '0.1.0-alpha.6' },
  ],
}

const getUpgradeCheck = vi.fn<(version: string) => Promise<UpgradeCheck | string>>()
vi.mock('../lib/upgradeCheck', async (original) => ({
  ...(await original<typeof import('../lib/upgradeCheck')>()),
  getUpgradeCheck: (version: string) => getUpgradeCheck(version),
}))

let wrapper: VueWrapper | null = null
beforeEach(() => getUpgradeCheck.mockReset())
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountCard(me: Me, locale: PortalLocale = 'en'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = me
  wrapper = mount(UpgradeCard, { global: { plugins: [createPortalI18n(locale), vuetify, pinia] } })
  await flushPromises()
  return wrapper
}

describe('UpgradeCard', () => {
  it('shows the window, the agents outside it and the backup state of the running release', async () => {
    getUpgradeCheck.mockResolvedValue(report)
    const w = await mountCard(platform)
    expect(getUpgradeCheck).toHaveBeenCalledWith('0.1.0-alpha.9')
    expect(w.get('h2').text()).toBe('Upgrade')
    expect(w.get('[data-testid="upgrade-version"]').text()).toBe('Release 0.1.0-alpha.9')
    expect(w.get('[data-testid="upgrade-window"]').text()).toContain('0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9')
    const agents = w.get('[data-testid="upgrade-agents"]').text()
    expect(agents).toContain('2 active devices run an agent outside the window')
    expect(agents).toContain('lt-01, lt-02')
    expect(agents).toContain('Warning')
    const backups = w.get('[data-testid="upgrade-backups"]').text()
    expect(backups).toContain('Warning')
    expect(backups).toContain('target nas has no recent success for kind postgres')
  })

  it('says so when no agent is outside the window and offers no action', async () => {
    getUpgradeCheck.mockResolvedValue({
      ...report,
      items: report.items.map((i) => (i.name === 'agents' ? { ...i, status: 'PASS' as const } : i)),
      agents_outside: [],
    })
    const w = await mountCard(platform)
    expect(w.get('[data-testid="upgrade-agents"]').text()).toContain('No active device runs an agent outside the window.')
    expect(w.find('button').exists()).toBe(false)
    expect(w.find('a').exists()).toBe(false)
  })

  it('names how many more devices are outside the window than it lists', async () => {
    getUpgradeCheck.mockResolvedValue({
      ...report,
      agents_outside: Array.from({ length: 8 }, (_, i) => ({ device_id: `d${i}`, hostname: `lt-0${i}`, agent_version: '0.1.0-alpha.6' })),
    })
    const w = await mountCard(platform)
    const agents = w.get('[data-testid="upgrade-agents"]').text()
    expect(agents).toContain('8 active devices run an agent outside the window')
    expect(agents).toContain('lt-00, lt-01, lt-02, lt-03, lt-04')
    expect(agents).toContain('and 3 more')
    expect(agents).not.toContain('lt-05')
  })

  it('explains a server version that is not a known release instead of an error code', async () => {
    getUpgradeCheck.mockResolvedValue('invalid_request')
    const w = await mountCard({ ...platform, server_version: '0.0.0-dev' })
    expect(getUpgradeCheck).toHaveBeenCalledWith('0.0.0-dev')
    expect(w.get('[data-testid="upgrade-problem"]').text()).toContain('not a known release')
    expect(w.find('[data-testid="upgrade-window"]').exists()).toBe(false)
  })

  it('shows the message of another problem', async () => {
    getUpgradeCheck.mockResolvedValue('internal')
    const w = await mountCard(platform)
    expect(w.get('[data-testid="upgrade-problem"]').text()).not.toBe('')
    expect(w.find('[data-testid="upgrade-window"]').exists()).toBe(false)
  })

  it('is absent for an organization role and reads nothing', async () => {
    const w = await mountCard(orgAdmin)
    expect(w.find('[data-testid="upgrade-card"]').exists()).toBe(false)
    expect(getUpgradeCheck).not.toHaveBeenCalled()
  })

  it('renders in German', async () => {
    getUpgradeCheck.mockResolvedValue(report)
    const w = await mountCard(platform, 'de')
    expect(w.get('[data-testid="upgrade-agents"]').text()).toContain('2 aktive Geräte nutzen einen Agent außerhalb des Fensters')
  })
})
