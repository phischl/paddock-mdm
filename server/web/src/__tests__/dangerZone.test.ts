import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { RevocationRequest } from '../api/client'
import DangerZone from '../components/DangerZone.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const base = {
  device_id: 'd1', hostname: 'lt-1', action: 'lock' as const, requested_at: '2026-10-07T10:00:00Z', reason: '',
  approvals: [], confirmed_at: '2026-10-07T10:01:03Z',
}
const requests: RevocationRequest[] = [
  {
    ...base, id: 'r1', status: 'failed', result: {
      erased: false, slots_before: 5, slots_after: 3, unresolved: ['UUID=0000-gone'], volumes: [
        { device: '/dev/sdb1', slots_before: 3, slots_after: 3, erased: false },
        { device: '/dev/sdc1', slots_before: 1, slots_after: -1, erased: false },
        { device: '/dev/sda3', slots_before: 2, slots_after: 0, erased: true },
      ],
    },
  },
  {
    // A device that reports the same device twice must not break the list.
    ...base, id: 'r3', status: 'failed', result: {
      erased: false, slots_before: 2, slots_after: 0, unresolved: ['/etc/crypttab', '/etc/crypttab'], volumes: [
        { device: '/dev/sda3', slots_before: 1, slots_after: 0, erased: true },
        { device: '/dev/sda3', slots_before: 1, slots_after: 0, erased: true },
      ],
    },
  },
  { ...base, id: 'r2', status: 'confirmed', result: { erased: true, slots_before: 2, slots_after: 0 } },
  {
    // PDK-009: a Lock leaves the volumes without an escrowed header alone; it is complete all the same.
    ...base, id: 'r4', status: 'confirmed', result: {
      erased: true, slots_before: 2, slots_after: 0,
      volumes: [{ device: '/dev/sda3', uuid: '0d8f4c62-0000-4000-8000-0000000000aa', slots_before: 2, slots_after: 0, erased: true }],
      skipped_not_escrowed: [{ device: '/dev/sdb1', uuid: '0d8f4c62-0000-4000-8000-0000000000bb' }, { device: '/dev/sdc1' }, { bogus: 1 }],
      shared_uuid: ['/dev/sdc1'],
    },
  },
]

const started: string[] = []
const requested: unknown[] = []
vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  listRevocations: () => () => Promise.resolve({ items: requests, page: 1, page_size: 10, total: 3, total_capped: false, sort: '-requested_at' }),
  requestRevocation: (...args: unknown[]) => {
    requested.push(args)
    return Promise.resolve({ ...base, id: 'r9', status: 'requested' })
  },
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string) => started.push(action),
  resumeStepUp: (action: string) => (resumeFor === action ? { payload: {}, failed: false } : null),
  withoutStepUpParam: () => '/devices/d1',
}))
let resumeFor: string | null = null

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  started.length = 0
  requested.length = 0
  resumeFor = null
})

async function mountZone(props: Record<string, unknown> = {}, revocationEnabled = true, onRetire?: () => void): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null,
    revocation_enabled: revocationEnabled,
  } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
  await router.push('/devices/d1')
  const App = () => h(VApp, null, {
    default: () => h(DangerZone, { deviceId: 'd1', hostname: 'lt-1', revocable: true, presumedSelfLockedAt: null, retirable: true, onRetire, ...props }),
  })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

const text = (testid: string) => document.querySelector(`[data-testid="${testid}"]`)?.textContent?.replace(/\s+/g, ' ').trim()

describe('danger zone (plan M7c decision 24)', () => {
  it('is the labelled last section with one row per action, each ending in an ellipsis, and no shared reason field', async () => {
    const w = await mountZone()
    const zone = w.find('#danger-zone')
    expect(zone.attributes('data-testid')).toBe('revocation')
    expect(zone.find('h2').attributes('tabindex')).toBe('-1')
    expect(zone.find('h2').text()).toBe('Danger zone — revocation')
    expect(zone.text()).toContain('Separately signed path.')
    expect(text('revocation-lock')).toBe('Lock device…')
    expect(text('revocation-destroy')).toBe('Request destroy…')
    expect(text('device-retire')).toBe('Retire…')
    expect(text('danger-lock')).toContain('Lock erases every keyslot')
    expect(text('danger-destroy')).toContain('second organization administrator')
    expect(text('danger-retire')).toContain('cannot be undone')
    expect(zone.find('input, textarea').exists()).toBe(false)
  })

  it('shows the disabled alert instead of Lock and Destroy while revocation is off; Retire stays', async () => {
    await mountZone({}, false)
    expect(document.querySelector('[data-testid="revocation-disabled"]')).not.toBeNull()
    expect(document.querySelector('[data-testid="revocation-lock"]')).toBeNull()
    expect(document.querySelector('[data-testid="revocation-destroy"]')).toBeNull()
    expect(document.querySelector('[data-testid="device-retire"]')).not.toBeNull()
  })

  it('hides Lock and Destroy for a device that cannot be revoked and Retire when it cannot be retired', async () => {
    await mountZone({ revocable: false, retirable: false })
    expect(document.querySelector('[data-testid="revocation-lock"]')).toBeNull()
    expect(document.querySelector('[data-testid="device-retire"]')).toBeNull()
  })

  it('starts the step-up on Lock and, on return, asks for the reason and the hostname in the dialog', async () => {
    const w = await mountZone()
    await w.find('[data-testid="revocation-lock"]').trigger('click')
    expect(started).toEqual(['revocation-lock'])
    w.unmount()
    resumeFor = 'revocation-lock'
    await mountZone()
    expect(pendingConfirm.value?.options).toMatchObject({ requireTypedText: 'lt-1', destructive: true, reason: { required: true, label: 'Reason' } })
    settleConfirm({ reason: 'stolen' })
    await flushPromises()
    expect(requested).toEqual([['d1', 'lock', 'lt-1', 'stolen']])
    expect(document.querySelector('[data-testid="revocation-requested"]')?.textContent).toContain('The lock was requested.')
  })

  it('emits retire for the page to run its typed confirmation', async () => {
    const onRetire = vi.fn()
    const w = await mountZone({}, true, onRetire)
    await w.find('[data-testid="device-retire"]').trigger('click')
    expect(onRetire).toHaveBeenCalledTimes(1)
  })

  it('lists the erasure of every volume and the unresolved crypttab entries (plan M4c.1 decision 4)', async () => {
    await mountZone()
    const lists = document.querySelectorAll('[aria-label="Encrypted volumes"]')
    // A confirmation from before M4c.1 has no volumes and shows no list.
    expect(lists).toHaveLength(3)
    expect([...lists[0].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sdb1: not erased, 3 keyslots left',
      '/dev/sdc1: not erased, the remaining keyslots are unknown',
      '/dev/sda3: 2 keyslots erased',
      'UUID=0000-gone: listed in /etc/crypttab but not erased with certainty',
    ])
    expect([...lists[1].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sda3: 1 keyslot erased', '/dev/sda3: 1 keyslot erased',
      '/etc/crypttab: listed in /etc/crypttab but not erased with certainty',
      '/etc/crypttab: listed in /etc/crypttab but not erased with certainty',
    ])
    expect([...lists[2].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sda3: 2 keyslots erased',
      '/dev/sdb1: not erased, its header was not escrowed (the volume stays readable)',
      '/dev/sdc1: not erased, its header was not escrowed (the volume stays readable)',
      '/dev/sdc1: shares its LUKS UUID with another volume',
    ])
    // Both failed requests are marked incomplete; the M4c confirmation and the Lock with skipped volumes are not.
    const incomplete = [...document.querySelectorAll('p')].filter((p) => p.textContent?.includes('Incomplete: not every encrypted volume'))
    expect(incomplete).toHaveLength(2)
    const chips = [...document.querySelectorAll('[data-testid="revocation-timeline"] .pd-chip')].map((c) => c.textContent?.trim())
    expect(chips).toEqual(['Failed', 'Failed', 'Confirmed', 'Confirmed'])
  })
})
