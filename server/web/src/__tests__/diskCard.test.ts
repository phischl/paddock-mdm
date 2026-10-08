import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DiskEncryption } from '../api/client'
import DiskEncryptionCard from '../components/DiskEncryptionCard.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const at = '2026-10-08T10:00:00Z'
const disk: DiskEncryption = {
  state: 'escrow_pending', luks_version: 2, tokens: ['recovery', 'tpm2+pin'], keyslots: 2, reported_at: at,
  recovery_keys: [{ generation: 1, status: 'stored', created_at: at }],
  headers: [
    { generation: 3, status: 'stored', created_at: at, volume: '0d8f4c62-0000-4000-8000-0000000000bb' },
    { generation: 1, status: 'stored', created_at: at },
  ],
  volumes: [
    { uuid: '0d8f4c62-0000-4000-8000-0000000000aa', device: '/dev/sda3', root: true, luks_version: 2, keyslots: 2,
      tokens: ['recovery', 'tpm2+pin'], escrowed: true, header_generation: 1 },
    { uuid: '0d8f4c62-0000-4000-8000-0000000000bb', device: '/dev/sdb1', root: false, luks_version: 2, keyslots: 1,
      tokens: ['password'], escrowed: true, header_generation: 3 },
    { uuid: '0d8f4c62-0000-4000-8000-0000000000cc', device: '/dev/sdc1', root: false, luks_version: 1, keyslots: 1,
      tokens: ['password'], escrowed: false },
    { device: '/dev/sdd', root: false, keyslots: 0, tokens: [], escrowed: false },
    { uuid: '0d8f4c62-0000-4000-8000-0000000000aa', device: '/dev/sde', root: false, keyslots: 0, tokens: [], escrowed: false, shared_uuid: true },
    { uuid: '0d8f4c62-0000-4000-8000-0000000000dd', device: '/dev/sdf', root: false, keyslots: 1, tokens: ['password'], escrowed: false, refused: true },
  ],
  unresolved: ['LABEL=backup'],
}

vi.mock('../lib/disk', async (original) => ({
  ...(await original<typeof import('../lib/disk')>()),
  getDisk: () => Promise.resolve(disk),
}))

describe('disk encryption card', () => {
  it('lists every volume and offers the header of each escrowed volume (PDK-009 decisions 4 and 5)', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = {
      id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null, revocation_enabled: true,
    } as never
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
    await router.push('/devices/d1')
    const App = () => h(VApp, null, { default: () => h(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' }) })
    const wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
    await flushPromises()
    const volumes = document.querySelector('[data-testid="disk-volumes"]')
    expect([...(volumes?.querySelectorAll('div') ?? [])].map((d) => d.textContent?.trim())).toEqual([
      '/dev/sda3 (root): 2 keyslots, LUKS 2, header escrowed',
      '/dev/sdb1: 1 keyslot, LUKS 2, header escrowed',
      '/dev/sdc1: 1 keyslot, LUKS 1, header not escrowed yet',
      '/dev/sdd: not inventoried, its LUKS UUID is unknown',
      '/dev/sde: shares its LUKS UUID with another volume (a cloned header); not escrowed, a Lock leaves it readable, a Destroy erases it',
      '/dev/sdf: header not escrowed, the device already escrows 32 volumes',
      'LABEL=backup: listed in /etc/crypttab but not classified; not escrowed',
    ])
    expect([...document.querySelectorAll('[data-testid="disk-header"]')].map((b) => b.textContent?.trim())).toEqual([
      'Download header of /dev/sda3', 'Download header of /dev/sdb1',
    ])
    expect(document.querySelector('[data-testid="disk-headers"]')?.textContent).toContain('/dev/sdb1, generation 3: escrowed')
    wrapper.unmount()
  })
})
