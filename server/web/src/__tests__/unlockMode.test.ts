import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DiskEncryption, LoginSettings } from '../api/client'
import DiskEncryptionCard from '../components/DiskEncryptionCard.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import LoginSettingsView from '../views/LoginSettings.vue'

const settings: LoginSettings = {
  hello_enabled: true, hello_pin_min_length: 6, user_lock_session_action: 'lock_screen', break_glass_accounts: [],
  sudoers_d_allowlist: [], sudo_lecture_text: 'Be careful.', local_admin_username: 'paddock-admin', local_admin_rotation_days: 30,
  rotate_after_reveal_hours: null, notice_text: '', boot_pin_min_length: 8, login_history_enabled: false, login_history_days: 90,
  disk_unlock_mode: 'tpm_pin', updated_at: '2026-10-18T09:00:00Z',
}
const saved: unknown[] = []
vi.mock('../lib/loginSettings', async (original) => ({
  ...(await original<typeof import('../lib/loginSettings')>()),
  getLoginSettings: () => Promise.resolve(settings),
  saveLoginSettings: (body: unknown) => {
    saved.push(body)
    return Promise.resolve({ ...settings, ...(body as object) })
  },
}))
let disk: DiskEncryption
vi.mock('../lib/disk', async (original) => ({
  ...(await original<typeof import('../lib/disk')>()),
  getDisk: () => Promise.resolve(disk),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  saved.length = 0
})

async function mountIn(component: object, props: Record<string, unknown> = {}): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system' } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)', component: { render: () => null } }] })
  await router.push('/x')
  wrapper = mount(() => h(VApp, null, { default: () => h(component, props) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

const el = (testid: string) => document.querySelector<HTMLElement>(`[data-testid="${testid}"]`)

describe('disk unlock mode (plan M8d decision 49)', () => {
  it('shows the TPM-only notice only for tpm_only and saves the mode', async () => {
    await mountIn(LoginSettingsView)
    expect(el('settings-unlock-mode')?.textContent).toContain('TPM + boot PIN: the disk asks for a PIN at every start')
    expect(el('settings-tpm-only-notice')).toBeNull()
    const tpmOnly = [...el('settings-unlock-mode')!.querySelectorAll('input')].find((i) => i.value === 'tpm_only')!
    tpmOnly.click()
    await flushPromises()
    expect(el('settings-tpm-only-notice')?.textContent).toContain('TPM only protects the data against a removed disk')
    const save = [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save')!
    save.click()
    await flushPromises()
    expect(saved[0]).toMatchObject({ disk_unlock_mode: 'tpm_only' })
  })

  it('shows the applied mode and, for a mismatch, the hint with the runbook link', async () => {
    disk = {
      state: 'unlock_mode_mismatch', tokens: ['recovery', 'tpm2+pin'], keyslots: 2, recovery_keys: [], headers: [], volumes: [],
      unresolved: [], unlock_mode: 'tpm_only',
    }
    await mountIn(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' })
    expect(el('disk-unlock-mode')?.textContent?.trim()).toBe('TPM only')
    expect(el('disk-state')?.textContent?.trim()).toBe('Unlock mode differs from the policy')
    const alert = el('disk-unlock-mode-mismatch')!
    expect(alert.textContent).toContain('enrolled for the other unlock mode')
    expect(alert.querySelector('a')?.getAttribute('href')).toContain('disk-recovery.md#changing-the-unlock-mode')
  })
})

describe('unencrypted devices (plan M8d decision 50)', () => {
  const base = { tokens: [], keyslots: 0, recovery_keys: [], headers: [], volumes: [], unresolved: [] }
  const texts = () => [...(el('disk-reinstall')?.querySelectorAll('p') ?? [])].map((p) => p.textContent?.trim())

  it('asks for a reinstall and names a separate /boot as a conversion candidate', async () => {
    disk = { ...base, state: 'not_encrypted', boot_separate: true }
    await mountIn(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' })
    expect(texts()).toEqual([
      'This device is not encrypted. Encrypt it by reinstalling it with the Paddock autoinstall after a backup; Paddock does not encrypt a running device in place.',
      'Its disk layout (separate /boot) qualifies for the in-place encryption planned for a later release.',
    ])
  })

  it('shows only the reinstall without a separate /boot', async () => {
    disk = { ...base, state: 'not_encrypted', boot_separate: false }
    await mountIn(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' })
    expect(texts()).toHaveLength(1)
    expect(el('disk-conversion-planned')).toBeNull()
  })

  it('asks for a reinstall of a device encrypted outside Paddock and says nothing for a compliant one', async () => {
    disk = { ...base, state: 'unmanaged' }
    await mountIn(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' })
    expect(el('disk-reinstall')?.textContent?.trim()).toBe('This device was encrypted outside Paddock: no recovery key or header is escrowed, and a Lock cannot be restored. Reinstall it with the Paddock autoinstall to manage its encryption.')
    wrapper?.unmount()
    disk = { ...base, state: 'compliant', tokens: ['recovery', 'tpm2+pin'], keyslots: 2 }
    await mountIn(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1' })
    expect(el('disk-reinstall')).toBeNull()
  })
})
