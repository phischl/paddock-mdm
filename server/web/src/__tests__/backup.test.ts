import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import BackupKeyDialog from '../components/BackupKeyDialog.vue'
import BackupTargetForm from '../components/BackupTargetForm.vue'
import PlatformBackup from '../views/PlatformBackup.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'
import {
  attemptsLeft, credentialsRequired, emptyTarget, hostStateStatus, inputOf, keyFileText, scheduleErrors, toBody, validateTarget,
  withoutSecrets, type BackupKey, type BackupOverview, type BackupTarget, type TargetInput,
} from '../lib/backup'

function target(over: Partial<BackupTarget> = {}): BackupTarget {
  return {
    id: 't1', name: 'NAS', type: 'smb', enabled: true, host_state: 'pending_host', host_revision: 1,
    settings: { smb: { host: 'nas.example.org', share: 'paddock', path: '', username: 'svc', domain: '', options: '' } },
    has_credentials: true, test_requested_at: null, last_test_at: null, last_test_ok: null, last_test_error: null,
    status: [], created_by: 'alice', created_at: '2026-11-04T10:00:00Z', updated_at: '2026-11-04T10:00:00Z', ...over,
  }
}

function overviewOf(over: Partial<BackupOverview> = {}): BackupOverview {
  return {
    key: { active: null, pending: null, retired: [] },
    schedule: {
      full_interval_hours: 24, openbao_interval_hours: 6, fleet_interval_hours: 24, escrow_interval_hours: 1, retention_full: 14,
      openbao_keep_days: 30, fleet_keep_days: 30, updated_by: null, updated_at: null,
    },
    targets: [], repo: { path: null, bytes_used: null, bytes_free: null, stanzas: [] }, last_runs: [], ...over,
  }
}

describe('backup rules', () => {
  it('reads the attempts left from the detail', () => {
    expect(attemptsLeft('the characters do not match; attempts_left=2')).toBe(2)
    expect(attemptsLeft('key discarded after three failed confirmations; generate a new key')).toBeNull()
  })

  it('asks for the password again only when the SMB destination changed', () => {
    const original = inputOf(target())
    expect(credentialsRequired(original, original)).toEqual({ password: false, keys: false })
    expect(credentialsRequired({ ...original, smb: { ...original.smb, path: 'sub' } }, original).password).toBe(false)
    for (const field of ['host', 'share', 'domain', 'username', 'options'] as const) {
      expect(credentialsRequired({ ...original, smb: { ...original.smb, [field]: 'x' } }, original).password).toBe(true)
    }
    expect(validateTarget({ ...original, smb: { ...original.smb, host: 'other' } }, original).smbPassword).toBe('backup.targets.passwordAgain')
    expect(validateTarget({ ...original, smb: { ...original.smb, host: 'other', password: 'pw' } }, original)).toEqual({})
  })

  it('asks for both S3 keys after a destination change and when only one is typed', () => {
    const s3 = target({
      type: 's3', settings: { s3: { endpoint: 'https://s3.example.org', bucket: 'b', region: '', prefix: '', ca_pem: '' } },
    })
    const original = inputOf(s3)
    expect(validateTarget(original, original)).toEqual({})
    expect(validateTarget({ ...original, s3: { ...original.s3, prefix: 'p' } }, original)).toEqual({})
    expect(validateTarget({ ...original, s3: { ...original.s3, bucket: 'c' } }, original).s3AccessKey).toBe('backup.targets.keysAgain')
    const one = validateTarget({ ...original, s3: { ...original.s3, accessKey: 'a' } }, original)
    expect(one.s3SecretKey).toBe('backup.targets.keysAgain')
    expect(one.s3AccessKey).toBeUndefined()
  })

  it('requires the credentials and the https endpoint on creation', () => {
    const s3: TargetInput = { ...emptyTarget(), type: 's3', name: 'S3', s3: { ...emptyTarget().s3, endpoint: 'http://x', bucket: 'b' } }
    const errors = validateTarget(s3, null)
    expect(errors.s3Endpoint).toBe('backup.targets.endpointInvalid')
    expect(errors.s3AccessKey).toBe('backup.targets.required')
    expect(validateTarget({ ...emptyTarget(), name: 'L', local: { path: '/srv/../x' } }, null).localPath).toBe('backup.targets.pathInvalid')
    expect(validateTarget({ ...emptyTarget(), name: 'L', local: { path: '/srv/backup' } }, null)).toEqual({})
  })

  it('sends only the group of the chosen type and a credential only when typed', () => {
    const smb: TargetInput = { ...inputOf(target()), smb: { ...inputOf(target()).smb, password: '' } }
    const body = toBody(smb)
    expect(Object.keys(body).sort()).toEqual(['enabled', 'name', 'smb', 'type'])
    expect(body.smb).not.toHaveProperty('password')
    expect(toBody({ ...smb, smb: { ...smb.smb, password: 'pw' } }).smb?.password).toBe('pw')
    expect(withoutSecrets({ ...smb, smb: { ...smb.smb, password: 'pw' } }).smb.password).toBe('')
  })

  it('checks the schedule ranges', () => {
    const ok = {
      full_interval_hours: 24, openbao_interval_hours: 6, fleet_interval_hours: 24, escrow_interval_hours: 1, retention_full: 14,
      openbao_keep_days: 30, fleet_keep_days: 30,
    }
    expect(scheduleErrors(ok)).toEqual([])
    expect(scheduleErrors({ ...ok, full_interval_hours: 5, retention_full: 1.5 })).toEqual(['full_interval_hours', 'retention_full'])
  })

  it('maps the host state to a chip and writes the key file with the fingerprint and the sentence', () => {
    expect(hostStateStatus('mounted').status).toBe('ok')
    expect(hostStateStatus('pending_host').status).toBe('info')
    expect(hostStateStatus('unreachable').status).toBe('critical')
    expect(keyFileText('KEY', 'abc', 'Keep it.')).toBe('KEY\n\nFingerprint: abc\n\nKeep it.\n')
  })
})

describe('BackupKeyDialog', () => {
  const key = { id: 'k1', text: 'AAAABBBBCCCC', fingerprint: 'f1', positions: [1, 3, 5, 7, 9, 11], downloadName: 'paddock-backup-key-k1.txt' }
  function mountDialog(props: Record<string, unknown> = {}) {
    return mount(BackupKeyDialog, {
      props: { step: 2, keyInfo: key, attemptsLeft: null, problem: '', pending: false, ...props },
      global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body,
    })
  }
  const body = () => document.body.textContent ?? ''

  it('shows the key with copy and download and offers no way out but the discard', async () => {
    const w = mountDialog()
    expect((document.querySelector('[data-testid="backup-key-text"] input') as HTMLInputElement).value).toBe('AAAABBBBCCCC')
    expect(document.querySelector('[data-testid="backup-key-copy"]')).not.toBeNull()
    expect(document.querySelector('[data-testid="backup-key-download"]')).not.toBeNull()
    expect(document.querySelector('[data-testid="backup-key-cancel"]')).toBeNull()
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(w.emitted('cancel')).toBeUndefined()
    ;(document.querySelector('[data-testid="backup-key-discard"]') as HTMLElement).click()
    expect(w.emitted('discard')).toHaveLength(1)
    w.unmount()
  })

  it('asks for the six characters at the named positions and sends them in order', async () => {
    const w = mountDialog({ step: 3 })
    const inputs = [...document.querySelectorAll<HTMLInputElement>('[data-testid^="backup-key-char-"]')]
    expect(inputs).toHaveLength(6)
    expect(body()).toContain('Position 11')
    expect(body()).not.toContain('AAAABBBBCCCC')
    const confirm = document.querySelector('[data-testid="backup-key-confirm"]') as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    'AbC+/=' .split('').forEach((c, i) => {
      inputs[i].value = c
      inputs[i].dispatchEvent(new Event('input'))
    })
    await flushPromises()
    expect(confirm.disabled).toBe(false)
    confirm.click()
    expect(w.emitted('confirm')?.[0]).toEqual(['AbC+/='])
    w.unmount()
  })

  it('shows the attempts left after a mismatch and clears the fields', async () => {
    const w = mountDialog({ step: 3 })
    const first = document.querySelector('[data-testid="backup-key-char-0"]') as HTMLInputElement
    first.value = 'x'
    first.dispatchEvent(new Event('input'))
    await w.setProps({ attemptsLeft: 2 })
    expect(document.querySelector('[data-testid="backup-key-attempts"]')?.textContent).toContain('2 attempts left')
    expect(first.value).toBe('')
    await w.setProps({ attemptsLeft: 1 })
    expect(document.querySelector('[data-testid="backup-key-attempts"]')?.textContent).toContain('1 attempt left')
    w.unmount()
  })

  it('allows leaving only before a key exists', async () => {
    const w = mountDialog({ step: 1, keyInfo: null })
    expect(body()).toContain('exactly once')
    ;(document.querySelector('[data-testid="backup-key-cancel"]') as HTMLElement).click()
    expect(w.emitted('cancel')).toHaveLength(1)
    ;(document.querySelector('[data-testid="backup-key-generate"]') as HTMLElement).click()
    expect(w.emitted('generate')).toHaveLength(1)
    w.unmount()
  })
})

describe('BackupTargetForm', () => {
  function mountForm(props: Record<string, unknown> = {}) {
    return mount(BackupTargetForm, { props, global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body })
  }

  it('keeps the password write-only and asks for it again after a host change', async () => {
    const w = mountForm({ initial: target() })
    const password = w.find('#backup-smb-password')
    expect((password.element as HTMLInputElement).value).toBe('')
    expect(password.attributes('placeholder')).toBe('unchanged')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toHaveLength(1)
    await w.find('#backup-smb-host').setValue('other.example.org')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toHaveLength(1)
    expect(w.text()).toContain('enter the password again')
    await password.setValue('pw')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toHaveLength(2)
    w.unmount()
  })

  it('shows the fields of the chosen type only', async () => {
    const w = mountForm()
    expect(w.find('#backup-local-path').exists()).toBe(true)
    await w.find('[data-testid="backup-target-type-s3"] input').setValue(true)
    expect(w.find('#backup-local-path').exists()).toBe(false)
    expect(w.find('#backup-s3-endpoint').exists()).toBe(true)
    expect(w.find('#backup-smb-host').exists()).toBe(false)
    w.unmount()
  })
})

const getOverview = vi.fn()
const generate = vi.fn()
const confirmK = vi.fn()
const discard = vi.fn()
const remove = vi.fn()
const create = vi.fn()
const update = vi.fn()
const fetchTarget = vi.fn()
const saveSched = vi.fn()
const toggle = vi.fn()
const runNow = vi.fn()
let targets: BackupTarget[] = []
vi.mock('../lib/backup', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/backup')>()
  return {
    ...original,
    loadOverview: () => getOverview(),
    generateKey: () => generate(),
    confirmKey: (...a: unknown[]) => confirmK(...a),
    discardKey: (...a: unknown[]) => discard(...a),
    deleteTarget: (...a: unknown[]) => remove(...a),
    createTarget: (...a: unknown[]) => create(...a),
    updateTarget: (...a: unknown[]) => update(...a),
    getTarget: (...a: unknown[]) => fetchTarget(...a),
    saveSchedule: (...a: unknown[]) => saveSched(...a),
    setTargetEnabled: (...a: unknown[]) => toggle(...a),
    requestRun: () => runNow(),
    targetLister: () => () => Promise.resolve({ items: targets, page: 1, page_size: 25, total: targets.length, total_capped: false, sort: 'name' }),
    runLister: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-started_at' }),
  }
})

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  localStorage.clear()
  for (const f of [getOverview, generate, confirmK, discard, remove, create, update, fetchTarget, saveSched, toggle, runNow, assign]) f.mockReset()
  getOverview.mockResolvedValue(overviewOf())
  targets = [target()]
  Object.defineProperty(window, 'location', { value: { ...window.location, assign, href: 'https://admin.test/platform/backup', search: '' }, writable: true })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(query = ''): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'u', username: 'u', display_name: 'U', role: 'platform_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/platform/backup', component: PlatformBackup }] })
  await router.push('/platform/backup' + query)
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

async function click(selector: string): Promise<void> {
  ;(document.querySelector(selector) as HTMLElement).click()
  await flushPromises()
}

describe('PlatformBackup', () => {
  it('lists the targets with the host state chip', async () => {
    await mountPage('?tab=targets')
    const list = document.querySelector('[data-testid="backup-target-list"]')
    expect(list?.textContent).toContain('NAS')
    expect(document.querySelector('[data-testid="backup-host-state-NAS"]')?.textContent).toContain('Waiting for the host')
  })

  it('states the host step with both commands after a local, SMB or NFS target was saved', async () => {
    create.mockResolvedValue(target({ name: 'Disk', type: 'local' }))
    await mountPage('?tab=targets')
    await click('[data-testid="create-backup-target"]')
    const set = (sel: string, v: string) => {
      const el = document.querySelector(sel) as HTMLInputElement
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    set('#backup-target-name', 'Disk')
    set('#backup-local-path', '/srv/backup')
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    const alert = document.querySelector('[data-testid="backup-host-step"]')?.textContent ?? ''
    expect(alert).toContain('./paddock backup-target apply')
    expect(alert).toContain('./paddock up')
  })

  it('does not show the host step after an S3 target', async () => {
    create.mockResolvedValue(target({ name: 'Cloud', type: 's3' }))
    await mountPage('?tab=targets')
    await click('[data-testid="create-backup-target"]')
    await click('[data-testid="backup-target-type-s3"] input')
    const set = (sel: string, v: string) => {
      const el = document.querySelector(sel) as HTMLInputElement
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    set('#backup-target-name', 'Cloud')
    set('#backup-s3-endpoint', 'https://s3.example.org')
    set('#backup-s3-bucket', 'b')
    set('#backup-s3-access-key', 'a')
    set('#backup-s3-secret-key', 's')
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(create).toHaveBeenCalledTimes(1)
    expect(document.querySelector('[data-testid="backup-host-step"]')).toBeNull()
  })

  it('deletes a target only after its name is typed', async () => {
    remove.mockResolvedValue(null)
    await mountPage('?tab=targets')
    await click('[aria-label="Delete NAS"]')
    expect(pendingConfirm.value?.options.requireTypedText).toBe('NAS')
    settleConfirm(false)
    await flushPromises()
    expect(remove).not.toHaveBeenCalled()
    await click('[aria-label="Delete NAS"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(remove).toHaveBeenCalledWith('t1')
  })

  const activeKey: BackupKey = { key_id: 'k0', fingerprint: 'fp', state: 'confirmed', created_at: '2026-11-04T10:00:00Z', created_by: 'a', confirmed_at: '2026-11-04T11:00:00Z', confirmed_by: 'a', retired_at: null, attempts: 0, legacy: false, positions: null }

  it('does not start a backup without a confirmed key', async () => {
    await mountPage()
    expect((document.querySelector('[data-testid="backup-run-now"]') as HTMLButtonElement).disabled).toBe(true)
  })

  it('asks for confirmation before it starts a backup with an active key', async () => {
    getOverview.mockResolvedValue(overviewOf({ key: { active: activeKey, pending: null, retired: [] } }))
    runNow.mockResolvedValue(null)
    await mountPage()
    await click('[data-testid="backup-run-now"]')
    expect(pendingConfirm.value?.options.title).toBe('Back up now')
    settleConfirm(false)
    await flushPromises()
    expect(runNow).not.toHaveBeenCalled()
    await click('[data-testid="backup-run-now"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(runNow).toHaveBeenCalledTimes(1)
  })

  it('disables a target only after a destructive confirmation', async () => {
    toggle.mockResolvedValue(target({ enabled: false }))
    await mountPage('?tab=targets')
    await click('[aria-label="Disable NAS"]')
    expect(pendingConfirm.value?.options.destructive).toBe(true)
    settleConfirm(false)
    await flushPromises()
    expect(toggle).not.toHaveBeenCalled()
    await click('[aria-label="Disable NAS"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(toggle).toHaveBeenCalledWith('t1', false)
  })

  it('saves a valid schedule and refuses an out-of-range one without a request', async () => {
    saveSched.mockResolvedValue({})
    await mountPage('?tab=schedule')
    const field = document.querySelector('#backup-schedule-full_interval_hours') as HTMLInputElement
    field.value = '5'
    field.dispatchEvent(new Event('input'))
    await flushPromises()
    await click('[data-testid="backup-schedule-save"]')
    expect(saveSched).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter a whole number from 6 to 168.')
    field.value = '12'
    field.dispatchEvent(new Event('input'))
    await flushPromises()
    await click('[data-testid="backup-schedule-save"]')
    expect(saveSched).toHaveBeenCalledWith(expect.objectContaining({ full_interval_hours: 12 }))
    expect(document.querySelector('[data-testid="backup-saved"]')?.textContent).toContain('The schedule was saved.')
  })

  it('shows the generated key once, never stores it and drops it after the confirmation', async () => {
    generate.mockResolvedValue({
      key_id: 'k1', key: 'SECRETKEYTEXT0123', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'paddock-backup-key-k1.txt',
    })
    confirmK.mockResolvedValue({ key_id: 'k1' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    expect((document.querySelector('[data-testid="backup-key-text"] input') as HTMLInputElement).value).toBe('SECRETKEYTEXT0123')
    await click('[data-testid="backup-key-next"]')
    expect(document.body.textContent).not.toContain('SECRETKEYTEXT0123')
    const inputs = [...document.querySelectorAll<HTMLInputElement>('[data-testid^="backup-key-char-"]')]
    'SECRET'.split('').forEach((c, i) => {
      inputs[i].value = c
      inputs[i].dispatchEvent(new Event('input'))
    })
    await flushPromises()
    await click('[data-testid="backup-key-confirm"]')
    expect(confirmK).toHaveBeenCalledWith('k1', 'SECRET')
    expect(document.querySelector('[data-testid="backup-key-dialog"]')).toBeNull()
    expect(document.body.textContent).not.toContain('SECRETKEYTEXT0123')
    for (const store of [sessionStorage, localStorage]) {
      expect(JSON.stringify({ ...store })).not.toContain('SECRET')
    }
    expect(assign).not.toHaveBeenCalled()
  })

  it('shows the attempts left after a mismatch and keeps the dialog open', async () => {
    generate.mockResolvedValue({ key_id: 'k1', key: 'KEY', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'x.txt' })
    confirmK.mockResolvedValue({ code: 'backup_key_mismatch', detail: 'the characters do not match; attempts_left=2' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    await click('[data-testid="backup-key-next"]')
    document.querySelectorAll<HTMLInputElement>('[data-testid^="backup-key-char-"]').forEach((el) => {
      el.value = 'x'
      el.dispatchEvent(new Event('input'))
    })
    await flushPromises()
    await click('[data-testid="backup-key-confirm"]')
    expect(document.querySelector('[data-testid="backup-key-attempts"]')?.textContent).toContain('2 attempts left')
  })

  it('discards the key only after a destructive confirmation and drops it', async () => {
    generate.mockResolvedValue({ key_id: 'k1', key: 'KEYTEXTXX', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'x.txt' })
    discard.mockResolvedValue({ key_id: 'k1' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    await click('[data-testid="backup-key-discard"]')
    expect(pendingConfirm.value?.options.destructive).toBe(true)
    settleConfirm(false)
    await flushPromises()
    expect(discard).not.toHaveBeenCalled()
    expect((document.querySelector('[data-testid="backup-key-text"] input') as HTMLInputElement).value).toBe('KEYTEXTXX')
    await click('[data-testid="backup-key-discard"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(discard).toHaveBeenCalledWith('k1')
    expect(document.querySelector('[data-testid="backup-key-dialog"]')).toBeNull()
    expect(document.body.textContent).not.toContain('KEYTEXTXX')
  })

  it('shows only the fingerprint of the active key and offers confirmation of a pending one without its text', async () => {
    const base = { created_at: '2026-11-04T10:00:00Z', created_by: 'a', confirmed_at: null, confirmed_by: null, retired_at: null, attempts: 0, legacy: false }
    getOverview.mockResolvedValue(overviewOf({
      key: {
        active: { ...base, key_id: 'k0', fingerprint: 'activefp', state: 'confirmed', confirmed_at: '2026-11-04T11:00:00Z', confirmed_by: 'a', positions: null },
        pending: { ...base, key_id: 'k1', fingerprint: 'pendingfp', state: 'unconfirmed', positions: [2, 4, 6, 8, 10, 12] },
        retired: [],
      },
    }))
    await mountPage('?tab=key')
    expect(document.querySelector('[data-testid="backup-key-fingerprint"]')?.textContent).toBe('activefp')
    await click('[data-testid="backup-key-open-confirm"]')
    expect(document.body.textContent).toContain('Position 12')
    expect(document.querySelector('[data-testid="backup-key-text"]')).toBeNull()
  })

  it('starts the step-up when the key generation is refused and repeats it on return', async () => {
    generate.mockResolvedValueOnce({ code: 'step_up_required' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    expect(assign).toHaveBeenCalledTimes(1)
    expect(JSON.parse(sessionStorage.getItem('paddock.stepup') ?? '{}').payload).toEqual({ op: 'generate' })
  })

  async function typeSix(): Promise<void> {
    document.querySelectorAll<HTMLInputElement>('[data-testid^="backup-key-char-"]').forEach((el) => {
      el.value = 'x'
      el.dispatchEvent(new Event('input'))
    })
    await flushPromises()
    await click('[data-testid="backup-key-confirm"]')
  }

  it('stores only the operation when the key confirmation needs a step-up and reopens step 3 on return', async () => {
    generate.mockResolvedValue({ key_id: 'k1', key: 'KEYTEXTXX', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'x.txt' })
    confirmK.mockResolvedValue({ code: 'step_up_required' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    await click('[data-testid="backup-key-next"]')
    await typeSix()
    expect(assign).toHaveBeenCalledTimes(1)
    const raw = sessionStorage.getItem('paddock.stepup') ?? ''
    expect(JSON.parse(raw).payload).toEqual({ op: 'resume-confirm' })
    expect(raw).not.toContain('KEYTEXTXX')
    expect(raw).not.toContain('"x')
    wrapper?.unmount()
    wrapper = null

    const pendingKey: BackupKey = { key_id: 'k1', fingerprint: 'f1', state: 'unconfirmed', created_at: '2026-11-04T10:00:00Z', created_by: 'a', confirmed_at: null, confirmed_by: null, retired_at: null, attempts: 0, legacy: false, positions: [1, 2, 3, 4, 5, 6] }
    getOverview.mockResolvedValue(overviewOf({ key: { active: null, pending: pendingKey, retired: [] } }))
    await mountPage('?tab=key')
    await vi.waitFor(() => expect(document.querySelector('[data-testid^="backup-key-char-"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="backup-key-text"]')).toBeNull()
    expect(sessionStorage.getItem('paddock.stepup')).toBeNull()
  })

  it('drops the key and shows the discarded problem after the third mismatch', async () => {
    generate.mockResolvedValue({ key_id: 'k1', key: 'KEYTEXTXX', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'x.txt' })
    confirmK.mockResolvedValue({ code: 'backup_key_mismatch', detail: 'key discarded after three failed confirmations; generate a new key' })
    await mountPage('?tab=key')
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    await click('[data-testid="backup-key-next"]')
    await typeSix()
    expect(document.querySelector('[data-testid="backup-key-dialog"]')).toBeNull()
    expect(document.querySelector('[data-testid="backup-page-problem"]')?.textContent).toContain('discarded after three wrong confirmations')
    expect(document.body.textContent).not.toContain('KEYTEXTXX')
  })

  function typeInto(selector: string, value: string): void {
    const el = document.querySelector(selector) as HTMLInputElement
    el.value = value
    el.dispatchEvent(new Event('input'))
  }
  const stepUpPayload = (): { op: string; hadSecrets: boolean; id?: string; input: TargetInput } =>
    JSON.parse(sessionStorage.getItem('paddock.stepup') ?? '{}').payload

  it('keeps an SMB password out of the storage during a step-up and asks for it again on return', async () => {
    create.mockResolvedValue({ code: 'step_up_required' })
    await mountPage('?tab=targets')
    await click('[data-testid="create-backup-target"]')
    await click('[data-testid="backup-target-type-smb"] input')
    typeInto('#backup-target-name', 'Share')
    typeInto('#backup-smb-host', 'nas.example.org')
    typeInto('#backup-smb-share', 'paddock')
    typeInto('#backup-smb-username', 'svc')
    typeInto('#backup-smb-password', 'TOPSECRETPW')
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(assign).toHaveBeenCalledTimes(1)
    expect(sessionStorage.getItem('paddock.stepup')).not.toContain('TOPSECRETPW')
    expect(stepUpPayload().op).toBe('create')
    expect(stepUpPayload().hadSecrets).toBe(true)
    wrapper?.unmount()
    wrapper = null

    create.mockReset()
    await mountPage('?tab=targets')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="backup-reenter-credentials"]')).not.toBeNull())
    expect(create).not.toHaveBeenCalled()
    expect((document.querySelector('#backup-smb-password') as HTMLInputElement).value).toBe('')
    expect((document.querySelector('#backup-smb-host') as HTMLInputElement).value).toBe('nas.example.org')
  })

  it('keeps S3 keys out of the storage during a step-up', async () => {
    create.mockResolvedValue({ code: 'step_up_required' })
    await mountPage('?tab=targets')
    await click('[data-testid="create-backup-target"]')
    await click('[data-testid="backup-target-type-s3"] input')
    typeInto('#backup-target-name', 'Cloud')
    typeInto('#backup-s3-endpoint', 'https://s3.example.org')
    typeInto('#backup-s3-bucket', 'b')
    typeInto('#backup-s3-access-key', 'AKIAEXAMPLE')
    typeInto('#backup-s3-secret-key', 'S3SECRETVALUE')
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    const raw = sessionStorage.getItem('paddock.stepup') ?? ''
    expect(raw).not.toContain('AKIAEXAMPLE')
    expect(raw).not.toContain('S3SECRETVALUE')
    expect(stepUpPayload().hadSecrets).toBe(true)
  })

  it('reopens an interrupted update of the existing target and asks for the credentials again', async () => {
    const input = withoutSecrets({ ...inputOf(target()), smb: { ...inputOf(target()).smb, host: 'other.example.org', password: '' } })
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'backup', target: 'backup', payload: { op: 'update', id: 't1', input, hadSecrets: true }, at: Date.now() }))
    fetchTarget.mockResolvedValue(target())
    await mountPage('?tab=targets')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="backup-reenter-credentials"]')).not.toBeNull())
    expect(update).not.toHaveBeenCalled()
    expect((document.querySelector('#backup-smb-host') as HTMLInputElement).value).toBe('other.example.org')
    expect((document.querySelector('#backup-smb-password') as HTMLInputElement).value).toBe('')
    expect((document.querySelector('[data-testid="backup-target-type-local"] input') as HTMLInputElement).disabled).toBe(true)
  })

  it('shows the problem instead of a create form when the target of an interrupted update cannot be read', async () => {
    const input = withoutSecrets({ ...inputOf(target()), smb: { ...inputOf(target()).smb, host: 'other.example.org', password: '' } })
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'backup', target: 'backup', payload: { op: 'update', id: 't1', input, hadSecrets: true }, at: Date.now() }))
    fetchTarget.mockResolvedValue({ code: 'not_found' })
    await mountPage('?tab=targets')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="backup-page-problem"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="backup-page-problem"]')).not.toBeNull()
    expect(document.querySelector('form')).toBeNull()
    expect(create).not.toHaveBeenCalled()
  })

  it('reloads the retired keys after the page state is refreshed', async () => {
    await mountPage('?tab=key')
    expect(document.querySelector('[data-testid="backup-retired-list"]')?.textContent).not.toContain('retiredfp')
    const retired: BackupKey = { ...activeKey, key_id: 'k9', fingerprint: 'retiredfp', state: 'retired', retired_at: '2026-11-04T12:00:00Z' }
    getOverview.mockResolvedValue(overviewOf({ key: { active: activeKey, pending: null, retired: [retired] } }))
    generate.mockResolvedValue({ key_id: 'k1', key: 'KEYTEXTXX', fingerprint: 'f1', positions: [1, 2, 3, 4, 5, 6], download_name: 'x.txt' })
    discard.mockResolvedValue({ key_id: 'k1' })
    await click('[data-testid="backup-key-start"]')
    await click('[data-testid="backup-key-generate"]')
    await click('[data-testid="backup-key-discard"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(document.querySelector('[data-testid="backup-retired-list"]')?.textContent).toContain('retiredfp')
  })

  it('runs no window dialogs', async () => {
    const spies = [vi.spyOn(window, 'confirm'), vi.spyOn(window, 'alert'), vi.spyOn(window, 'prompt')]
    remove.mockResolvedValue(null)
    await mountPage('?tab=targets')
    await click('[aria-label="Delete NAS"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    for (const s of spies) expect(s).not.toHaveBeenCalled()
  })
})
