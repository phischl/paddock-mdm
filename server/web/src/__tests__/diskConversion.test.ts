import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceDiskConversion, DiskConversionHealth, DiskEncryption } from '../api/client'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import DangerZone from '../components/DangerZone.vue'
import DiskEncryptionCard from '../components/DiskEncryptionCard.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { conversionEstimate, conversionWarning, diskStateFilter, formatDuration } from '../lib/disk'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const at = '2026-10-21T10:00:00Z'
let disk: DiskEncryption
const encrypted: unknown[] = []
const cancelled: unknown[] = []
const started: string[] = []
let resumeFor: string | null = null
let afterCancel: DeviceDiskConversion | null = null
let refuseCancel: string | null = null

vi.mock('../lib/disk', async (original) => ({
  ...(await original<typeof import('../lib/disk')>()),
  getDisk: () => Promise.resolve(disk),
  requestEncrypt: (...args: unknown[]) => {
    encrypted.push(args)
    return Promise.resolve(null)
  },
  cancelEncrypt: (...args: unknown[]) => {
    cancelled.push(args)
    if (refuseCancel) return Promise.resolve(refuseCancel)
    if (afterCancel) disk = { ...disk, disk_conversion: afterCancel }
    return Promise.resolve(null)
  },
  abortIssuedAt: () => Promise.resolve(at),
}))
vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  listRevocations: () => () => Promise.resolve({ items: [], page: 1, page_size: 10, total: 0, total_capped: false, sort: '-requested_at' }),
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string) => started.push(action),
  resumeStepUp: (action: string) => (resumeFor === action ? { payload: null, failed: false } : null),
  withoutStepUpParam: () => '/devices/d1',
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  encrypted.length = 0
  cancelled.length = 0
  started.length = 0
  resumeFor = null
  afterCancel = null
  refuseCancel = null
})

const base = { tokens: [], keyslots: 0, recovery_keys: [], headers: [], volumes: [], unresolved: [] }
const eligible: DiskConversionHealth = { eligible: true, layout: 'lvm', release: '24.04', initramfs: 'dracut' }

function row(phase: DeviceDiskConversion['phase'], extra: Partial<DeviceDiskConversion> = {}): DeviceDiskConversion {
  return {
    id: 'c1', phase, requested_at: at, reason: 'policy', command_id: 'k1', command_status: 'pending', layout: 'lvm', luks_uuid: null,
    data_bytes: null, done_bytes: null, eta_s: null, paused_reason: null, progress_at: null, failure_stage: null, failure_reason: null,
    finished_at: null, abort_command_id: null, abort_command_status: null, abort_refused_reason: null,
    active: phase === 'requested' || phase === 'prepared' || phase === 'encrypting', ...extra,
  }
}

/** Mounts a component with the portal's single confirmation host, as App.vue does. */
async function mountWith(component: object, props: Record<string, unknown>, role = 'org_admin'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', theme: 'system', organization: null, revocation_enabled: true,
  } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
  await router.push('/devices/d1')
  wrapper = mount(() => h(VApp, null, {
    default: () => [
      h(component, props),
      pendingConfirm.value
        ? h(ConfirmDialog, {
          key: pendingConfirm.value.id, modelValue: true, ...pendingConfirm.value.options,
          onConfirm: (a: { reason: string }) => settleConfirm(a), onCancel: () => settleConfirm(false),
        })
        : null,
    ],
  }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

const mountCard = (props: Record<string, unknown> = {}, role = 'org_admin') =>
  mountWith(DiskEncryptionCard, { deviceId: 'd1', hostname: 'lt-1', active: true, diskTotalBytes: null, ...props }, role)

const el = (testid: string) => document.querySelector<HTMLElement>(`[data-testid="${testid}"]`)
const text = (testid: string) => el(testid)?.textContent?.replace(/\s+/g, ' ').trim()
const button = (name: string) => [...document.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === name)
const dialogLines = () => [...(el('encrypt-checks')?.querySelectorAll('li') ?? [])].map((l) => l.textContent?.trim())

async function type(testid: string, value: string): Promise<void> {
  const input = el(testid)!.querySelector<HTMLInputElement | HTMLTextAreaElement>('input, textarea')!
  input.value = value
  input.dispatchEvent(new Event('input'))
  await flushPromises()
}

describe('in-place encryption: eligibility (plan M8e decision 24)', () => {
  it('shows the eligible panel and, for an administrator of an active device, the button that starts the step-up', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: null }
    await mountCard()
    expect(text('disk-convert-eligible')).toContain('Its disk layout allows encrypting it in place')
    expect(el('disk-reinstall')).toBeNull()
    button('Encrypt this device…')!.click()
    await flushPromises()
    expect(started).toEqual(['disk-convert'])
  })

  it.each(['org_operator', 'org_auditor'])('offers no button to %s', async (role) => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: null }
    await mountCard({}, role)
    expect(text('disk-convert-eligible')).toContain('Its disk layout allows encrypting it in place')
    expect(button('Encrypt this device…')).toBeUndefined()
  })

  it('offers no button for a device that is not active', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: null }
    await mountCard({ active: false })
    expect(button('Encrypt this device…')).toBeUndefined()
  })

  it('lists the reasons under the reinstall alert when the layout is not eligible', async () => {
    disk = {
      ...base, state: 'not_encrypted', disk_conversion: null,
      conversion: { eligible: false, reasons: ['no_separate_boot', 'root_not_ext4', 'cleanup_pending'] },
    }
    await mountCard()
    expect(text('disk-reinstall')).toContain('its agent reports no disk layout that can be encrypted in place. Encrypt it by reinstalling it')
    expect(text('disk-reinstall')).toContain('In-place encryption is not possible on this device:')
    expect([...el('disk-convert-reasons')!.querySelectorAll('li')].map((l) => l.textContent?.trim())).toEqual([
      '/boot is not on its own partition',
      'the root file system is not ext4',
      'the device is still removing an abandoned encryption from its boot files; try again after its next check-in',
    ])
    expect(el('disk-convert-eligible')).toBeNull()
    expect(button('Encrypt this device…')).toBeUndefined()
  })

  it('names the reasons added by PDK-244 and shows an unknown reason as reported', async () => {
    disk = {
      ...base, state: 'not_encrypted', disk_conversion: null,
      conversion: { eligible: false, reasons: ['hibernation_configured', 'lvm_devicesfile', 'lvm_filter', 'lvm_unknown', 'other_luks_present', 'some_future_reason'] },
    }
    await mountCard()
    expect([...el('disk-convert-reasons')!.querySelectorAll('li')].map((l) => l.textContent?.trim())).toEqual([
      'hibernation is set up on the device',
      'LVM uses a devices file on this device, which in-place encryption does not support yet',
      'LVM uses a custom device filter on this device, which in-place encryption does not support yet',
      'the LVM configuration of the device could not be read',
      'another encrypted volume exists on the device',
      'some_future_reason',
    ])
  })
})

describe('in-place encryption: the dialogue (plan M8e decision 24, §14.4 decision 34)', () => {
  it('keeps the confirm button disabled until the backup is acknowledged, the reason given and the hostname typed', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: null, unlock_mode: 'tpm_pin' }
    resumeFor = 'disk-convert'
    await mountCard({ diskTotalBytes: 500e9 })
    expect(el('encrypt-dialog')?.textContent).toContain('Encrypt lt-1 in place')
    expect(dialogLines()).toEqual([
      'The user must restart the device once. Until then nothing is encrypted. The restart takes a few minutes longer than usual.',
      'A laptop must be on mains power at that restart; the background encryption pauses on battery.',
      'At the restart the device asks the user for a boot PIN on a text console (unlock mode: TPM + boot PIN). The PIN never reaches Paddock.',
      'The background encryption takes about 1 hour on this disk; the device stays usable meanwhile.',
    ])
    const accept = button('Encrypt at the next restart')!
    await type('encrypt-reason', 'policy')
    await type('encrypt-typed', 'lt-1')
    expect(accept.disabled).toBe(true)
    el('encrypt-backup')!.querySelector('input')!.click()
    await flushPromises()
    expect(accept.disabled).toBe(false)
    await type('encrypt-typed', 'lt-2')
    expect(accept.disabled).toBe(true)
    await type('encrypt-typed', 'lt-1')
    accept.click()
    await flushPromises()
    expect(encrypted).toEqual([['d1', 'lt-1', 'policy']])
    expect(text('disk-convert-notice')).toBe('Encryption requested.')
  })

  it('names the TPM-only unlock, the unknown duration and the packages the switch to dracut removes', async () => {
    disk = {
      ...base, state: 'not_encrypted', unlock_mode: 'tpm_only', disk_conversion: null,
      conversion: { ...eligible, initramfs: 'initramfs-tools', initramfs_removes: ['brltty', 'initramfs-tools'] },
    }
    resumeFor = 'disk-convert'
    await mountCard()
    const lines = dialogLines()
    expect(lines[2]).toBe('The device unlocks with its TPM without a PIN (unlock mode: TPM only).')
    expect(lines[3]).toBe('The background encryption takes minutes to hours depending on the disk size; the device stays usable meanwhile.')
    expect(lines[4]).toContain('this removes the packages brltty, initramfs-tools — initramfs-tools itself and, where listed, brltty')
  })

  it('falls back to the unknown removal set and says nothing of the switch under dracut', async () => {
    disk = { ...base, state: 'not_encrypted', disk_conversion: null, conversion: { ...eligible, initramfs: 'initramfs-tools', initramfs_removes: [] } }
    resumeFor = 'disk-convert'
    await mountCard()
    expect(dialogLines()[4]).toContain('it could not report which packages leave with initramfs-tools')
    wrapper?.unmount()
    disk = { ...base, state: 'not_encrypted', disk_conversion: null, conversion: eligible }
    resumeFor = 'disk-convert'
    await mountCard()
    expect(dialogLines()).toHaveLength(4)
  })
})

describe('in-place encryption: progress and cancel (plan M8e decisions 8 and 25)', () => {
  it('shows a requested conversion with its command status and the cancel button for administrators', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: row('requested') }
    await mountCard()
    expect(text('disk-convert-phase')).toBe('Encryption requested — Pending. The device prepares itself at its next check-in.')
    expect(el('disk-convert-eligible')).toBeNull()
    expect(button('Encrypt this device…')).toBeUndefined()
    button('Cancel encryption')!.click()
    await flushPromises()
    expect(started).toEqual(['disk-convert-cancel'])
    wrapper?.unmount()
    await mountCard({}, 'org_operator')
    expect(button('Cancel encryption')).toBeUndefined()
  })

  it('cancels after the step-up and the typed hostname', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: row('requested') }
    afterCancel = row('cancelled', { finished_at: at, command_status: 'cancelled' })
    resumeFor = 'disk-convert-cancel'
    await mountCard()
    const dialog = el('confirm-dialog')!
    expect(dialog.textContent).toContain('Cancel the encryption of lt-1')
    expect(dialog.textContent).toContain('Possible until the device restarts.')
    const accept = [...dialog.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Cancel encryption')!
    expect(accept.disabled).toBe(true)
    await type('confirm-typed', 'lt-1')
    accept.click()
    await flushPromises()
    expect(cancelled).toEqual([['d1', 'lt-1']])
    expect(text('disk-convert-notice')).toBe('Encryption cancelled.')
    expect(text('disk-convert-phase')).toContain('Encryption cancelled on')
    expect(text('disk-convert-phase')).toContain('the disk is unchanged')
  })

  it('shows a prepared conversion and, once an abort is sent, the sent state without a button', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: { ...eligible, phase: 'prepared', updated_at: at }, disk_conversion: row('prepared') }
    await mountCard()
    expect(text('disk-convert-phase')).toMatch(/^Prepared since .+: the recovery key is stored\. Waiting for the user to restart the device\.$/)
    expect(button('Cancel encryption')).not.toBeUndefined()
    wrapper?.unmount()
    disk = { ...disk, disk_conversion: row('prepared', { abort_command_id: 'k2', abort_command_status: 'pending' }) }
    await mountCard()
    expect(text('disk-convert-cancel-sent')).toMatch(/^Cancellation sent .+; the device confirms it at its next check-in/)
    expect(button('Cancel encryption')).toBeUndefined()
  })

  it.each(['failed', 'expired', 'cancelled'])('offers the cancel again when the abort command is %s', async (status) => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: row('prepared', { abort_command_id: 'k2', abort_command_status: status }) }
    await mountCard()
    expect(el('disk-convert-cancel-sent')).toBeNull()
    expect(button('Cancel encryption')).not.toBeUndefined()
  })

  it('shows the refusal with its reason and offers no cancel while encrypting', async () => {
    disk = {
      ...base, state: 'encrypting', disk_conversion: row('encrypting', {
        abort_command_id: 'k2', abort_command_status: 'failed', abort_refused_reason: 'not_abortable',
        data_bytes: 200e9, done_bytes: 100e9, eta_s: 5400, progress_at: at,
      }),
    }
    await mountCard()
    expect(text('disk-convert-cancel-refused')).toBe('The device refused the cancellation: it had already restarted and started the encryption.')
    expect(el('disk-convert-cancel-sent')).toBeNull()
    expect(button('Cancel encryption')).toBeUndefined()
    expect(text('disk-convert-phase')).toBe('Encrypting in the background: 50 % of 200.0 GB')
    expect(el('disk-convert-progress')?.getAttribute('aria-valuenow')).toBe('50')
    expect(text('disk-convert-progress-text')).toMatch(/^about 1 hour 30 minutes left · last report /)
  })

  it('shows the catalog text when the server refuses a cancel of a started encryption', async () => {
    disk = { ...base, state: 'not_encrypted', conversion: eligible, disk_conversion: row('prepared') }
    resumeFor = 'disk-convert-cancel'
    refuseCancel = 'conversion_not_cancellable'
    await mountCard()
    await type('confirm-typed', 'lt-1')
    ;[...el('confirm-dialog')!.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Cancel encryption')!.click()
    await flushPromises()
    expect(document.querySelector('[role="alert"]')?.textContent?.trim()).toBe('The device already started the encryption; it cannot be cancelled.')
  })

  it('shows the pause reason instead of the ETA', async () => {
    disk = { ...base, state: 'encrypting', disk_conversion: row('encrypting', { data_bytes: 100, done_bytes: 10, eta_s: 60, paused_reason: 'on_battery' }) }
    await mountCard()
    expect(text('disk-convert-progress-text')).toBe('paused: the device runs on battery')
  })

  it('shows a completed conversion until the disk is compliant', async () => {
    disk = { ...base, state: 'escrow_pending', disk_conversion: row('completed', { finished_at: at, active: false }) }
    await mountCard()
    expect(text('disk-convert-phase')).toMatch(/^Encryption completed on .+; the recovery key and the TPM unlock are being set up\.$/)
    wrapper?.unmount()
    disk = { ...disk, state: 'compliant' }
    await mountCard()
    expect(el('disk-conversion')).toBeNull()
  })

  it('shows a failure with the stage, the reason verbatim, the runbook and the button again', async () => {
    disk = {
      ...base, state: 'not_encrypted', conversion: eligible,
      disk_conversion: row('failed', { failure_stage: 'init', failure_reason: 'on_battery', active: false }),
    }
    await mountCard()
    const alert = el('disk-convert-failed')!
    expect(alert.textContent).toContain('The encryption failed at stage "restart (the device boots unencrypted; see the runbook when it does not boot)": on_battery. See the runbook.')
    expect(alert.querySelector('a')?.getAttribute('href')).toContain('docs/operations/in-place-encryption.md')
    expect(button('Encrypt this device…')).not.toBeUndefined()
  })
})

describe('in-place encryption: waits and stuck boot files (plan M8e amendment 2026-10-21, items 17 to 19)', () => {
  it('shows the wait for a package run with its start while the device prepares', async () => {
    disk = { ...base, state: 'not_encrypted', disk_conversion: row('requested', { paused_reason: 'packages_busy', paused_since: at }) }
    await mountCard()
    expect(text('disk-convert-wait')).toMatch(/^Waiting since .+: a software installation or update is running on the device\. The preparation continues on its own once it has finished\.$/)
    expect(el('disk-convert-initrd-issue')).toBeNull()
    expect(el('disk-convert-cleanup')).toBeNull()
  })

  it('shows no wait once the device is prepared', async () => {
    disk = { ...base, state: 'not_encrypted', disk_conversion: row('prepared') }
    await mountCard()
    expect(el('disk-convert-wait')).toBeNull()
  })

  it('shows the room missing in /boot in MiB, the need rounded up and the free room down', async () => {
    disk = {
      ...base, state: 'not_encrypted',
      disk_conversion: row('requested', { initrd_issue: 'boot_space_low', boot_space_needed: 90 * 2 ** 20 - 1, boot_space_free: 89 * 2 ** 20 + 1 }),
    }
    await mountCard()
    expect(text('disk-convert-initrd-issue')).toBe('The boot partition (/boot) has too little free space to rebuild the boot files: 90 MiB needed, 89 MiB free. Free space there, for example by removing old kernels; the device retries on its own.')
  })

  it('names the kernel of an issue and shows an unknown issue as reported', async () => {
    disk = { ...base, state: 'tpm_pin_missing', disk_conversion: row('completed', { initrd_issue: 'kernel_not_buildable', initrd_issue_kernel: '6.8.0-45-generic', finished_at: at }) }
    await mountCard()
    expect(text('disk-convert-initrd-issue')).toBe('The boot files of kernel 6.8.0-45-generic cannot be rebuilt because its module list is missing. The step waits; reinstall or remove that kernel.')
    wrapper?.unmount()
    disk = { ...disk, disk_conversion: row('completed', { initrd_issue: 'newer_issue', finished_at: at }) }
    await mountCard()
    expect(text('disk-convert-initrd-issue')).toBe('newer_issue')
  })

  it('shows why a cleanup after a cancel is still pending, with the runbook', async () => {
    disk = {
      ...base, state: 'not_encrypted',
      disk_conversion: row('cancelled', { finished_at: at, cleanup_error: 'dracut: no space left on device', initrd_issue: 'key_material_hardlinked', active: false }),
    }
    await mountCard()
    const alert = el('disk-convert-cleanup')!
    expect(alert.textContent).toContain('The device has not yet removed the abandoned encryption from its boot files and retries at its next check-in. Last attempt: dracut: no space left on device.')
    expect(alert.querySelector('a')?.getAttribute('href')).toContain('docs/operations/in-place-encryption.md')
    expect(text('disk-convert-initrd-issue')).toBe('A file holding the encryption key has further hard links on the device. The cleanup cannot finish; see the runbook.')
  })
})

describe('in-place encryption: the conversion key on /boot (plan M8e §14.6 decision 52)', () => {
  it.each([
    ['encrypting', true, true],
    ['completed', true, true],
    ['completed', false, false],
    ['failed', true, false],
  ] as const)('phase %s with key_on_boot %s shows the alert: %s', async (phase, keyOnBoot, shown) => {
    disk = {
      ...base, state: 'encrypting', conversion: { eligible: false, key_on_boot: keyOnBoot },
      disk_conversion: row(phase, { failure_stage: 'resume', failure_reason: 'x' }),
    }
    await mountCard()
    if (shown) expect(text('disk-convert-key-on-boot')).toContain('The disk is encrypted but not protected at rest yet')
    else expect(el('disk-convert-key-on-boot')).toBeNull()
  })

  it('names the completion, the restart and the PIN or TPM setup (plan M8e amendment 2026-10-22, item 22)', async () => {
    disk = { ...base, state: 'encrypting', conversion: { eligible: false, key_on_boot: true }, disk_conversion: row('completed') }
    await mountCard()
    expect(text('disk-convert-key-on-boot')).toBe('The disk is encrypted but not protected at rest yet: the key that unlocks it ' +
      'lies on the unencrypted boot partition until the background encryption has completed, the device has been ' +
      'restarted and the boot PIN or TPM unlock has been set up. The device asks for the restart and, under TPM + PIN, ' +
      'for the PIN at every start.')
  })
})

describe('in-place encryption: the deferred enrollment (plan M8e amendment 2026-10-22, item 22)', () => {
  it.each([
    ['reencrypt', true],
    [undefined, false],
  ] as const)('enrollment_deferred %s shows the line in the progress panel: %s', async (deferred, shown) => {
    disk = {
      ...base, state: 'encrypting',
      conversion: { eligible: false, key_on_boot: true, ...(deferred ? { enrollment_deferred: deferred } : {}) },
      disk_conversion: row('encrypting', { data_bytes: 200e9, done_bytes: 100e9, eta_s: 5400, progress_at: at }),
    }
    await mountCard()
    if (shown) {
      expect(text('disk-convert-enrollment-deferred')).toBe('The boot PIN or the TPM unlock is set up at the first start after ' +
        'the background encryption has completed; it cannot be added while the encryption is unfinished.')
      expect(el('disk-conversion')?.contains(el('disk-convert-enrollment-deferred'))).toBe(true)
    } else {
      expect(el('disk-convert-enrollment-deferred')).toBeNull()
    }
  })
})

describe('in-place encryption in the danger zone (plan M8e §14.5 decisions 36 and 39)', () => {
  const zone = (props: Record<string, unknown>) => mountWith(DangerZone, {
    deviceId: 'd1', hostname: 'lt-1', revocable: true, presumedSelfLockedAt: null, retirable: false, uninstallable: true,
    uninstall: null, diskTpm: false, ...props,
  })

  it('refuses the removal with a disabled confirm button while a conversion is active', async () => {
    resumeFor = 'uninstall'
    await zone({ diskConversion: row('prepared'), diskState: 'not_encrypted' })
    expect(text('uninstall-conversion-open')).toContain('Paddock cannot be removed while this device is being encrypted in place')
    await type('uninstall-reason', 'returned')
    await type('uninstall-typed', 'lt-1')
    expect((el('uninstall-accept') as HTMLButtonElement).disabled).toBe(true)
  })

  it('allows the removal when no conversion is active', async () => {
    resumeFor = 'uninstall'
    await zone({ diskConversion: row('cancelled', { active: false }), diskState: 'not_encrypted' })
    expect(el('uninstall-conversion-open')).toBeNull()
    await type('uninstall-reason', 'returned')
    await type('uninstall-typed', 'lt-1')
    expect((el('uninstall-accept') as HTMLButtonElement).disabled).toBe(false)
  })

  it.each([
    ['revocation-lock', row('prepared'), 'not_encrypted', 'This device is not encrypted yet; it refuses a Lock or Destroy'],
    ['revocation-destroy', row('requested'), 'not_encrypted', 'This device is not encrypted yet; it refuses a Lock or Destroy'],
    ['revocation-lock', row('encrypting'), 'encrypting', 'The in-place encryption is unfinished'],
    ['revocation-destroy', row('failed', { active: true }), 'encrypting', 'The in-place encryption is unfinished'],
  ] as const)('%s warns for a %s conversion', async (action, conversion, state, warning) => {
    resumeFor = action
    await zone({ diskConversion: conversion, diskState: state })
    expect(text('confirm-warning')).toContain(warning)
  })

  it('shows no warning in the Lock dialogue when no conversion is active', async () => {
    resumeFor = 'revocation-lock'
    await zone({ diskConversion: row('completed', { active: false }), diskState: 'compliant' })
    expect(el('confirm-dialog')).not.toBeNull()
    expect(el('confirm-warning')).toBeNull()
  })
})

describe('in-place encryption helpers', () => {
  it('offers encrypting in the disk state filter', () => {
    expect(diskStateFilter.kind === 'enum' && diskStateFilter.options.map((o) => o.value)).toContain('encrypting')
  })

  it('estimates the duration at 150 MB/s rounded up to 10 minutes and formats it per locale', () => {
    expect(conversionEstimate(null)).toBeNull()
    expect(conversionEstimate(0)).toBeNull()
    expect(conversionEstimate(1e9)).toBe(600)
    expect(conversionEstimate(500e9)).toBe(3600)
    expect(formatDuration(3600 + 1800, 'en')).toBe('1 hour 30 minutes')
    expect(formatDuration(7200, 'de')).toBe('2 Stunden')
  })

  it('picks the Lock and Destroy warning by phase and disk state', () => {
    expect(conversionWarning(null, 'not_encrypted')).toBeNull()
    expect(conversionWarning(row('requested'), 'encrypting')).toBe('encrypting')
    expect(conversionWarning(row('completed', { active: true }), 'escrow_pending')).toBe('encrypting')
  })
})
