import {
  api, problemCode, type DeviceDiskConversion, type DiskEncryption, type DiskEscrow, type DiskRecoveryKey, type DiskState, type DiskVolume,
} from '../api/client'
import type { ListFilter } from './listQuery'

/** The disk encryption states (plan M4b decision 8), from the least to the most complete. */
export const diskStates: DiskState[] = [
  'not_encrypted', 'encrypting', 'unmanaged', 'tpm_missing', 'tpm_pin_missing', 'unlock_mode_mismatch', 'escrow_pending', 'compliant',
]

/** The runbook section on converting a disk to the other unlock mode with the recovery key. */
export const unlockModeRunbook =
  'https://github.com/phischl/paddock-mdm/blob/main/docs/operations/disk-recovery.md#changing-the-unlock-mode'

/** The short label of a disk state (the mismatch's state text is a full hint, plan M8d decision 49). */
export function diskStateLabel(state: DiskState): string {
  return state === 'unlock_mode_mismatch' ? 'devices.disk.unlockModeMismatch' : 'devices.disk.states.' + state
}

/** The disk state filter of the device list (plan M4b decision 14). */
export const diskStateFilter: ListFilter = {
  kind: 'enum', key: 'disk_state', label: 'devices.disk.state',
  options: diskStates.map((value) => ({ value, title: diskStateLabel(value) })),
}

/** The disk encryption of a device; the problem code on failure. */
export async function getDisk(id: string): Promise<DiskEncryption | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}/disk', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Reveals the newest recovery key (step-up and typed hostname); the key or the problem code. */
export async function revealRecoveryKey(id: string, hostname: string): Promise<DiskRecoveryKey | string> {
  const { data, error } = await api.POST('/api/v1/devices/{id}/disk/recovery-key', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body: { confirm_hostname: hostname },
  })
  return data ?? problemCode(error)
}

/** A downloaded header backup. */
export interface HeaderFile {
  blob: Blob
  filename: string
}

/**
 * Downloads the newest stored header of a volume (its LUKS UUID; null: the root volume) with step-up and typed
 * hostname (PDK-009 decision 5); the file or the problem code.
 */
export async function downloadHeader(id: string, hostname: string, volume: string | null = null): Promise<HeaderFile | string> {
  const body = volume ? { confirm_hostname: hostname, volume } : { confirm_hostname: hostname }
  const { data, error, response } = await api.POST('/api/v1/devices/{id}/disk/header', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body, parseAs: 'blob',
  })
  if (error || !data) return problemCode(error)
  return { blob: data as Blob, filename: headerFileName(response.headers.get('Content-Disposition'), hostname) }
}

/** The file name of a Content-Disposition header, or "<hostname>-luks-header.img". */
export function headerFileName(disposition: string | null, hostname: string): string {
  const match = /filename="?([^";]+)"?/.exec(disposition ?? '')
  return match?.[1] ?? hostname + '-luks-header.img'
}

/** Hands a blob to the browser as a download. */
export function saveFile(file: HeaderFile): void {
  const url = URL.createObjectURL(file.blob)
  const a = document.createElement('a')
  a.href = url
  a.download = file.filename
  a.click()
  URL.revokeObjectURL(url)
}

/** The newest stored generation of a list of escrows (newest first), or null. */
export function latestStored(escrows: DiskEscrow[]): DiskEscrow | null {
  return escrows.find((e) => e.status === 'stored') ?? null
}

/**
 * The header generations of a volume (newest first): those with its UUID and, for the root volume, those without a
 * volume (escrowed before PDK-009).
 */
export function volumeHeaders(headers: DiskEscrow[], v: DiskVolume): DiskEscrow[] {
  return headers.filter((h) => (h.volume !== undefined && h.volume === v.uuid) || (v.root && h.volume === undefined))
}

/** The device a header belongs to, by its volume; the root volume's for a header without a volume. */
export function headerDevice(h: DiskEscrow, volumes: DiskVolume[]): string {
  const v = h.volume === undefined ? volumes.find((x) => x.root) : volumes.find((x) => x.uuid === h.volume)
  return v?.device ?? h.volume ?? ''
}

/** The runbook of the in-place encryption (plan M8e decision 25). */
export const conversionRunbook = 'https://github.com/phischl/paddock-mdm/blob/main/docs/operations/in-place-encryption.md'

/** The phases in which a conversion is open (plan M8e decision 10). */
const openPhases = ['requested', 'prepared', 'encrypting']

/** Whether the conversion is requested, prepared or encrypting. */
export function conversionOpen(c: DeviceDiskConversion | null | undefined): c is DeviceDiskConversion {
  return !!c && openPhases.includes(c.phase)
}

/**
 * Whether a cancellation of the conversion is on its way (plan M8e decision 8): an abort was issued, the device has not
 * refused it, and the command did not fail, expire or get cancelled (then the server allows a new cancel, as its
 * abortOnItsWay does).
 */
export function abortOpen(c: DeviceDiskConversion): boolean {
  return !!c.abort_command_id && !c.abort_refused_reason && !['failed', 'expired', 'cancelled'].includes(c.abort_command_status ?? '')
}

/** Whether the conversion can still be cancelled: requested or prepared, and no abort on its way. */
export function conversionCancellable(c: DeviceDiskConversion | null | undefined): c is DeviceDiskConversion {
  return !!c && (c.phase === 'requested' || c.phase === 'prepared') && !abortOpen(c)
}

/**
 * The warning of the Lock and Destroy dialogues while an in-place encryption is active (plan M8e §14.5 decision 39):
 * unencrypted for a requested or prepared conversion of a device that does not report the disk encrypting, encrypting
 * otherwise; null when no conversion is active.
 */
export function conversionWarning(c: DeviceDiskConversion | null | undefined, state: DiskState | null | undefined): 'unencrypted' | 'encrypting' | null {
  if (!c?.active) return null
  return (c.phase === 'requested' || c.phase === 'prepared') && state !== 'encrypting' ? 'unencrypted' : 'encrypting'
}

/** The disk throughput the duration estimate assumes (plan M8e decision 24): 150 MB/s. */
const conversionBytesPerSecond = 150e6

/** The estimated duration of the background encryption in seconds, rounded up to 10 minutes; null without a disk size. */
export function conversionEstimate(diskTotalBytes: number | null | undefined): number | null {
  if (!diskTotalBytes) return null
  const seconds = Math.ceil(diskTotalBytes / conversionBytesPerSecond)
  return Math.max(1, Math.ceil(seconds / 600)) * 600
}

/** Formats a duration in hours and minutes in the locale (e.g. "2 hours 10 minutes"); at least one minute. */
export function formatDuration(seconds: number, locale: string): string {
  const total = Math.max(1, Math.round(seconds / 60))
  const hours = Math.floor(total / 60)
  const minutes = total % 60
  const unit = (u: 'hour' | 'minute', n: number) => new Intl.NumberFormat(locale, { style: 'unit', unit: u, unitDisplay: 'long' }).format(n)
  return [hours > 0 ? unit('hour', hours) : '', minutes > 0 ? unit('minute', minutes) : ''].filter(Boolean).join(' ')
}

/** The share of the data encrypted in whole percent; 0 without a size. */
export function conversionPercent(c: Pick<DeviceDiskConversion, 'done_bytes' | 'data_bytes'>): number {
  if (!c.data_bytes) return 0
  return Math.min(100, Math.floor(((c.done_bytes ?? 0) / c.data_bytes) * 100))
}

/** Requests the in-place encryption of a device (step-up, typed hostname, backup acknowledgement); null or the problem code. */
export async function requestEncrypt(id: string, hostname: string, reason: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/devices/{id}/encrypt', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { confirm_hostname: hostname, reason, backup_confirmed: true },
  })
  return error ? problemCode(error) : null
}

/** Cancels the in-place encryption of a device (step-up, typed hostname); null or the problem code. */
export async function cancelEncrypt(id: string, hostname: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/devices/{id}/encrypt/cancel', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body: { confirm_hostname: hostname },
  })
  return error ? problemCode(error) : null
}

/** When the abort command of a cancel after delivery was issued (for devices.disk.convert.cancelSent); null if unknown. */
export async function abortIssuedAt(id: string, commandId: string): Promise<string | null> {
  const { data } = await api.GET('/api/v1/devices/{id}/commands', {
    params: { path: { id }, query: { type: ['encrypt_disk_abort'], sort: '-issued_at', page: 1, page_size: 10 } },
  })
  return data?.items.find((c) => c.id === commandId)?.issued_at ?? null
}
