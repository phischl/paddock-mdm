import { api, problemCode, type DiskEncryption, type DiskEscrow, type DiskRecoveryKey, type DiskState, type DiskVolume } from '../api/client'
import type { ListFilter } from './listQuery'

/** The disk encryption states (plan M4b decision 8), from the least to the most complete. */
export const diskStates: DiskState[] = ['not_encrypted', 'unmanaged', 'tpm_missing', 'tpm_pin_missing', 'escrow_pending', 'compliant']

/** The disk state filter of the device list (plan M4b decision 14). */
export const diskStateFilter: ListFilter = {
  kind: 'enum', key: 'disk_state', label: 'devices.disk.state',
  options: diskStates.map((value) => ({ value, title: 'devices.disk.states.' + value })),
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
