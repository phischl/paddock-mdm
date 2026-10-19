import { api, problemCode, type DeviceUninstall, type DeviceUninstallRequest } from '../api/client'

/** The modes of an uninstall (plan M8d decision 35). */
export type UninstallMode = DeviceUninstallRequest['mode']
export const uninstallModes: UninstallMode[] = ['leave', 'reset']

/** The answer of the uninstall dialog. */
export interface UninstallAnswer {
  mode: UninstallMode
  clearTpm: boolean
  keepLocalAdmin: boolean
  reason: string
}

/** Statuses of the uninstall command while the request can still be cancelled (plan M8d decision 38). */
const cancellable = ['pending', 'failed', 'expired']

/** Whether an uninstall is requested and not reported yet. */
export function uninstallPending(u: DeviceUninstall | null | undefined): u is DeviceUninstall {
  return !!u && !u.uninstalled_at
}

/** Whether a pending uninstall can be cancelled: its command has not reached the device, or its removal report is overdue. */
export function uninstallCancellable(u: DeviceUninstall | null | undefined): boolean {
  return uninstallPending(u) && (cancellable.includes(u.command_status) || u.report_overdue)
}

/** Whether a disk report lists a TPM keyslot on any volume: then the TPM cannot be cleared. */
export function diskUsesTpm(disk: { tokens: string[]; volumes: { tokens?: string[] }[] } | null): boolean {
  if (!disk) return false
  const tpm = (tokens: string[] | undefined) => (tokens ?? []).some((k) => k === 'tpm2' || k === 'tpm2+pin')
  return tpm(disk.tokens) || disk.volumes.some((v) => tpm(v.tokens))
}

/** Requests the removal of Paddock from a device (step-up, typed hostname); null on success, else the problem code. */
export async function requestUninstall(id: string, hostname: string, answer: UninstallAnswer): Promise<string | null> {
  const reset = answer.mode === 'reset'
  const body: DeviceUninstallRequest = {
    mode: answer.mode, confirm_hostname: hostname, reason: answer.reason,
    clear_tpm: reset && answer.clearTpm, keep_local_admin: reset && answer.keepLocalAdmin,
  }
  const { error } = await api.POST('/api/v1/devices/{id}/uninstall', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body,
  })
  return error ? problemCode(error) : null
}

/** Cancels a pending uninstall; null on success, else the problem code. */
export async function cancelUninstall(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/devices/{id}/uninstall/cancel', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}
