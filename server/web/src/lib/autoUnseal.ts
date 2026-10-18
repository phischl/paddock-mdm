import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'

/** The automatic-unseal setting, the unsealer's report and OpenBao's seal status (ADR 0035). */
export type AutoUnsealStatus = components['schemas']['AutoUnsealStatus']

/** What the platform administrator acknowledges: the version of the disclaimer and the typed sentence. */
export interface AutoUnsealAcknowledgement {
  disclaimer_version: string
  acknowledgement: string
}

/** The setting; the problem code when it cannot be read. */
export async function getAutoUnseal(): Promise<AutoUnsealStatus | string> {
  const { data, error } = await api.GET('/api/platform/v1/openbao/auto-unseal')
  return data ?? problemCode(error)
}

/** Records the acknowledgement and enables the setting; the new status or the problem code. */
export async function enableAutoUnseal(input: AutoUnsealAcknowledgement): Promise<AutoUnsealStatus | string> {
  const { data, error } = await api.POST('/api/platform/v1/openbao/auto-unseal/enable', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: input,
  })
  return data ?? problemCode(error)
}

/** Disables the setting; the new status or the problem code. */
export async function disableAutoUnseal(): Promise<AutoUnsealStatus | string> {
  const { data, error } = await api.POST('/api/platform/v1/openbao/auto-unseal/disable', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
  })
  return data ?? problemCode(error)
}

/** Which alert the page shows (plan M8u decision 22): shares left on the host, or the host step still to do. */
export function autoUnsealAlert(s: AutoUnsealStatus): 'sharesLeft' | 'hostStep' | null {
  // Only a running unsealer's report counts: the host step removes the unsealer before it deletes the file, so a stale
  // `shares_present` would never clear (plan M8u decision 22, amended 2026-10-18).
  if (s.state === 'disabled' && s.unsealer.running && s.unsealer.shares_present) return 'sharesLeft'
  if (s.state === 'enabled' && (!s.unsealer.running || !s.unsealer.shares_present)) return 'hostStep'
  return null
}
