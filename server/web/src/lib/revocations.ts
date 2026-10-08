import {
  api, listPage, problemCode, type DMSSettings, type DMSSettingsUpdate, type RevocationAction, type RevocationRequest,
  type RevocationRequestSort, type RevocationStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

/** What an administrator can request on a device (plan M4c decision 18). */
export type RevokeAction = Extract<RevocationAction, 'lock' | 'destroy'>

/** What an administrator can do with an open request. */
export type ReviewVerb = 'approve' | 'reject' | 'cancel'

export const revocationActions: RevocationAction[] = ['lock', 'destroy', 'self_lock']
export const revocationStatuses: RevocationStatus[] = [
  'requested', 'approved', 'issued', 'delivered', 'confirmed', 'failed', 'rejected', 'cancelled', 'expired',
]

/** The filters of the revocation request list. */
export const revocationFilters: ListFilter[] = [
  { kind: 'enum', key: 'status', label: 'revocations.status', options: revocationStatuses.map((value) => ({ value, title: 'revocations.statuses.' + value })) },
  { kind: 'enum', key: 'action', label: 'revocations.action', options: revocationActions.map((value) => ({ value, title: 'revocations.actions.' + value })) },
]

/** One page of revocation requests for DataList; deviceID limits it to one device. */
export function listRevocations(deviceID?: string): (p: ListParams) => Promise<Page<RevocationRequest>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/revocation-requests', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as RevocationRequestSort, q: p.q,
            status: p.status as RevocationStatus[], action: p.action as RevocationAction[], device_id: deviceID,
          },
        },
      }),
    )
}

/** Requests a Lock or Destroy (step-up and typed hostname); the request or the problem code. */
export async function requestRevocation(id: string, action: RevokeAction, hostname: string, reason: string): Promise<RevocationRequest | string> {
  const init = { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' as const } }, body: { confirm_hostname: hostname, reason } }
  const { data, error } = action === 'lock'
    ? await api.POST('/api/v1/devices/{id}/lock', init)
    : await api.POST('/api/v1/devices/{id}/destroy', init)
  return data ?? problemCode(error)
}

/** Approves, rejects or cancels an open request (step-up and typed hostname); null on success, otherwise the problem code. */
export async function reviewRevocation(id: string, verb: ReviewVerb, hostname: string): Promise<string | null> {
  const init = { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' as const } }, body: { confirm_hostname: hostname } }
  let res
  switch (verb) {
    case 'approve':
      res = await api.POST('/api/v1/revocation-requests/{id}/approve', init)
      break
    case 'reject':
      res = await api.POST('/api/v1/revocation-requests/{id}/reject', init)
      break
    default:
      res = await api.POST('/api/v1/revocation-requests/{id}/cancel', init)
  }
  return res.error ? problemCode(res.error) : null
}

/**
 * The verbs the signed-in administrator may run on a request: a Destroy waiting for its second administrator is
 * approved or rejected by another administrator and cancelled by its requester (plan M4c decision 5).
 */
export function reviewVerbs(r: RevocationRequest, adminID: string | undefined): ReviewVerb[] {
  if (r.status !== 'requested' || !adminID) return []
  return r.requested_by === adminID ? ['cancel'] : ['approve', 'reject']
}

/** A step of a request's timeline. */
export interface TimelineStep {
  step: 'requested' | 'approved' | 'issued' | 'delivered' | 'confirmed' | 'finished'
  at: string
}

/** The steps a request went through, oldest first (the revocation status timeline of the device page). */
export function timeline(r: RevocationRequest): TimelineStep[] {
  const steps: TimelineStep[] = [{ step: 'requested', at: r.requested_at }]
  const optional: [TimelineStep['step'], string | undefined][] = [
    ['approved', r.approved_at], ['issued', r.issued_at], ['delivered', r.delivered_at], ['confirmed', r.confirmed_at],
  ]
  for (const [step, at] of optional) if (at) steps.push({ step, at })
  // finished_at closes a request that ended otherwise (failed, rejected, cancelled, expired).
  if (r.finished_at && !r.confirmed_at) steps.push({ step: 'finished', at: r.finished_at })
  return steps
}

/** The erasure of one LUKS volume in a device's confirmation (plan M4c.1 decision 2). */
export interface VolumeResult {
  device: string
  slots_before: number
  slots_after: number
  erased: boolean
}

/** A volume a Lock left alone because its header escrow was not confirmed (PDK-009); uuid is absent when unknown. */
export interface SkippedVolume {
  device: string
  uuid?: string
}

/**
 * The per-volume results of a request's confirmation, the crypttab entries the device could not erase with
 * certainty and the volumes a Lock skipped; incomplete when an entry is unresolved or a volume was not erased (plan
 * M4c.1, review round 1). Skipped volumes do not make a Lock incomplete: they stay readable.
 */
export interface VolumeResults {
  volumes: VolumeResult[]
  unresolved: string[]
  skipped: SkippedVolume[]
  incomplete: boolean
}

/** Reads the per-volume results from a request's confirmation; both lists are empty for confirmations before M4c.1. */
export function volumeResults(r: RevocationRequest): VolumeResults {
  const raw = Array.isArray(r.result?.volumes) ? r.result.volumes as unknown[] : []
  const rawUnresolved = Array.isArray(r.result?.unresolved) ? r.result.unresolved as unknown[] : []
  const rawSkipped = Array.isArray(r.result?.skipped_not_escrowed) ? r.result.skipped_not_escrowed as unknown[] : []
  const volumes = raw.filter(isVolumeResult)
  const unresolved = rawUnresolved.filter((s): s is string => typeof s === 'string')
  const skipped = rawSkipped.filter(isSkippedVolume)
  return { volumes, unresolved, skipped, incomplete: unresolved.length > 0 || volumes.some((v) => !v.erased) }
}

function isSkippedVolume(v: unknown): v is SkippedVolume {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  return typeof o.device === 'string' && (o.uuid === undefined || typeof o.uuid === 'string')
}

function isVolumeResult(v: unknown): v is VolumeResult {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  return typeof o.device === 'string' && typeof o.slots_before === 'number' && typeof o.slots_after === 'number'
    && typeof o.erased === 'boolean'
}

/** The dead man's switch settings; the problem code on failure. */
export async function getDMS(): Promise<DMSSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/dms')
  return data ?? problemCode(error)
}

/** Replaces the dead man's switch settings; the saved settings or the problem code. */
export async function saveDMS(s: DMSSettingsUpdate): Promise<DMSSettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/dms', { params: { header: { 'X-Paddock-CSRF': '1' } }, body: s })
  return data ?? problemCode(error)
}

/** The bounds of the dead man's switch period (plan M4c decision 15): the server refuses below 7 days. */
export const dmsMinPeriod = 7
export const dmsMaxPeriod = 365
/** Below this period the portal warns: Himmelblau's cached logins may outlast shorter offline windows. */
export const dmsWarnBelow = 30

/** Parses warning lead times ("3, 1"); null when one is not a whole number. */
export function parseWarnDays(text: string): number[] | null {
  const parts = text.split(',').map((p) => p.trim()).filter((p) => p !== '')
  if (!parts.every((p) => /^\d+$/.test(p))) return null
  return parts.map(Number)
}
