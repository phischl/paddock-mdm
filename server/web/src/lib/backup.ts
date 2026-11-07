import { api, listPage, problemCode } from '../api/client'
import type { components } from '../api/schema'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { Status, StatusView } from './status'

export type BackupTarget = components['schemas']['BackupTarget']
export type BackupTargetType = components['schemas']['BackupTargetType']
export type BackupTargetHostState = components['schemas']['BackupTargetHostState']
export type BackupKind = components['schemas']['BackupKind']
export type BackupKey = components['schemas']['BackupKey']
export type BackupKeyStatus = components['schemas']['BackupKeyStatus']
export type BackupKeyGenerated = components['schemas']['BackupKeyGenerated']
export type BackupOverview = components['schemas']['BackupOverview']
export type BackupSchedule = components['schemas']['BackupSchedule']
export type BackupScheduleUpdate = components['schemas']['BackupScheduleUpdate']
export type BackupRun = components['schemas']['BackupRun']
export type BackupRestorePlan = components['schemas']['BackupRestorePlan']
export type BackupRestorePlanInput = components['schemas']['BackupRestorePlanInput']
export type BackupRestorePlanState = components['schemas']['BackupRestorePlanState']
export type RestoreComponent = BackupRestorePlanInput['components'][number]
type TargetBody = components['schemas']['BackupTargetInput']
type TargetSort = components['parameters']['BackupTargetSort']
type RunSort = components['parameters']['BackupRunSort']
type PlanSort = components['parameters']['BackupRestorePlanSort']

/** The answer of an operation: the problem code with the server's detail when it sent one. */
export interface BackupProblem {
  code: string
  detail?: string
}

export const backupKinds: BackupKind[] = ['postgres', 'authentik', 'openbao', 'fleet', 'escrow']
export const targetTypes: BackupTargetType[] = ['local', 'smb', 'nfs', 's3']
export const namePattern = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/
/** The number of characters the key confirmation asks for (plan M15 decision 7). */
export const challengeLength = 6
/** The step-up actions of the page; the target is fixed because the backup settings are a singleton. */
export const stepUpTarget = 'backup'
/** How long and how often the portal waits for the result of a connection test (plan M15 decision 13). */
export const testPollIntervalMs = 3000
export const testPollTimeoutMs = 60_000

const csrf = { 'X-Paddock-CSRF': '1' } as const

function problemOf(error: unknown): BackupProblem {
  const detail = error && typeof error === 'object' && 'detail' in error && typeof error.detail === 'string' ? error.detail : undefined
  return { code: problemCode(error), detail }
}

export function isProblem(v: unknown): v is BackupProblem {
  return typeof v === 'object' && v !== null && 'code' in v && typeof (v as { code: unknown }).code === 'string'
}

/** The attempts a failed key confirmation leaves, read from the server's detail; null when the key was discarded. */
export function attemptsLeft(detail: string | undefined): number | null {
  const match = /attempts_left=(\d+)/.exec(detail ?? '')
  return match ? Number(match[1]) : null
}

/** The text of the key file: the key, its fingerprint and the sentence that says it is the only copy. */
export function keyFileText(key: string, fingerprint: string, sentence: string): string {
  return `${key}\n\nFingerprint: ${fingerprint}\n\n${sentence}\n`
}

/** The six characters of the key at the 1-based positions, as a reader would copy them from the shown key. */
export function answerOf(chars: readonly string[]): string {
  return chars.join('')
}

export const targetFilters: ListFilter[] = [
  { kind: 'enum', key: 'type', label: 'backup.targets.type', options: targetTypes.map((value) => ({ value, title: 'backup.targets.types.' + value })) },
  {
    kind: 'enum', key: 'enabled', label: 'backup.targets.enabled',
    options: [{ value: 'true', title: 'backup.on' }, { value: 'false', title: 'backup.off' }],
  },
  {
    kind: 'enum', key: 'host_state', label: 'backup.targets.hostState',
    options: (['pending_host', 'mounted', 'unreachable', 'n/a'] as const).map((value) => ({ value, title: 'backup.hostStates.' + value })),
  },
]

export const runFilters: ListFilter[] = [
  { kind: 'enum', key: 'kind', label: 'backup.runs.kind', options: backupKinds.map((value) => ({ value, title: 'backup.kinds.' + value })) },
  {
    kind: 'enum', key: 'outcome', label: 'backup.runs.outcome',
    options: [{ value: 'succeeded', title: 'backup.outcomes.succeeded' }, { value: 'failed', title: 'backup.outcomes.failed' }],
  },
]

/** The chip of a target's host state: a mounted share is ok, the host step still open is info, a failing mount critical. */
export function hostStateStatus(state: BackupTargetHostState): StatusView {
  const status: Record<BackupTargetHostState, Status> = { 'n/a': 'neutral', pending_host: 'info', mounted: 'ok', unreachable: 'critical' }
  return { status: status[state], label: 'backup.hostStates.' + state }
}

/** The chip of a target's last connection test. */
export function testStatus(t: BackupTarget): StatusView {
  if (t.test_requested_at) return { status: 'info', label: 'backup.tests.waiting' }
  if (t.last_test_ok === null) return { status: 'neutral', label: 'backup.tests.never' }
  return t.last_test_ok ? { status: 'ok', label: 'backup.tests.ok' } : { status: 'critical', label: 'backup.tests.failed' }
}

/** The chip of one target and kind in the overview grid. */
export function kindStatus(t: BackupTarget, kind: BackupKind): StatusView {
  const s = t.status.find((x) => x.kind === kind)
  if (s?.last_error) return { status: 'critical', label: 'backup.kindStates.failed' }
  if (s?.last_success_at) return { status: 'ok', label: 'backup.kindStates.ok' }
  return { status: 'neutral', label: 'backup.kindStates.never' }
}

/** The chip of the key state banner. */
export function keyStatus(key: BackupKeyStatus): StatusView {
  if (key.pending) return { status: 'warn', label: 'backup.key.statePending' }
  if (key.active) return { status: 'ok', label: 'backup.key.stateActive' }
  return { status: 'critical', label: 'backup.key.stateNone' }
}

/** Whether a target needs the backup host step (mount or bind) after saving. */
export function needsHostStep(type: BackupTargetType): boolean {
  return type !== 's3'
}

/** What the target form edits; secrets and the CA bundle behave write-only (empty unless typed). */
export interface TargetInput {
  name: string
  type: BackupTargetType
  enabled: boolean
  local: { path: string }
  smb: { host: string; share: string; path: string; username: string; password: string; domain: string; options: string }
  nfs: { host: string; export: string; path: string; options: string }
  s3: { endpoint: string; bucket: string; region: string; prefix: string; accessKey: string; secretKey: string; caPem: string }
}

export function emptyTarget(): TargetInput {
  return {
    name: '', type: 'local', enabled: true,
    local: { path: '' },
    smb: { host: '', share: '', path: '', username: '', password: '', domain: '', options: '' },
    nfs: { host: '', export: '', path: '', options: '' },
    s3: { endpoint: '', bucket: '', region: '', prefix: '', accessKey: '', secretKey: '', caPem: '' },
  }
}

/** A copy of the input that shares nothing with it (a reactive form cannot be structuredClone'd). */
export function cloneTarget(i: TargetInput): TargetInput {
  return { ...i, local: { ...i.local }, smb: { ...i.smb }, nfs: { ...i.nfs }, s3: { ...i.s3 } }
}

/** The form of a stored target; the credentials stay empty (they are never returned). */
export function inputOf(t: BackupTarget): TargetInput {
  const e = emptyTarget()
  e.name = t.name
  e.type = t.type
  e.enabled = t.enabled
  const s = t.settings
  if (s.local) e.local = { path: s.local.path }
  if (s.smb) e.smb = { ...e.smb, host: s.smb.host, share: s.smb.share, path: s.smb.path, username: s.smb.username, domain: s.smb.domain, options: s.smb.options }
  if (s.nfs) e.nfs = { host: s.nfs.host, export: s.nfs.export, path: s.nfs.path, options: s.nfs.options }
  if (s.s3) e.s3 = { ...e.s3, endpoint: s.s3.endpoint, bucket: s.s3.bucket, region: s.s3.region, prefix: s.s3.prefix, caPem: s.s3.ca_pem }
  return e
}

/** The destination fields whose change makes the server ask for the credentials again (PDK-731 amendment 2026-11-04). */
const smbDestination = ['host', 'share', 'domain', 'username', 'options'] as const
const s3Destination = ['endpoint', 'bucket', 'region', 'caPem'] as const

/** Which credentials the form has to ask for: everything on creation, otherwise only after a destination change. */
export function credentialsRequired(input: TargetInput, original: TargetInput | null): { password: boolean; keys: boolean } {
  if (original === null) return { password: input.type === 'smb', keys: input.type === 's3' }
  return {
    password: input.type === 'smb' && smbDestination.some((f) => input.smb[f] !== original.smb[f]),
    keys: input.type === 's3' && s3Destination.some((f) => input.s3[f] !== original.s3[f]),
  }
}

export type TargetField =
  | 'name' | 'localPath' | 'smbHost' | 'smbShare' | 'smbUsername' | 'smbPassword' | 'nfsHost' | 'nfsExport'
  | 's3Endpoint' | 's3Bucket' | 's3AccessKey' | 's3SecretKey'
export type TargetErrors = Partial<Record<TargetField, string>>

const controlChars = /[\u0000-\u001f\u007f-\u009f]/
function hasControl(p: string): boolean {
  return controlChars.test(p)
}

/** A relative subpath of the host's local backup root: no empty, '.' or '..' element (plan M15 decision 36). */
function validLocalSubpath(p: string): boolean {
  return p !== '' && new TextEncoder().encode(p).length <= 256 && !p.includes('\\') && !hasControl(p) && p.split('/').every((el) => el !== '' && el !== '.' && el !== '..')
}

/** Validates like the server's first line of defense (plan M15 §6.1); returns message keys by field. */
export function validateTarget(input: TargetInput, original: TargetInput | null): TargetErrors {
  const errors: TargetErrors = {}
  const need = credentialsRequired(input, original)
  if (!namePattern.test(input.name)) errors.name = 'backup.targets.nameInvalid'
  switch (input.type) {
    case 'local':
      if (!validLocalSubpath(input.local.path)) errors.localPath = 'backup.targets.pathInvalid'
      break
    case 'smb':
      if (input.smb.host.trim() === '') errors.smbHost = 'backup.targets.required'
      if (input.smb.share.trim() === '') errors.smbShare = 'backup.targets.required'
      if (input.smb.username.trim() === '') errors.smbUsername = 'backup.targets.required'
      if (need.password && input.smb.password === '') errors.smbPassword = original === null ? 'backup.targets.required' : 'backup.targets.passwordAgain'
      else if (/[\s,]/.test(input.smb.password)) errors.smbPassword = 'backup.targets.passwordChars'
      break
    case 'nfs':
      if (input.nfs.host.trim() === '') errors.nfsHost = 'backup.targets.required'
      if (!input.nfs.export.startsWith('/')) errors.nfsExport = 'backup.targets.exportInvalid'
      break
    case 's3': {
      if (!input.s3.endpoint.startsWith('https://')) errors.s3Endpoint = 'backup.targets.endpointInvalid'
      if (input.s3.bucket.trim() === '') errors.s3Bucket = 'backup.targets.required'
      const typed = input.s3.accessKey !== '' || input.s3.secretKey !== ''
      if (need.keys || typed) {
        const missing = original === null ? 'backup.targets.required' : 'backup.targets.keysAgain'
        if (input.s3.accessKey === '') errors.s3AccessKey = missing
        if (input.s3.secretKey === '') errors.s3SecretKey = missing
      }
      break
    }
  }
  return errors
}

/** The field a server problem belongs to, from the field name in its detail; null when it names none. */
export function fieldOfProblem(p: BackupProblem): TargetField | null {
  const d = p.detail ?? ''
  const table: [RegExp, TargetField][] = [
    [/smb\.password/, 'smbPassword'], [/s3\.(access_key|secret_key)/, 's3AccessKey'], [/smb\.host/, 'smbHost'],
    [/smb\.share/, 'smbShare'], [/smb\.username/, 'smbUsername'], [/nfs\.host/, 'nfsHost'], [/nfs\.export/, 'nfsExport'],
    [/s3\.endpoint/, 's3Endpoint'], [/s3\.bucket/, 's3Bucket'], [/local\.path/, 'localPath'], [/\bname\b/, 'name'],
  ]
  if (p.code === 'already_exists') return 'name'
  if (p.code !== 'invalid_request') return null
  return table.find(([re]) => re.test(d))?.[1] ?? null
}

/** The request body: only the object of the chosen type; a credential only when typed. */
export function toBody(i: TargetInput): TargetBody {
  const base = { name: i.name.trim(), type: i.type, enabled: i.enabled }
  switch (i.type) {
    case 'local':
      return { ...base, local: { path: i.local.path.trim() } }
    case 'smb':
      return {
        ...base,
        smb: {
          host: i.smb.host.trim(), share: i.smb.share.trim(), username: i.smb.username.trim(),
          ...(i.smb.path.trim() !== '' ? { path: i.smb.path.trim() } : {}),
          ...(i.smb.domain.trim() !== '' ? { domain: i.smb.domain.trim() } : {}),
          ...(i.smb.options.trim() !== '' ? { options: i.smb.options.trim() } : {}),
          ...(i.smb.password !== '' ? { password: i.smb.password } : {}),
        },
      }
    case 'nfs':
      return {
        ...base,
        nfs: {
          host: i.nfs.host.trim(), export: i.nfs.export.trim(),
          ...(i.nfs.path.trim() !== '' ? { path: i.nfs.path.trim() } : {}),
          ...(i.nfs.options.trim() !== '' ? { options: i.nfs.options.trim() } : {}),
        },
      }
    case 's3':
      return {
        ...base,
        s3: {
          endpoint: i.s3.endpoint.trim(), bucket: i.s3.bucket.trim(),
          ...(i.s3.region.trim() !== '' ? { region: i.s3.region.trim() } : {}),
          ...(i.s3.prefix.trim() !== '' ? { prefix: i.s3.prefix.trim() } : {}),
          ...(i.s3.caPem.trim() !== '' ? { ca_pem: i.s3.caPem.trim() + '\n' } : {}),
          ...(i.s3.accessKey !== '' ? { access_key: i.s3.accessKey } : {}),
          ...(i.s3.secretKey !== '' ? { secret_key: i.s3.secretKey } : {}),
        },
      }
  }
}

/** The same input without any credential; kept across a step-up redirect instead of the secrets. */
export function withoutSecrets(i: TargetInput): TargetInput {
  return { ...i, smb: { ...i.smb, password: '' }, s3: { ...i.s3, accessKey: '', secretKey: '' } }
}

/** Whether the input holds a credential the browser must not keep. */
export function hasSecrets(i: TargetInput): boolean {
  return i.smb.password !== '' || i.s3.accessKey !== '' || i.s3.secretKey !== ''
}

/** The ranges of the schedule fields (plan M15 decision 12). */
export const scheduleRanges = {
  full_interval_hours: [6, 168],
  openbao_interval_hours: [1, 24],
  fleet_interval_hours: [6, 168],
  escrow_interval_hours: [1, 24],
  retention_full: [2, 60],
  openbao_keep_days: [7, 365],
  fleet_keep_days: [7, 365],
} as const satisfies Record<keyof BackupScheduleUpdate, readonly [number, number]>

export type ScheduleField = keyof typeof scheduleRanges

export function scheduleFields(): ScheduleField[] {
  return Object.keys(scheduleRanges) as ScheduleField[]
}

export function scheduleOf(s: BackupSchedule): BackupScheduleUpdate {
  return {
    full_interval_hours: s.full_interval_hours, openbao_interval_hours: s.openbao_interval_hours,
    fleet_interval_hours: s.fleet_interval_hours, escrow_interval_hours: s.escrow_interval_hours,
    retention_full: s.retention_full, openbao_keep_days: s.openbao_keep_days, fleet_keep_days: s.fleet_keep_days,
  }
}

/** The schedule fields outside their range or not whole numbers. */
export function scheduleErrors(s: BackupScheduleUpdate): ScheduleField[] {
  return scheduleFields().filter((f) => {
    const [min, max] = scheduleRanges[f]
    return !Number.isInteger(s[f]) || s[f] < min || s[f] > max
  })
}

export async function loadOverview(): Promise<BackupOverview | BackupProblem> {
  const { data, error } = await api.GET('/api/platform/v1/backup')
  return data ?? problemOf(error)
}

export async function loadKey(): Promise<BackupKeyStatus | BackupProblem> {
  const { data, error } = await api.GET('/api/platform/v1/backup/key')
  return data ?? problemOf(error)
}

/** Generates a key; the response holds its text and is meant to be shown once, never stored. */
export async function generateKey(): Promise<BackupKeyGenerated | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/key', { params: { header: csrf } })
  return data ?? problemOf(error)
}

export async function confirmKey(id: string, answer: string): Promise<BackupKey | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/key/{id}/confirm', {
    params: { path: { id }, header: csrf }, body: { answer },
  })
  return data ?? problemOf(error)
}

export async function discardKey(id: string): Promise<BackupKey | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/key/{id}/discard', { params: { path: { id }, header: csrf } })
  return data ?? problemOf(error)
}

export async function loadSchedule(): Promise<BackupSchedule | BackupProblem> {
  const { data, error } = await api.GET('/api/platform/v1/backup/schedule')
  return data ?? problemOf(error)
}

export async function saveSchedule(body: BackupScheduleUpdate): Promise<BackupSchedule | BackupProblem> {
  const { data, error } = await api.PUT('/api/platform/v1/backup/schedule', { params: { header: csrf }, body })
  return data ?? problemOf(error)
}

export function targetLister(): (p: ListParams) => Promise<Page<BackupTarget>> {
  return async (p) => {
    const enabled = (p.enabled as string[] | undefined) ?? []
    return listPage(
      await api.GET('/api/platform/v1/backup/targets', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as TargetSort, q: p.q,
            type: p.type as BackupTargetType[], host_state: p.host_state as BackupTargetHostState[],
            enabled: enabled.length === 1 ? enabled[0] === 'true' : undefined,
          },
        },
      }),
    )
  }
}

export function runLister(): (p: ListParams) => Promise<Page<BackupRun>> {
  return async (p) =>
    listPage(
      await api.GET('/api/platform/v1/backup/runs', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as RunSort,
            kind: p.kind as BackupKind[], outcome: p.outcome as ('succeeded' | 'failed')[],
          },
        },
      }),
    )
}

export async function getTarget(id: string): Promise<BackupTarget | BackupProblem> {
  const { data, error } = await api.GET('/api/platform/v1/backup/targets/{id}', { params: { path: { id } } })
  return data ?? problemOf(error)
}

export async function createTarget(input: TargetInput): Promise<BackupTarget | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/targets', { params: { header: csrf }, body: toBody(input) })
  return data ?? problemOf(error)
}

export async function updateTarget(id: string, input: TargetInput): Promise<BackupTarget | BackupProblem> {
  const { data, error } = await api.PUT('/api/platform/v1/backup/targets/{id}', { params: { path: { id }, header: csrf }, body: toBody(input) })
  return data ?? problemOf(error)
}

export async function deleteTarget(id: string): Promise<BackupProblem | null> {
  const { error } = await api.DELETE('/api/platform/v1/backup/targets/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemOf(error) : null
}

export async function testTarget(id: string): Promise<BackupTarget | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/targets/{id}/test', { params: { path: { id }, header: csrf } })
  return data ?? problemOf(error)
}

export async function setTargetEnabled(id: string, enabled: boolean): Promise<BackupTarget | BackupProblem> {
  const params = { path: { id }, header: csrf }
  const { data, error } = enabled
    ? await api.POST('/api/platform/v1/backup/targets/{id}/enable', { params })
    : await api.POST('/api/platform/v1/backup/targets/{id}/disable', { params })
  return data ?? problemOf(error)
}

/** Requests a backup of every kind now; null once requested. */
export async function requestRun(): Promise<BackupProblem | null> {
  const { error } = await api.POST('/api/platform/v1/backup/run', { params: { header: csrf }, body: { label: '' } })
  return error ? problemOf(error) : null
}

/** The word that confirms a restore plan; the server checks it again (plan M15 decision 25). */
export const restoreWord = 'restore'
export const restoreComponents: RestoreComponent[] = ['postgres', 'openbao', 'fleet', 'escrow']
export const restorePlanStates: BackupRestorePlanState[] = ['approved', 'running', 'completed', 'failed', 'expired', 'abandoned']

export const planFilters: ListFilter[] = [
  { kind: 'enum', key: 'state', label: 'backup.restore.state', options: restorePlanStates.map((value) => ({ value, title: 'backup.restore.states.' + value })) },
]

/** The chip of a plan's state; the server already reports an approved plan past its expiry as expired. */
export function planStateStatus(state: BackupRestorePlanState): StatusView {
  const status: Record<BackupRestorePlanState, Status> = { approved: 'info', running: 'warn', completed: 'ok', failed: 'critical', expired: 'neutral', abandoned: 'neutral' }
  return { status: status[state], label: 'backup.restore.states.' + state }
}

/**
 * The newest success per kind of a source: the target's own status, or for the local repository the newest run per
 * kind that succeeded (the overview carries the newest run per kind only).
 */
export function newestSuccess(overview: BackupOverview, sourceTargetId: string | null): Record<BackupKind, string | null> {
  const out = Object.fromEntries(backupKinds.map((k) => [k, null])) as Record<BackupKind, string | null>
  if (sourceTargetId) {
    for (const s of overview.targets.find((x) => x.id === sourceTargetId)?.status ?? []) out[s.kind] = s.last_success_at
    return out
  }
  for (const r of overview.last_runs) if (r.outcome === 'succeeded') out[r.kind] = r.finished_at ?? r.started_at
  return out
}

/** What the plan dialog edits; at is the value of a datetime-local field. */
export interface PlanInput {
  kind: 'point_in_time' | 'components'
  sourceTargetId: string | null
  at: string
  components: RestoreComponent[]
  confirmation: string
}

export function emptyPlan(): PlanInput {
  return { kind: 'components', sourceTargetId: null, at: '', components: [...restoreComponents], confirmation: '' }
}

export type PlanField = 'at' | 'components' | 'confirmation'

/** The fields that block the request: a point in the future or missing, no component, a wrong word. */
export function planErrors(i: PlanInput, now: Date): PlanField[] {
  const errors: PlanField[] = []
  if (i.kind === 'point_in_time') {
    const at = new Date(i.at)
    if (i.at === '' || Number.isNaN(at.getTime()) || at.getTime() > now.getTime() + 60_000) errors.push('at')
  }
  if (i.components.length === 0) errors.push('components')
  if (i.confirmation !== restoreWord) errors.push('confirmation')
  return errors
}

export function planBody(i: PlanInput): BackupRestorePlanInput {
  return {
    kind: i.kind,
    components: restoreComponents.filter((c) => i.components.includes(c)),
    confirmation: i.confirmation,
    ...(i.sourceTargetId ? { source_target_id: i.sourceTargetId } : {}),
    ...(i.kind === 'point_in_time' ? { at: new Date(i.at).toISOString() } : {}),
  }
}

/** The time left until expiresAt in whole hours and minutes; null once it has passed. */
export function timeLeft(expiresAt: string, now: Date): { hours: number; minutes: number } | null {
  const ms = Date.parse(expiresAt) - now.getTime()
  if (!(ms > 0)) return null
  const minutes = Math.floor(ms / 60_000)
  return { hours: Math.floor(minutes / 60), minutes: minutes % 60 }
}

export function planLister(): (p: ListParams) => Promise<Page<BackupRestorePlan>> {
  return async (p) =>
    listPage(
      await api.GET('/api/platform/v1/backup/restore-plans', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as PlanSort, q: p.q,
            state: p.state as BackupRestorePlanState[],
          },
        },
      }),
    )
}

export async function createRestorePlan(input: PlanInput): Promise<BackupRestorePlan | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/restore-plans', { params: { header: csrf }, body: planBody(input) })
  return data ?? problemOf(error)
}

export async function abandonRestorePlan(id: string, confirmation: string): Promise<BackupRestorePlan | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/restore-plans/{id}/abandon', { params: { path: { id }, header: csrf }, body: { confirmation } })
  return data ?? problemOf(error)
}

export async function cancelRestorePlan(id: string): Promise<BackupRestorePlan | BackupProblem> {
  const { data, error } = await api.POST('/api/platform/v1/backup/restore-plans/{id}/cancel', { params: { path: { id }, header: csrf } })
  return data ?? problemOf(error)
}
