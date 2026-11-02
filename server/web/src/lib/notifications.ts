import { api, listPage, problemCode } from '../api/client'
import type { components } from '../api/schema'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'

export type NotificationDestination = components['schemas']['NotificationDestination']
export type NotificationDestinationType = components['schemas']['NotificationDestinationType']
export type NotificationFilterMode = components['schemas']['NotificationFilterMode']
type CreateBody = components['schemas']['NotificationDestinationCreate']
type UpdateBody = components['schemas']['NotificationDestinationUpdate']
type Sort = components['parameters']['NotificationDestinationSort']

/** Where a destination page works: the organization's destinations or the platform's (plan M9 decision 36). */
export type NotificationScope = 'organization' | 'platform'

/** What the form edits; the URL is write-only and empty unless the administrator types a new one. */
export interface NotificationInput {
  type: NotificationDestinationType
  name: string
  enabled: boolean
  filterMode: NotificationFilterMode
  codes: string[]
  pseudonymizeUsers: boolean
  includeParams: boolean
  url: string
  heartbeatIntervalS: number
  recipients: string[]
  emailMinIntervalS: number
}

/** The answer of an operation: the problem code with the server's detail when it sent one. */
export interface NotificationProblem {
  code: string
  detail?: string
}

export const namePattern = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/
export const maxCodes = 200
export const maxRecipients = 20
/** How long and how often the portal asks for the result of a test or a pseudonym lookup (plan M9 decision 36). */
export const pollIntervalMs = 2000
export const pollTimeoutMs = 30_000

/** The step-up action of a pseudonym lookup; the page resumes it, the dialog repeats the request. */
export const pseudonymStepUpAction = 'notification-resolve'

export const pseudonymPattern = /^u_[0-9a-f]{24}$/

const csrf = { 'X-Paddock-CSRF': '1' } as const
const types: NotificationDestinationType[] = ['webhook', 'email']

/** Filters of the destination list. */
export const notificationFilters: ListFilter[] = [
  { kind: 'enum', key: 'type', label: 'notifications.type', options: types.map((value) => ({ value, title: 'notifications.types.' + value })) },
  {
    kind: 'enum', key: 'enabled', label: 'notifications.enabled',
    options: [{ value: 'true', title: 'notifications.on' }, { value: 'false', title: 'notifications.off' }],
  },
]

/** An empty form; a new destination is enabled and forwards the security preset. */
export function emptyInput(): NotificationInput {
  return {
    type: 'webhook', name: '', enabled: true, filterMode: 'security', codes: [], pseudonymizeUsers: false,
    includeParams: false, url: '', heartbeatIntervalS: 0, recipients: [], emailMinIntervalS: 300,
  }
}

/** The form of a stored destination; the URL stays empty (it is never returned). */
export function inputOf(d: NotificationDestination): NotificationInput {
  return {
    type: d.type, name: d.name, enabled: d.enabled, filterMode: d.filter_mode, codes: [...d.codes],
    pseudonymizeUsers: d.pseudonymize_users, includeParams: d.include_params, url: '',
    heartbeatIntervalS: d.heartbeat_interval_s, recipients: [...d.recipients], emailMinIntervalS: d.email_min_interval_s,
  }
}

/** The fields validation and server problems are shown at. */
export type NotificationField = 'name' | 'type' | 'url' | 'codes' | 'recipients' | 'heartbeat' | 'interval'

export type NotificationErrors = Partial<Record<NotificationField, string>>

/** Validates an input like the server (plan M9 decision 9); returns message keys by field. */
export function validateNotification(input: NotificationInput, editing: boolean, knownCodes: readonly string[]): NotificationErrors {
  const errors: NotificationErrors = {}
  if (!namePattern.test(input.name)) errors.name = 'notifications.nameInvalid'
  if (input.type === 'webhook') {
    if (!editing && input.url.trim() === '') errors.url = 'notifications.urlRequired'
    else if (input.url.trim() !== '' && !input.url.trim().startsWith('https://')) errors.url = 'notifications.urlHttps'
    if (input.heartbeatIntervalS !== 0 && (input.heartbeatIntervalS < 60 || input.heartbeatIntervalS > 3600)) {
      errors.heartbeat = 'notifications.heartbeatInvalid'
    }
  } else {
    if (input.recipients.length < 1 || input.recipients.length > maxRecipients) errors.recipients = 'notifications.recipientsCount'
    else if (input.recipients.some((r) => !/^[^\s@,;<>]+@[^\s@,;<>]+$/.test(r))) errors.recipients = 'notifications.recipientsInvalid'
    if (input.emailMinIntervalS < 60 || input.emailMinIntervalS > 3600) errors.interval = 'notifications.intervalInvalid'
  }
  if (input.filterMode === 'custom') {
    if (input.codes.length < 1 || input.codes.length > maxCodes) errors.codes = 'notifications.codesCount'
    else if (input.codes.some((c) => !knownCodes.includes(c))) errors.codes = 'notifications.codesUnknown'
  }
  return errors
}

/** The recipients typed one per line or separated by commas and semicolons. */
export function parseRecipients(text: string): string[] {
  return text.split(/[\s,;]+/).filter((r) => r !== '')
}

/** The field a server problem belongs to; null for problems of the whole form. */
export function fieldOfProblem(p: NotificationProblem): NotificationField | null {
  switch (p.code) {
    case 'unknown_code':
      return 'codes'
    case 'email_not_configured':
      return 'type'
    case 'name_taken':
    case 'already_exists':
      return 'name'
    case 'invalid_request': {
      const d = p.detail ?? ''
      if (/^(invalid webhook URL|webhook host|a webhook destination requires url|an e-mail destination has no url)/.test(d)) return 'url'
      if (d.startsWith('heartbeat_interval_s')) return 'heartbeat'
      if (d.startsWith('recipients')) return 'recipients'
      if (d.startsWith('email_min_interval_s')) return 'interval'
      if (d.startsWith('name must')) return 'name'
      if (d.startsWith('codes')) return 'codes'
    }
  }
  return null
}

/** The state chip of a destination: disabled, stalled (with the failure class), or active. */
export function stateStatus(d: NotificationDestination): StatusView {
  if (!d.enabled) return { status: 'neutral', label: 'notifications.states.disabled' }
  if (d.state.status === 'stalled') return { status: 'critical', label: 'notifications.states.stalled' }
  return { status: 'ok', label: 'notifications.states.active' }
}

/** The events a re-enabled destination would deliver with cursor continue; null while unknown. */
export function backlogOf(latest: number | null, d: NotificationDestination): number | null {
  return latest === null ? null : Math.max(0, latest - d.state.cursor_commit_seq)
}

function problemOf(error: unknown): NotificationProblem {
  const detail = error && typeof error === 'object' && 'detail' in error && typeof error.detail === 'string' ? error.detail : undefined
  return { code: problemCode(error), detail }
}

function createBody(i: NotificationInput, scope: NotificationScope): CreateBody {
  const webhook = i.type === 'webhook'
  return {
    type: i.type, name: i.name, enabled: i.enabled, filter_mode: i.filterMode,
    codes: i.filterMode === 'custom' ? i.codes : [],
    pseudonymize_users: scope === 'organization' && i.pseudonymizeUsers, include_params: i.includeParams,
    heartbeat_interval_s: webhook ? i.heartbeatIntervalS : 0,
    email_min_interval_s: webhook ? emptyInput().emailMinIntervalS : i.emailMinIntervalS,
    ...(webhook ? (i.url.trim() !== '' ? { url: i.url.trim() } : {}) : { recipients: i.recipients }),
  }
}

/** One page of destinations for DataList. */
export function destinationLister(scope: NotificationScope): (p: ListParams) => Promise<Page<NotificationDestination>> {
  return async (p) => {
    const query = {
      page: p.page, page_size: p.page_size, sort: p.sort as Sort, q: p.q,
      type: p.type as NotificationDestinationType[],
      enabled: ((p.enabled as string[] | undefined) ?? []).length === 1 ? (p.enabled as string[])[0] === 'true' : undefined,
    }
    return listPage(
      scope === 'platform'
        ? await api.GET('/api/platform/v1/notification-destinations', { params: { query } })
        : await api.GET('/api/v1/notification-destinations', { params: { query } }),
    )
  }
}

/** Whether the installation can send e-mail (an SMTP relay is configured); false when the answer fails. */
export async function loadEmailCapability(): Promise<boolean> {
  const { data } = await api.GET('/api/v1/notification-capabilities')
  return data?.email ?? false
}

/** The newest audit position of the organization, the base of the backlog shown when enabling; null on failure. */
export async function loadLatestSeq(): Promise<number | null> {
  const { data } = await api.GET('/api/v1/audit-events/feed', { params: { query: { limit: 1 } } })
  return data?.latest ?? null
}

/** The organization's destinations that pseudonymize user names (the first 100); only they can resolve a pseudonym. */
export async function listPseudonymizing(): Promise<NotificationDestination[]> {
  const { data } = await api.GET('/api/v1/notification-destinations', { params: { query: { page: 1, page_size: 100 } } })
  return (data?.items ?? []).filter((d) => d.pseudonymize_users)
}

/** One destination with its delivery state. */
export async function getDestination(scope: NotificationScope, id: string): Promise<NotificationDestination | NotificationProblem> {
  const params = { path: { id } }
  const { data, error } = scope === 'platform'
    ? await api.GET('/api/platform/v1/notification-destinations/{id}', { params })
    : await api.GET('/api/v1/notification-destinations/{id}', { params })
  return data ?? problemOf(error)
}

/** The created destination with the secret shown once (webhook), or the problem. */
export type Created = { destination: NotificationDestination; secret: string | null }

export async function createDestination(scope: NotificationScope, input: NotificationInput): Promise<Created | NotificationProblem> {
  const body = createBody(input, scope)
  const params = { header: csrf }
  const { data, error } = scope === 'platform'
    ? await api.POST('/api/platform/v1/notification-destinations', { params, body })
    : await api.POST('/api/v1/notification-destinations', { params, body })
  if (!data) return problemOf(error)
  const { secret, ...destination } = data
  return { destination: destination as NotificationDestination, secret: secret ?? null }
}

/** Replaces a destination's settings; the URL is sent only when typed. cursor is required when it enables one. */
export async function updateDestination(
  scope: NotificationScope, id: string, input: NotificationInput, cursor?: 'continue' | 'skip',
): Promise<NotificationDestination | NotificationProblem> {
  const body: UpdateBody = { ...createBody(input, scope), ...(cursor ? { cursor } : {}) }
  const params = { path: { id }, header: csrf }
  const { data, error } = scope === 'platform'
    ? await api.PUT('/api/platform/v1/notification-destinations/{id}', { params, body })
    : await api.PUT('/api/v1/notification-destinations/{id}', { params, body })
  return data ?? problemOf(error)
}

/** Deletes a destination; null on success. */
export async function deleteDestination(scope: NotificationScope, id: string): Promise<NotificationProblem | null> {
  const params = { path: { id }, header: csrf }
  const { error } = scope === 'platform'
    ? await api.DELETE('/api/platform/v1/notification-destinations/{id}', { params })
    : await api.DELETE('/api/v1/notification-destinations/{id}', { params })
  return error ? problemOf(error) : null
}

/** Replaces the signing secret; the new secret is shown once. */
export async function rotateSecret(scope: NotificationScope, id: string): Promise<string | NotificationProblem> {
  const params = { path: { id }, header: csrf }
  const { data, error } = scope === 'platform'
    ? await api.POST('/api/platform/v1/notification-destinations/{id}/rotate-secret', { params })
    : await api.POST('/api/v1/notification-destinations/{id}/rotate-secret', { params })
  return data ? data.secret : problemOf(error)
}

/** Requests a test delivery; null once requested. */
export async function requestTest(scope: NotificationScope, id: string): Promise<NotificationProblem | null> {
  const params = { path: { id }, header: csrf }
  const { error } = scope === 'platform'
    ? await api.POST('/api/platform/v1/notification-destinations/{id}/test', { params })
    : await api.POST('/api/v1/notification-destinations/{id}/test', { params })
  return error ? problemOf(error) : null
}

/** Asks which user name a pseudonym stands for; the lookup id on success. */
export async function requestPseudonym(id: string, pseudonym: string): Promise<string | NotificationProblem> {
  const { data, error } = await api.POST('/api/v1/notification-destinations/{id}/resolve-pseudonym', {
    params: { path: { id }, header: csrf }, body: { pseudonym },
  })
  return data ? data.lookup_id : problemOf(error)
}

/** The result of a pseudonym lookup; resolved false until the notifier answered, read once. */
export async function getPseudonymLookup(id: string, lookupId: string): Promise<{ resolved: boolean; username: string } | NotificationProblem> {
  const { data, error } = await api.GET('/api/v1/notification-destinations/{id}/resolve-pseudonym/{lookup_id}', {
    params: { path: { id, lookup_id: lookupId } },
  })
  return data ? { resolved: data.resolved, username: data.username ?? '' } : problemOf(error)
}

/** A problem answer, not a destination or a value. */
export function isProblem(v: unknown): v is NotificationProblem {
  return typeof v === 'object' && v !== null && 'code' in v && typeof (v as { code: unknown }).code === 'string'
}

/** Lag as a short text: seconds below a minute, then minutes, hours and days. */
export function lagParts(seconds: number): { unit: 's' | 'min' | 'h' | 'd'; value: number } {
  if (seconds < 60) return { unit: 's', value: seconds }
  if (seconds < 3600) return { unit: 'min', value: Math.floor(seconds / 60) }
  if (seconds < 86400) return { unit: 'h', value: Math.floor(seconds / 3600) }
  return { unit: 'd', value: Math.floor(seconds / 86400) }
}

/** Waits for the result of check, asking every interval until it returns a value or the timeout passes; null on timeout. */
export async function pollUntil<T>(
  check: () => Promise<T | null>, isCancelled: () => boolean, intervalMs = pollIntervalMs, timeoutMs = pollTimeoutMs,
): Promise<T | null> {
  const deadline = Date.now() + timeoutMs
  while (!isCancelled()) {
    const value = await check()
    if (value !== null) return value
    if (Date.now() + intervalMs > deadline) return null
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
  return null
}
