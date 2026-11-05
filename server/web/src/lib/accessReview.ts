import type { LocationQuery } from 'vue-router'
import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'
import type { ListColumn, ListParams, Page } from './listQuery'

/** The access review of an organization (plan M12 decision 27). */
export type AccessReviewReport = components['schemas']['AccessReviewReport']
/** The access review of the platform. */
export type PlatformAccessReviewReport = components['schemas']['PlatformAccessReviewReport']

/** Where a report lives: the organization's API or the platform's. */
export type ReviewScope = 'organization' | 'platform'

/** One cell value of a section row. */
export type ReviewCell = string | number | boolean | null
/** One row of a section table; keys are the column keys. */
export type ReviewRow = Record<string, ReviewCell>

/** A column of a section table; kind selects how the cell renders. */
export interface ReviewColumn extends ListColumn {
  kind?: 'time' | 'flag'
}

/** One expandable card of the page: the rows the API returned and the total it counted (rows are capped). */
export interface ReviewSection {
  key: string
  title: string
  total: number
  rows: ReviewRow[]
  columns: ReviewColumn[]
  defaultSort: string
  /** An additional line (message key and its parameters) shown above the table. */
  note?: { key: string; params: Record<string, number> }
}

/** The presets of the period picker, in days. */
export const presets = [30, 90, 365] as const
/** The default preset, as the API's default period. */
export const defaultPreset = 90
/** The longest period the API accepts, in days. */
export const maxDays = 400

const dayMs = 86_400_000
const dayPattern = /^\d{4}-\d{2}-\d{2}$/

/** The period of a view or export; from and to are the RFC 3339 instants sent to the API. */
export interface ResolvedPeriod {
  preset: (typeof presets)[number] | 'custom'
  from: string
  to: string
  /** The UTC days a custom period shows in its inputs; empty for presets. */
  fromDay: string
  toDay: string
  /** A message key when the custom range is not valid; from and to are then empty. */
  error: string
}

function validDay(value: string): boolean {
  return dayPattern.test(value) && !Number.isNaN(Date.parse(value + 'T00:00:00Z'))
}

/** Validates a custom range of UTC days; the message key of the problem, or '' (the last day is included). */
export function customRangeError(fromDay: string, toDay: string): string {
  if (!validDay(fromDay) || !validDay(toDay)) return 'accessReview.errors.dates'
  const span = (Date.parse(toDay + 'T00:00:00Z') - Date.parse(fromDay + 'T00:00:00Z')) / dayMs + 1
  if (span < 1) return 'accessReview.errors.order'
  if (span > maxDays) return 'accessReview.errors.tooLong'
  return ''
}

/**
 * The period of the route query: days=30|90|365, or from and to as UTC days for a custom range; anything else is the
 * default preset. A custom range covers whole UTC days, the last one included.
 */
export function resolvePeriod(query: LocationQuery, now: Date): ResolvedPeriod {
  const one = (v: LocationQuery[string]): string => (Array.isArray(v) ? (v[0] ?? '') : (v ?? ''))
  const fromDay = one(query.from)
  const toDay = one(query.to)
  if (fromDay !== '' || toDay !== '') {
    const error = customRangeError(fromDay, toDay)
    if (error !== '') return { preset: 'custom', from: '', to: '', fromDay, toDay, error }
    const end = Date.parse(toDay + 'T00:00:00Z') + dayMs
    return { preset: 'custom', from: new Date(Date.parse(fromDay + 'T00:00:00Z')).toISOString(), to: new Date(end).toISOString(), fromDay, toDay, error: '' }
  }
  const days = Number(one(query.days))
  const preset = presets.find((p) => p === days) ?? defaultPreset
  return { preset, from: new Date(now.getTime() - preset * dayMs).toISOString(), to: now.toISOString(), fromDay: '', toDay: '', error: '' }
}

/** The report of the organization; the problem code on failure. */
export async function getAccessReview(p: ResolvedPeriod): Promise<AccessReviewReport | string> {
  const { data, error } = await api.GET('/api/v1/access-review', { params: { query: { from: p.from, to: p.to } } })
  return data ?? problemCode(error)
}

/** The report of the platform; the problem code on failure. */
export async function getPlatformAccessReview(p: ResolvedPeriod): Promise<PlatformAccessReviewReport | string> {
  const { data, error } = await api.GET('/api/platform/v1/access-review', { params: { query: { from: p.from, to: p.to } } })
  return data ?? problemCode(error)
}

/** The URL of an export; the browser fetches it with the session cookie and names the file after the response. */
export function exportUrl(scope: ReviewScope, p: ResolvedPeriod, format: 'json' | 'csv'): string {
  const base = scope === 'platform' ? '/api/platform/v1/access-review/export' : '/api/v1/access-review/export'
  return base + '?' + new URLSearchParams({ from: p.from, to: p.to, format }).toString()
}

function text(params: Record<string, unknown>): string {
  return Object.entries(params)
    .map(([k, v]) => k + '=' + String(v))
    .join(', ')
}

function rolesSection(roles: AccessReviewReport['roles']): ReviewSection {
  const roleRows = roles.flatMap((role) =>
    role.members.map((m) => ({ role: role.role, username: m.username, first_seen_at: m.first_seen_at })),
  )
  return {
    key: 'roles',
    title: 'accessReview.sections.roles',
    total: roles.reduce((sum, role) => sum + role.total, 0),
    rows: roleRows,
    columns: [
      { key: 'role', title: 'accessReview.columns.role', sortable: true, role: 'primary' },
      { key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'meta' },
      { key: 'first_seen_at', title: 'accessReview.columns.firstSeen', sortable: true, role: 'meta', kind: 'time' },
    ],
    defaultSort: 'role',
  }
}

function roleChangesSection(changes: AccessReviewReport['role_changes']): ReviewSection {
  return {
    key: 'changes',
    title: 'accessReview.sections.roleChanges',
    total: changes.total,
    rows: changes.items.map((e) => ({ ...e })),
    columns: [
      { key: 'at', title: 'accessReview.columns.at', sortable: true, role: 'meta', kind: 'time' },
      { key: 'code', title: 'accessReview.columns.code', sortable: true, role: 'primary', mono: true },
      { key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'meta' },
      { key: 'role', title: 'accessReview.columns.role', sortable: true, role: 'meta' },
      { key: 'actor', title: 'accessReview.columns.actor', sortable: true, role: 'meta', hideBelow: 'md' },
    ],
    defaultSort: '-at',
  }
}

/** The sections of the organization's report, in the order of the page. */
export function organizationSections(r: AccessReviewReport): ReviewSection[] {
  return [
    rolesSection(r.roles),
    roleChangesSection(r.role_changes),
    {
      key: 'accounts',
      title: 'accessReview.sections.accounts',
      total: r.accounts.total,
      rows: r.accounts.items.map((a) => ({ ...a })),
      columns: [
        { key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'primary' },
        { key: 'display_name', title: 'accessReview.columns.displayName', sortable: true, role: 'meta', hideBelow: 'sm' },
        { key: 'role', title: 'accessReview.columns.role', sortable: true, role: 'meta' },
        { key: 'last_login_at', title: 'accessReview.columns.lastLogin', sortable: true, role: 'meta', kind: 'time' },
        { key: 'disabled', title: 'accessReview.columns.disabled', sortable: true, role: 'status', kind: 'flag' },
      ],
      defaultSort: 'username',
    },
    {
      key: 'tokens',
      title: 'accessReview.sections.tokens',
      total: r.api_tokens.total,
      rows: r.api_tokens.items.map((x) => ({ ...x })),
      columns: [
        { key: 'name', title: 'accessReview.columns.name', sortable: true, role: 'primary' },
        { key: 'role', title: 'accessReview.columns.role', sortable: true, role: 'meta' },
        { key: 'prefix', title: 'accessReview.columns.prefix', role: 'meta', mono: true, hideBelow: 'md' },
        { key: 'created_by', title: 'accessReview.columns.createdBy', sortable: true, role: 'meta', hideBelow: 'md' },
        { key: 'created_at', title: 'accessReview.columns.createdAt', sortable: true, role: 'meta', kind: 'time' },
        { key: 'expires_at', title: 'accessReview.columns.expiresAt', sortable: true, role: 'meta', kind: 'time', hideBelow: 'xl' },
        { key: 'last_used_at', title: 'accessReview.columns.lastUsed', sortable: true, role: 'meta', kind: 'time', hideBelow: 'xl' },
        { key: 'revoked_at', title: 'accessReview.columns.revokedAt', sortable: true, role: 'meta', kind: 'time', hideBelow: 'xl' },
        { key: 'revoked_by', title: 'accessReview.columns.revokedBy', role: 'meta', hideBelow: 'xl' },
      ],
      defaultSort: '-created_at',
      note: { key: 'accessReview.tokenDenials', params: { count: r.token_denials } },
    },
    {
      key: 'reveals',
      title: 'accessReview.sections.reveals',
      total: r.reveals.total,
      rows: r.reveals.items.map((e) => ({ at: e.at, code: e.code, actor: e.actor, device_hostname: e.device_hostname, params: text(e.params) })),
      columns: [
        { key: 'at', title: 'accessReview.columns.at', sortable: true, role: 'meta', kind: 'time' },
        { key: 'code', title: 'accessReview.columns.code', sortable: true, role: 'primary', mono: true },
        { key: 'actor', title: 'accessReview.columns.actor', sortable: true, role: 'meta' },
        { key: 'device_hostname', title: 'accessReview.columns.device', sortable: true, role: 'meta' },
        { key: 'params', title: 'accessReview.columns.params', role: 'meta', mono: true, hideBelow: 'md' },
      ],
      defaultSort: '-at',
    },
    {
      key: 'sessions',
      title: 'accessReview.sections.sessionsRevoked',
      total: r.sessions_revoked.total,
      rows: r.sessions_revoked.items.map((s) => ({ ...s })),
      columns: [
        { key: 'at', title: 'accessReview.columns.at', sortable: true, role: 'meta', kind: 'time' },
        { key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'primary' },
        { key: 'reason', title: 'accessReview.columns.reason', sortable: true, role: 'meta' },
      ],
      defaultSort: '-at',
    },
    {
      key: 'destructive',
      title: 'accessReview.sections.destructive',
      total: r.destructive.total,
      rows: r.destructive.items.map((d) => ({ ...d })),
      columns: [
        { key: 'at', title: 'accessReview.columns.at', sortable: true, role: 'meta', kind: 'time' },
        { key: 'code', title: 'accessReview.columns.code', sortable: true, role: 'primary', mono: true },
        { key: 'actor', title: 'accessReview.columns.actor', sortable: true, role: 'meta' },
        { key: 'target', title: 'accessReview.columns.target', sortable: true, role: 'meta' },
      ],
      defaultSort: '-at',
    },
    {
      key: 'breakglass',
      title: 'accessReview.sections.breakGlass',
      total: r.break_glass_accounts.length,
      rows: r.break_glass_accounts.map((username) => ({ username })),
      columns: [{ key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'primary' }],
      defaultSort: 'username',
    },
  ]
}

/** The sections of the platform's report, in the order of the page. */
export function platformSections(r: PlatformAccessReviewReport): ReviewSection[] {
  return [
    rolesSection(r.roles),
    {
      key: 'administrators',
      title: 'accessReview.sections.administrators',
      total: r.administrators.total,
      rows: r.administrators.items.map((a) => ({ ...a })),
      columns: [
        { key: 'username', title: 'accessReview.columns.username', sortable: true, role: 'primary' },
        { key: 'display_name', title: 'accessReview.columns.displayName', sortable: true, role: 'meta', hideBelow: 'sm' },
        { key: 'last_login_at', title: 'accessReview.columns.lastLogin', sortable: true, role: 'meta', kind: 'time' },
      ],
      defaultSort: 'username',
    },
    roleChangesSection(r.role_changes),
    {
      key: 'events',
      title: 'accessReview.sections.platformEvents',
      total: r.events.total,
      rows: r.events.items.map((e) => ({ ...e })),
      columns: [
        { key: 'at', title: 'accessReview.columns.at', sortable: true, role: 'meta', kind: 'time' },
        { key: 'code', title: 'accessReview.columns.code', sortable: true, role: 'primary', mono: true },
        { key: 'actor', title: 'accessReview.columns.actor', sortable: true, role: 'meta' },
        { key: 'target', title: 'accessReview.columns.target', sortable: true, role: 'meta' },
      ],
      defaultSort: '-at',
    },
    {
      key: 'organizations',
      title: 'accessReview.sections.organizationsCreated',
      total: r.organizations_created.total,
      rows: r.organizations_created.items.map((o) => ({ ...o })),
      columns: [
        { key: 'slug', title: 'accessReview.columns.slug', sortable: true, role: 'primary', mono: true },
        { key: 'name', title: 'accessReview.columns.name', sortable: true, role: 'meta' },
        { key: 'created_at', title: 'accessReview.columns.createdAt', sortable: true, role: 'meta', kind: 'time' },
      ],
      defaultSort: '-created_at',
    },
  ]
}

function compare(a: ReviewCell | undefined, b: ReviewCell | undefined): number {
  // Empty values sort last in either direction of the caller's sign flip, so they are ranked apart here.
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1
  if (b === null || b === undefined) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b))
}

/** One page of the rows of a section, sorted and searched in the browser: the report is one response. */
export function clientPage(rows: ReviewRow[], p: ListParams): Page<ReviewRow> {
  const needle = (p.q ?? '').trim().toLowerCase()
  const keyed: ReviewRow[] = rows.map((row, i) => ({ ...row, __row: i }))
  const found = needle === ''
    ? keyed
    : keyed.filter((row) => Object.values(row).some((v) => typeof v === 'string' && v.toLowerCase().includes(needle)))
  const descending = p.sort.startsWith('-')
  const key = descending ? p.sort.slice(1) : p.sort
  const sorted = [...found].sort((x, y) => {
    const a = x[key]
    const b = y[key]
    const empty = a === null || a === undefined || b === null || b === undefined
    return empty || !descending ? compare(a, b) : -compare(a, b)
  })
  const start = (p.page - 1) * p.page_size
  return { items: sorted.slice(start, start + p.page_size), page: p.page, page_size: p.page_size, total: sorted.length, total_capped: false, sort: p.sort }
}
