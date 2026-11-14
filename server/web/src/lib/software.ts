import {
  api, listPage, problemCode, type CompileWarning, type CompileWarningSort, type DeviceManagedSoftware, type DeviceManagedSoftwareSort,
  type DeviceSoftwareState, type PackageRef, type SoftwareApproval, type SoftwareArchitecture, type SoftwareAssignment, type SoftwareAssignmentSort,
  type SoftwareCatalogDevice, type SoftwareCatalogDeviceSort, type SoftwareCatalogEntry, type SoftwareCatalogSort, type SoftwareIntent,
  type SoftwareScope, type SoftwareSource, type SoftwareSourceKind, type SoftwareSourceSort, type SoftwareSourceSummary,
  type SoftwareTarget, type SoftwareUpdateRule, type UserSoftware, type UserSoftwareSort,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import { urgentReasonMin, type StagedKey } from './configRollouts'
import type { StatusView } from './status'
import { validPackage, validPackageVersion } from './updates'

const csrf = { 'X-Paddock-CSRF': '1' } as const

function first(p: ListParams, key: string): string | undefined {
  return ((p[key] as string[] | undefined) ?? [])[0]
}

/** Largest icon the server accepts (plan M13a decision 11). */
export const maxIconBytes = 65536

/** Every intent in the order the forms offer them. */
export const softwareIntents: SoftwareIntent[] = ['required', 'uninstall', 'hold', 'forbid', 'available']

/** Every kind of assignment target in the order the form offers them (plan M13b decision 1). */
export const softwareTargets: SoftwareTarget[] = ['organization', 'device_group', 'user', 'user_group']

/** The scopes of a Flatpak application (plan M13b decision 3). */
export const softwareScopes: SoftwareScope[] = ['system', 'user']

/** The kinds of a package source (plan M13b decision 5). */
export const softwareSourceKinds: SoftwareSourceKind[] = ['apt', 'flatpak']

/** Every state a managed application can show on a device (plan M13a decision 32). */
export const softwareStates: DeviceSoftwareState[] = ['installed', 'held', 'absent', 'pending', 'failed', 'not_applicable', 'unknown']

/** The chip of a device's state for an application: installed success, held info, pending warning, failed error. */
export function softwareState(state: DeviceSoftwareState): StatusView {
  const label = 'software.state.' + state
  switch (state) {
    case 'installed':
      return { status: 'ok', label }
    case 'held':
      return { status: 'info', label }
    case 'pending':
      return { status: 'warn', label }
    case 'failed':
      return { status: 'critical', label }
    default:
      return { status: 'neutral', label }
  }
}

/** The filter of the states of a device list. */
export const softwareStateFilter: ListFilter = {
  kind: 'enum', key: 'state', label: 'software.state.label',
  options: softwareStates.map((value) => ({ value, title: 'software.state.' + value })),
}

/** The filter of the intents of an assignment or managed-software list. */
export const softwareIntentFilter: ListFilter = {
  kind: 'enum', key: 'intent', label: 'software.intent.label',
  options: softwareIntents.map((value) => ({ value, title: 'software.intent.' + value })),
}

/** The filter of the scopes of a device list (plan M13b decision 17). */
export const softwareScopeFilter: ListFilter = {
  kind: 'enum', key: 'scope', label: 'software.scope.label',
  options: softwareScopes.map((value) => ({ value, title: 'software.scope.' + value })),
}

/** The filter of the target kinds of an assignment list. */
export const softwareTargetFilter: ListFilter = {
  kind: 'enum', key: 'target', label: 'software.assignments.target',
  options: softwareTargets.map((value) => ({ value, title: 'software.target.' + value })),
}

/** Fingerprint without spaces, uppercase (the server ignores both; plan M13a decision 2). */
export function normalizeFingerprint(text: string): string {
  return text.replace(/\s+/g, '').toUpperCase()
}

/** A fingerprint in blocks of four characters for reading and comparing against the vendor's page. */
export function groupFingerprint(fingerprint: string): string {
  return (normalizeFingerprint(fingerprint).match(/.{1,4}/g) ?? []).join(' ')
}

/** Splits a list typed into one field (whitespace or commas). */
export function splitTokens(text: string): string[] {
  return text.split(/[\s,]+/).filter((t) => t !== '')
}

/** Splits the URI field: one URI per line or separated by spaces (a comma may be part of a path). */
export function splitUris(text: string): string[] {
  return text.split(/\s+/).filter((t) => t !== '')
}

export interface SourceInput {
  kind: SoftwareSourceKind
  slug: string
  name: string
  uris: string[]
  suites: string[]
  components: string[]
  architectures: SoftwareArchitecture[]
  signingKey: string
  fingerprint: string
}

export interface SourceErrors {
  slug?: string
  name?: string
  uris?: string
  suites?: string
  components?: string
  signingKey?: string
  fingerprint?: string
}

const slugPattern = /^[a-z0-9][a-z0-9-]{1,40}$/
const suitePattern = /^[A-Za-z0-9./_-]{1,64}$/
const componentPattern = /^[a-z0-9-]{1,32}$/
const fingerprintPattern = /^[0-9A-F]{40}$/
const maxKeyBytes = 65536

const invisibleInUri = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Variation_Selector}\u{E0000}-\u{E007F}\u115F\u1160\u3164\uFFA0\u2800\uFFFD]/u

/** Whether a source URI passes the rules of bundle.CheckSourceURI: case-sensitive https://, host, no user info, port 1 to 65535. */
function validHttpsUri(uri: string): boolean {
  if (!uri.startsWith('https://') || uri.length > 512 || /[\s?#"<>]/u.test(uri) || invisibleInUri.test(uri)) return false
  let url: URL
  try {
    url = new URL(uri)
  } catch {
    return false
  }
  const authority = uri.slice('https://'.length).split('/')[0]
  return url.hostname !== '' && url.username === '' && url.password === '' && !authority.endsWith(':') && url.port !== '0'
}

/** The repository a URI names, as the server compares URIs: host without case, port 443 equal to none, no trailing slash. */
function uriKey(uri: string): string {
  const url = new URL(uri)
  return url.hostname.toLowerCase() + ':' + url.port + url.pathname.replace(/\/$/, '')
}

function repeats(values: string[]): boolean {
  return new Set(values).size !== values.length
}

/**
 * Message keys of an invalid source. It mirrors the main rules of the server (software.ValidateSource and
 * bundle.CheckSourceURI) so a plain mistake never costs a step-up round trip; the server stays authoritative for the rest
 * (name character classes, the key itself and its policy).
 */
export function validateSource(s: SourceInput, creating: boolean): SourceErrors {
  const out: SourceErrors = {}
  if (creating && !slugPattern.test(s.slug)) out.slug = 'software.sources.slugInvalid'
  const nameLength = [...s.name.trim()].length
  if (nameLength < 1 || nameLength > 100) out.name = 'software.sources.nameInvalid'
  if (s.kind === 'flatpak' && s.uris.length !== 1) out.uris = 'software.sources.flatpakUri'
  else if (s.uris.length < 1 || s.uris.length > 4) out.uris = 'software.sources.urisInvalid'
  else if (s.uris.some((u) => !u.startsWith('https://'))) out.uris = 'software.sources.httpsOnly'
  else if (!s.uris.every(validHttpsUri)) out.uris = 'software.sources.urisInvalid'
  else if (repeats(s.uris.map(uriKey))) out.uris = 'software.sources.repeated'
  if (s.kind !== 'flatpak') validateDistribution(s, out)
  if (s.signingKey.trim() === '' || new TextEncoder().encode(s.signingKey).length > maxKeyBytes) out.signingKey = 'software.sources.keyInvalid'
  if (!fingerprintPattern.test(normalizeFingerprint(s.fingerprint))) out.fingerprint = 'software.sources.fingerprintInvalid'
  return out
}

/** Checks the suites and components of an APT repository; a Flatpak remote has none (plan M13b decision 5). */
function validateDistribution(s: SourceInput, out: SourceErrors): void {
  const flat = s.suites.filter((x) => x.endsWith('/')).length
  if (s.suites.length < 1 || s.suites.length > 8 || !s.suites.every((x) => suitePattern.test(x)) || s.suites.some((x) => x.split('/').includes('..'))) {
    out.suites = 'software.sources.suitesInvalid'
  } else if (repeats(s.suites)) out.suites = 'software.sources.repeated'
  else if (flat !== 0 && flat !== s.suites.length) out.suites = 'software.sources.flatMixed'
  else if (flat > 0 && s.components.length > 0) out.components = 'software.sources.flatComponents'
  else if (flat === 0 && s.components.length === 0) out.components = 'software.sources.componentsRequired'
  if (!out.components && (s.components.length > 8 || !s.components.every((x) => componentPattern.test(x)))) {
    out.components = 'software.sources.componentsInvalid'
  } else if (!out.components && repeats(s.components)) out.components = 'software.sources.repeated'
}

/** One page of package sources for DataList. */
export async function listSoftwareSources(p: ListParams): Promise<Page<SoftwareSourceSummary>> {
  return listPage(
    await api.GET('/api/v1/software-sources', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as SoftwareSourceSort, q: p.q } },
    }),
  )
}

/** A source with its key; the summary list does not carry the key. */
export async function getSoftwareSource(id: string): Promise<SoftwareSource | string> {
  const { data, error } = await api.GET('/api/v1/software-sources/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** A source as the catalog's source selector and filter know it. */
export interface SourceOption {
  id: string
  slug: string
  name: string
  kind: SoftwareSourceKind
}

/** Every source of the organization for the catalog's source selector and filter. */
export async function allSoftwareSources(): Promise<SourceOption[]> {
  const out: SourceOption[] = []
  for (let page = 1; page <= 100; page++) {
    const { data } = await api.GET('/api/v1/software-sources', { params: { query: { page, page_size: 100, sort: 'name' } } })
    out.push(...(data?.items ?? []).map((s) => ({ id: s.id, slug: s.slug, name: s.name, kind: s.kind })))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

/**
 * Creates (id null) or changes a source; null or the problem code (step_up_required, fingerprint_mismatch, in_use…). A change
 * sends the key only together with its fingerprint and only when one of them changed (the server refuses one alone). The
 * kind is fixed after creation, and a Flatpak remote is sent without suites, components and architectures.
 */
export async function saveSoftwareSource(id: string | null, s: SourceInput, keyChanged = true): Promise<string | null> {
  const fingerprint = normalizeFingerprint(s.fingerprint)
  const apt = s.kind !== 'flatpak'
  const distribution = {
    suites: apt ? s.suites : [], components: apt ? s.components : [], architectures: apt ? s.architectures : [],
  }
  const { error } = id
    ? await api.PATCH('/api/v1/software-sources/{id}', {
      params: { path: { id }, header: csrf },
      body: {
        name: s.name.trim(), uris: s.uris, ...distribution,
        ...(keyChanged ? { signing_key: s.signingKey, fingerprint } : {}),
      },
    })
    : await api.POST('/api/v1/software-sources', {
      params: { header: csrf },
      body: { kind: s.kind, slug: s.slug, name: s.name.trim(), uris: s.uris, ...distribution, signing_key: s.signingKey, fingerprint },
    })
  return error ? problemCode(error) : null
}

/** Removes a source; null or the problem code. */
export async function deleteSoftwareSource(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/software-sources/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemCode(error) : null
}

export interface EntryInput {
  name: string
  description: string
  category: string
  sourceID: string | null
  packages: PackageRef[]
  /** required: the users of an available assignment ask an administrator first (plan M13c decision 8). */
  approval: SoftwareApproval
}

export interface EntryErrors {
  name?: string
  description?: string
  category?: string
  /** Count or duplicate of the package rows. */
  packages?: string
  rows: { distribution?: string; release?: string; package?: string; flatpakRef?: string }[]
}

const distributionPattern = /^[a-z][a-z0-9-]{0,31}$/
const releasePattern = /^[a-z0-9][a-z0-9.-]{0,31}$/
const flatpakRefPattern = /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*){2,}$/
const maxFlatpakRefLength = 255

/** An empty package row for the editor: an APT package, or a Flatpak application in system scope for a Flatpak source. */
export function emptyPackageRef(flatpak = false): PackageRef {
  return flatpak
    ? { distribution: 'ubuntu', release: '*', architecture: '*', flatpak_ref: '', scope: 'system' }
    : { distribution: 'ubuntu', release: '*', architecture: '*', package: '' }
}

/**
 * The rows as the server stores them for the chosen source (plan M13b decision 3): an entry of a Flatpak source names
 * Flatpak applications with their scope only, every other entry APT packages only.
 */
export function packagesForSource(packages: PackageRef[], flatpak: boolean): PackageRef[] {
  return packages.map((p) => {
    const base = { distribution: p.distribution, release: p.release, architecture: p.architecture }
    return flatpak ? { ...base, flatpak_ref: p.flatpak_ref ?? '', scope: p.scope ?? 'system' } : { ...base, package: p.package ?? '' }
  })
}

/** Whether text is a Flatpak application ID the server accepts, e.g. org.gimp.GIMP. */
export function validFlatpakRef(text: string): boolean {
  return text.length <= maxFlatpakRefLength && flatpakRefPattern.test(text)
}

/** Message keys of an invalid catalog entry (server: software.ValidateEntry); flatpak when the source is a Flatpak remote. */
export function validateEntry(e: EntryInput, flatpak = false): EntryErrors {
  const out: EntryErrors = { rows: e.packages.map(() => ({})) }
  const nameLength = [...e.name.trim()].length
  if (nameLength < 1 || nameLength > 100) out.name = 'software.catalog.nameInvalid'
  if ([...e.description].length > 1000) out.description = 'software.catalog.descriptionInvalid'
  if ([...e.category.trim()].length > 64) out.category = 'software.catalog.categoryInvalid'
  if (e.packages.length < 1 || e.packages.length > 20) out.packages = 'software.catalog.packagesCount'
  e.packages.forEach((p, i) => {
    if (!distributionPattern.test(p.distribution)) out.rows[i].distribution = 'software.catalog.distributionInvalid'
    if (p.release !== '*' && !releasePattern.test(p.release)) out.rows[i].release = 'software.catalog.releaseInvalid'
    if (flatpak && !validFlatpakRef(p.flatpak_ref ?? '')) out.rows[i].flatpakRef = 'software.catalog.flatpakRefInvalid'
    if (!flatpak && !validPackage(p.package ?? '')) out.rows[i].package = 'software.catalog.packageInvalid'
  })
  const tuples = e.packages.map((p) => [p.distribution, p.release, p.architecture].join('\u0000'))
  if (!out.packages && new Set(tuples).size !== tuples.length) out.packages = 'software.catalog.packagesDuplicate'
  return out
}

/** Whether an entry validation found anything. */
export function entryHasErrors(e: EntryErrors): boolean {
  return !!(e.name || e.description || e.category || e.packages || e.rows.some((r) => r.distribution || r.release || r.package || r.flatpakRef))
}

/** One page of catalog entries for DataList. */
export async function listSoftwareCatalog(p: ListParams): Promise<Page<SoftwareCatalogEntry>> {
  return listPage(
    await api.GET('/api/v1/software-catalog', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as SoftwareCatalogSort, q: p.q,
          category: first(p, 'category'), source_id: first(p, 'source_id'),
        },
      },
    }),
  )
}

/** The distinct categories of the catalog (the filter's options); empty when the list cannot be read. */
export async function catalogCategories(): Promise<string[]> {
  const out = new Set<string>()
  for (let page = 1; page <= 100; page++) {
    const { data } = await api.GET('/api/v1/software-catalog', { params: { query: { page, page_size: 100, sort: 'name' } } })
    for (const e of data?.items ?? []) if (e.category !== '') out.add(e.category)
    if (!data || page * data.page_size >= data.total) break
  }
  return [...out].sort((a, b) => a.localeCompare(b))
}

/** One catalog entry, or the problem code. */
export async function getCatalogEntry(id: string): Promise<SoftwareCatalogEntry | string> {
  const { data, error } = await api.GET('/api/v1/software-catalog/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Creates (id null) or changes a catalog entry; null or the problem code. */
export async function saveCatalogEntry(id: string | null, e: EntryInput): Promise<string | null> {
  const body = {
    name: e.name.trim(), description: e.description, category: e.category.trim(), source_id: e.sourceID, packages: e.packages,
    approval: e.approval,
  }
  const { error } = id
    ? await api.PATCH('/api/v1/software-catalog/{id}', { params: { path: { id }, header: csrf }, body })
    : await api.POST('/api/v1/software-catalog', { params: { header: csrf }, body })
  return error ? problemCode(error) : null
}

/** Deletes a catalog entry with its assignments; null or the problem code. */
export async function deleteCatalogEntry(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/software-catalog/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemCode(error) : null
}

/** The URL of an entry's icon (same origin, session cookie); version busts the browser cache after an upload. */
export function iconUrl(id: string, version = 0): string {
  return `/api/v1/software-catalog/${id}/icon` + (version > 0 ? `?v=${version}` : '')
}

/** Message key of a file the icon upload refuses before the request, or null when it may be sent. */
export function iconFileProblem(file: { type: string; size: number }): string | null {
  if (file.type !== 'image/png') return 'software.icon.notPng'
  if (file.size > maxIconBytes) return 'software.icon.tooLarge'
  return null
}

/** Uploads the PNG icon of an entry; null or the problem code. */
export async function setCatalogIcon(id: string, file: File): Promise<string | null> {
  const { error } = await api.PUT('/api/v1/software-catalog/{id}/icon', {
    params: { path: { id }, header: csrf },
    // The generated type models the binary body as a string; the file is sent as it is.
    body: file as unknown as string,
    bodySerializer: (body) => body as BodyInit,
    headers: { 'Content-Type': 'image/png' },
  })
  return error ? problemCode(error) : null
}

export interface AssignmentInput {
  entryID: string
  /** What the assignment applies to; targetID names the device group, user or user group, null for the organization. */
  target: SoftwareTarget
  targetID: string | null
  intent: SoftwareIntent
  updateRule: SoftwareUpdateRule
  version: string
  reason: string
  /**
   * The devices apply the assignment outside their maintenance windows (plan M13c decision 7): it needs a reason of
   * 2 to 500 characters and a fresh step-up.
   */
  urgent: boolean
}

/** Whether the update rule can be chosen: only a required application is either latest or pinned (plan M13a decision 9). */
export function updateRuleEnabled(intent: SoftwareIntent): boolean {
  return intent === 'required'
}

/** Whether a version can be given: a pinned requirement and a hold; uninstall, forbid and required latest carry none. */
export function versionEnabled(intent: SoftwareIntent, rule: SoftwareUpdateRule): boolean {
  return intent === 'hold' || (intent === 'required' && rule === 'pinned')
}

/** The input as the server expects it: no version and the rule latest where the intent allows neither. */
export function normalizeAssignment(a: AssignmentInput): AssignmentInput {
  const updateRule = updateRuleEnabled(a.intent) ? a.updateRule : 'latest'
  const version = versionEnabled(a.intent, updateRule) ? a.version.trim() : ''
  return { ...a, updateRule, version }
}

/** The kind of target of a stored assignment; at most one of its target IDs is set (plan M13b decision 1). */
export function assignmentTarget(a: Pick<SoftwareAssignment, 'device_group_id' | 'user_id' | 'user_group_id'>): { target: SoftwareTarget; targetID: string | null } {
  if (a.device_group_id) return { target: 'device_group', targetID: a.device_group_id }
  if (a.user_id) return { target: 'user', targetID: a.user_id }
  if (a.user_group_id) return { target: 'user_group', targetID: a.user_group_id }
  return { target: 'organization', targetID: null }
}

/** Message keys of an invalid assignment. */
export function validateAssignment(input: AssignmentInput): { target?: string; version?: string; reason?: string } {
  const a = normalizeAssignment(input)
  const out: { target?: string; version?: string; reason?: string } = {}
  if (a.target !== 'organization' && !a.targetID) out.target = 'software.assignments.targetRequired'
  if (a.intent === 'required' && a.updateRule === 'pinned' && a.version === '') out.version = 'software.assignments.versionRequired'
  else if (a.version !== '' && !validPackageVersion(a.version)) out.version = 'software.assignments.versionInvalid'
  if ([...a.reason].length > 500) out.reason = 'software.assignments.reasonInvalid'
  else if (a.urgent && [...a.reason.trim()].length < urgentReasonMin) out.reason = 'software.assignments.urgentReasonRequired'
  return out
}

/** One page of the assignments of an entry for DataList. */
export function listSoftwareAssignments(entryID: string): (p: ListParams) => Promise<Page<SoftwareAssignment>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/software-assignments', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as SoftwareAssignmentSort, q: p.q, catalog_entry_id: entryID,
            intent: first(p, 'intent') as SoftwareIntent | undefined, target: first(p, 'target') as SoftwareTarget | undefined,
          },
        },
      }),
    )
}

/** Every assignment of an entry (at most the list contract's depth), to name the assignment a compile warning concerns. */
export async function allSoftwareAssignments(entryID: string): Promise<SoftwareAssignment[]> {
  const out: SoftwareAssignment[] = []
  for (let page = 1; page <= 100; page++) {
    const { data } = await api.GET('/api/v1/software-assignments', {
      params: { query: { page, page_size: 100, sort: '-created_at', catalog_entry_id: entryID } },
    })
    out.push(...(data?.items ?? []))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

/**
 * Creates (id null) or changes an assignment; null or the problem code. The entry and the target of an assignment are
 * fixed. An urgent assignment the server refuses with step_up_required is repeated by the page after the step-up.
 */
export async function saveSoftwareAssignment(id: string | null, input: AssignmentInput): Promise<string | null> {
  const a = normalizeAssignment(input)
  const version = a.version === '' ? null : a.version
  const { error } = id
    ? await api.PATCH('/api/v1/software-assignments/{id}', {
      params: { path: { id }, header: csrf },
      body: { intent: a.intent, update_rule: a.updateRule, version, reason: a.reason, urgent: a.urgent },
    })
    : await api.POST('/api/v1/software-assignments', {
      params: { header: csrf },
      body: {
        catalog_entry_id: a.entryID,
        device_group_id: a.target === 'device_group' ? a.targetID : null,
        user_id: a.target === 'user' ? a.targetID : null,
        user_group_id: a.target === 'user_group' ? a.targetID : null,
        intent: a.intent, update_rule: a.updateRule, version, reason: a.reason, urgent: a.urgent,
      },
    })
  return error ? problemCode(error) : null
}

/** The names an assignment's natural key uses: the device group's name, the user's username, the user group's slug. */
export interface TargetNames {
  groups: { id: string; name: string }[]
  users: { id: string; username: string }[]
  userGroups: { id: string; slug?: string }[]
}

/**
 * The parts of an assignment's natural key as plans show it (declarative SoftwareAssignment.Key): the device group or
 * null, the entry's name, the target type and the username or user group slug or null. Null when a name is unknown.
 */
export function assignmentKeyParts(a: SoftwareAssignment, names: TargetNames): unknown[] | null {
  const { target, targetID } = assignmentTarget(a)
  switch (target) {
    case 'device_group': {
      const group = names.groups.find((g) => g.id === targetID)?.name
      return group ? [group, a.app_name, target, null] : null
    }
    case 'user': {
      const user = names.users.find((u) => u.id === targetID)?.username
      return user ? [null, a.app_name, target, user] : null
    }
    case 'user_group': {
      const slug = names.userGroups.find((g) => g.id === targetID)?.slug
      return slug ? [null, a.app_name, target, slug] : null
    }
    default:
      return [null, a.app_name, target, null]
  }
}

/** The open rollout that stages a change of the assignment, or null (the chip on the assignment list). */
export function stagingRollout(a: SoftwareAssignment, staged: StagedKey[], names: TargetNames): string | null {
  const parts = assignmentKeyParts(a, names)
  if (!parts) return null
  const hit = staged.find((k) => k.parts.length === parts.length && k.parts.every((p, i) => p === parts[i]))
  return hit?.rolloutID ?? null
}

/** Removes an assignment; null or the problem code. */
export async function deleteSoftwareAssignment(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/software-assignments/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemCode(error) : null
}

/** A row of a list that names a device or entry once per scope; row_key tells the rows apart (plan M13b decision 17). */
export type ScopedRow<T> = T & { row_key: string }

function withRowKey<T extends { scope: SoftwareScope }>(page: Page<T>, id: (item: T) => string): Page<ScopedRow<T>> {
  return { ...page, items: page.items.map((item) => ({ ...item, row_key: id(item) + ':' + item.scope })) }
}

/** One page of the devices an entry is assigned to, with their state, for DataList. */
export function listSoftwareCatalogDevices(entryID: string): (p: ListParams) => Promise<Page<ScopedRow<SoftwareCatalogDevice>>> {
  return async (p) =>
    withRowKey(
      listPage(
        await api.GET('/api/v1/software-catalog/{id}/devices', {
          params: {
            path: { id: entryID },
            query: {
              page: p.page, page_size: p.page_size, sort: p.sort as SoftwareCatalogDeviceSort, q: p.q,
              state: first(p, 'state') as DeviceSoftwareState | undefined, device_group_id: first(p, 'device_group_id'),
              scope: first(p, 'scope') as SoftwareScope | undefined,
            },
          },
        }),
      ),
      (d) => d.device_id,
    )
}

/**
 * One page of the managed software of a device for DataList. onTruncated receives whether the device's last report
 * left items out (the page then says so).
 */
export function listDeviceManagedSoftware(
  deviceID: string, onTruncated: (truncated: boolean) => void,
): (p: ListParams) => Promise<Page<ScopedRow<DeviceManagedSoftware>>> {
  return async (p) => {
    const res = await api.GET('/api/v1/devices/{id}/managed-software', {
      params: {
        path: { id: deviceID },
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as DeviceManagedSoftwareSort, q: p.q,
          state: first(p, 'state') as DeviceSoftwareState | undefined, intent: first(p, 'intent') as SoftwareIntent | undefined,
          scope: first(p, 'scope') as SoftwareScope | undefined,
        },
      },
    })
    const page = listPage(res)
    onTruncated(res.data?.truncated ?? false)
    return withRowKey(page, (m) => m.catalog_entry_id)
  }
}

/** One page of the software assignments that target a user directly or through a user group (plan M13b decision 6). */
export function listUserSoftware(userID: string): (p: ListParams) => Promise<Page<UserSoftware>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/users/{id}/software', {
        params: {
          path: { id: userID },
          query: { page: p.page, page_size: p.page_size, sort: p.sort as UserSoftwareSort, q: p.q, intent: first(p, 'intent') as SoftwareIntent | undefined },
        },
      }),
    )
}

/** The codes of compile warnings the portal names (architect decisions A10-9, A10-10, A10-11); the list may grow. */
export const compileWarningCodes = ['audience_truncated', 'flatpak_forbidden', 'flatpak_users_truncated'] as const

/** The filter of the codes of a compile-warning list. */
export const compileWarningCodeFilter: ListFilter = {
  kind: 'enum', key: 'code', label: 'software.compileWarnings.code',
  options: compileWarningCodes.map((value) => ({ value, title: 'software.compileWarnings.codes.' + value })),
}

/**
 * The message key and arguments of a compile warning. A code this portal does not know yet is shown with the generic
 * text and its code, never dropped, because the server's list of codes may grow.
 */
export function compileWarningMessage(w: Pick<CompileWarning, 'code' | 'params'>): { key: string; args: Record<string, string | number> } {
  const args: Record<string, string | number> = { code: w.code }
  for (const [k, v] of Object.entries(w.params ?? {})) {
    if (typeof v === 'string' || typeof v === 'number') args[k] = v
  }
  return (compileWarningCodes as readonly string[]).includes(w.code)
    ? { key: 'software.compileWarnings.text.' + w.code, args }
    : { key: 'software.compileWarnings.text.unknown', args }
}

/** One page of the compile warnings of a device or of a catalog entry for DataList. */
export function listCompileWarnings(filter: { deviceID?: string; catalogEntryID?: string }): (p: ListParams) => Promise<Page<CompileWarning>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/compile-warnings', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as CompileWarningSort, q: p.q, code: first(p, 'code'),
            device_id: filter.deviceID, catalog_entry_id: filter.catalogEntryID,
          },
        },
      }),
    )
}
