import {
  api, listPage, problemCode, type DeviceManagedSoftware, type DeviceManagedSoftwareSort, type DeviceSoftwareState, type PackageRef,
  type SoftwareArchitecture, type SoftwareAssignment, type SoftwareAssignmentSort, type SoftwareCatalogDevice,
  type SoftwareCatalogDeviceSort, type SoftwareCatalogEntry, type SoftwareCatalogSort, type SoftwareIntent, type SoftwareSource,
  type SoftwareSourceSort, type SoftwareSourceSummary, type SoftwareUpdateRule,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'
import { validPackage, validPackageVersion } from './updates'

const csrf = { 'X-Paddock-CSRF': '1' } as const

function first(p: ListParams, key: string): string | undefined {
  return ((p[key] as string[] | undefined) ?? [])[0]
}

/** Largest icon the server accepts (plan M13a decision 11). */
export const maxIconBytes = 65536

/** Every intent in the order the forms offer them. */
export const softwareIntents: SoftwareIntent[] = ['required', 'uninstall', 'hold', 'forbid']

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
  if (s.uris.length < 1 || s.uris.length > 4) out.uris = 'software.sources.urisInvalid'
  else if (s.uris.some((u) => !u.startsWith('https://'))) out.uris = 'software.sources.httpsOnly'
  else if (!s.uris.every(validHttpsUri)) out.uris = 'software.sources.urisInvalid'
  else if (repeats(s.uris.map(uriKey))) out.uris = 'software.sources.repeated'
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
  if (s.signingKey.trim() === '' || new TextEncoder().encode(s.signingKey).length > maxKeyBytes) out.signingKey = 'software.sources.keyInvalid'
  if (!fingerprintPattern.test(normalizeFingerprint(s.fingerprint))) out.fingerprint = 'software.sources.fingerprintInvalid'
  return out
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

/** Every source of the organization (id, slug, name) for the catalog's source selector and filter. */
export async function allSoftwareSources(): Promise<{ id: string; slug: string; name: string }[]> {
  const out: { id: string; slug: string; name: string }[] = []
  for (let page = 1; page <= 100; page++) {
    const { data } = await api.GET('/api/v1/software-sources', { params: { query: { page, page_size: 100, sort: 'name' } } })
    out.push(...(data?.items ?? []).map((s) => ({ id: s.id, slug: s.slug, name: s.name })))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

/**
 * Creates (id null) or changes a source; null or the problem code (step_up_required, fingerprint_mismatch, in_use…). A change
 * sends the key only together with its fingerprint and only when one of them changed (the server refuses one alone).
 */
export async function saveSoftwareSource(id: string | null, s: SourceInput, keyChanged = true): Promise<string | null> {
  const fingerprint = normalizeFingerprint(s.fingerprint)
  const { error } = id
    ? await api.PATCH('/api/v1/software-sources/{id}', {
      params: { path: { id }, header: csrf },
      body: {
        name: s.name.trim(), uris: s.uris, suites: s.suites, components: s.components, architectures: s.architectures,
        ...(keyChanged ? { signing_key: s.signingKey, fingerprint } : {}),
      },
    })
    : await api.POST('/api/v1/software-sources', {
      params: { header: csrf },
      body: {
        slug: s.slug, name: s.name.trim(), uris: s.uris, suites: s.suites, components: s.components, architectures: s.architectures,
        signing_key: s.signingKey, fingerprint,
      },
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
}

export interface EntryErrors {
  name?: string
  description?: string
  category?: string
  /** Count or duplicate of the package rows. */
  packages?: string
  rows: { distribution?: string; release?: string; package?: string }[]
}

const distributionPattern = /^[a-z][a-z0-9-]{0,31}$/
const releasePattern = /^[a-z0-9][a-z0-9.-]{0,31}$/

/** An empty package row for the editor. */
export function emptyPackageRef(): PackageRef {
  return { distribution: 'ubuntu', release: '*', architecture: '*', package: '' }
}

/** Message keys of an invalid catalog entry (server: software.ValidateEntry). */
export function validateEntry(e: EntryInput): EntryErrors {
  const out: EntryErrors = { rows: e.packages.map(() => ({})) }
  const nameLength = [...e.name.trim()].length
  if (nameLength < 1 || nameLength > 100) out.name = 'software.catalog.nameInvalid'
  if ([...e.description].length > 1000) out.description = 'software.catalog.descriptionInvalid'
  if ([...e.category.trim()].length > 64) out.category = 'software.catalog.categoryInvalid'
  if (e.packages.length < 1 || e.packages.length > 20) out.packages = 'software.catalog.packagesCount'
  e.packages.forEach((p, i) => {
    if (!distributionPattern.test(p.distribution)) out.rows[i].distribution = 'software.catalog.distributionInvalid'
    if (p.release !== '*' && !releasePattern.test(p.release)) out.rows[i].release = 'software.catalog.releaseInvalid'
    if (!validPackage(p.package ?? '')) out.rows[i].package = 'software.catalog.packageInvalid'
  })
  const tuples = e.packages.map((p) => [p.distribution, p.release, p.architecture].join('\u0000'))
  if (!out.packages && new Set(tuples).size !== tuples.length) out.packages = 'software.catalog.packagesDuplicate'
  return out
}

/** Whether an entry validation found anything. */
export function entryHasErrors(e: EntryErrors): boolean {
  return !!(e.name || e.description || e.category || e.packages || e.rows.some((r) => r.distribution || r.release || r.package))
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
  groupID: string | null
  intent: SoftwareIntent
  updateRule: SoftwareUpdateRule
  version: string
  reason: string
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

/** Message keys of an invalid assignment. */
export function validateAssignment(input: AssignmentInput): { version?: string; reason?: string } {
  const a = normalizeAssignment(input)
  const out: { version?: string; reason?: string } = {}
  if (a.intent === 'required' && a.updateRule === 'pinned' && a.version === '') out.version = 'software.assignments.versionRequired'
  else if (a.version !== '' && !validPackageVersion(a.version)) out.version = 'software.assignments.versionInvalid'
  if ([...a.reason].length > 500) out.reason = 'software.assignments.reasonInvalid'
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
            intent: first(p, 'intent') as SoftwareIntent | undefined,
          },
        },
      }),
    )
}

/** Creates (id null) or changes an assignment; null or the problem code. The entry and the scope of an assignment are fixed. */
export async function saveSoftwareAssignment(id: string | null, input: AssignmentInput): Promise<string | null> {
  const a = normalizeAssignment(input)
  const version = a.version === '' ? null : a.version
  const { error } = id
    ? await api.PATCH('/api/v1/software-assignments/{id}', {
      params: { path: { id }, header: csrf },
      body: { intent: a.intent, update_rule: a.updateRule, version, reason: a.reason },
    })
    : await api.POST('/api/v1/software-assignments', {
      params: { header: csrf },
      body: {
        catalog_entry_id: a.entryID, device_group_id: a.groupID, intent: a.intent, update_rule: a.updateRule, version, reason: a.reason,
      },
    })
  return error ? problemCode(error) : null
}

/** Removes an assignment; null or the problem code. */
export async function deleteSoftwareAssignment(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/software-assignments/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemCode(error) : null
}

/** One page of the devices an entry is assigned to, with their state, for DataList. */
export function listSoftwareCatalogDevices(entryID: string): (p: ListParams) => Promise<Page<SoftwareCatalogDevice>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/software-catalog/{id}/devices', {
        params: {
          path: { id: entryID },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as SoftwareCatalogDeviceSort, q: p.q,
            state: first(p, 'state') as DeviceSoftwareState | undefined, device_group_id: first(p, 'device_group_id'),
          },
        },
      }),
    )
}

/**
 * One page of the managed software of a device for DataList. onTruncated receives whether the device's last report
 * left items out (the page then says so).
 */
export function listDeviceManagedSoftware(deviceID: string, onTruncated: (truncated: boolean) => void): (p: ListParams) => Promise<Page<DeviceManagedSoftware>> {
  return async (p) => {
    const res = await api.GET('/api/v1/devices/{id}/managed-software', {
      params: {
        path: { id: deviceID },
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as DeviceManagedSoftwareSort, q: p.q,
          state: first(p, 'state') as DeviceSoftwareState | undefined, intent: first(p, 'intent') as SoftwareIntent | undefined,
        },
      },
    })
    const page = listPage(res)
    onTruncated(res.data?.truncated ?? false)
    return page
  }
}
