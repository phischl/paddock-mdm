import {
  api, listPage, problemCode, type Attention, type AttentionKind, type AttentionSort, type DeviceCommand,
  type DeviceUpdates, type PackageHold, type PackageHoldSort, type UpdateSettings, type UpdateSettingsUpdate,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** The update settings of the organization (plan M5b decisions 1 and 9). */
export async function getUpdateSettings(): Promise<UpdateSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/updates')
  return data ?? problemCode(error)
}

/** Replaces the update settings; the saved settings or the problem code. */
export async function saveUpdateSettings(s: UpdateSettingsUpdate): Promise<UpdateSettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/updates', { params: { header: csrf }, body: s })
  return data ?? problemCode(error)
}

const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
const timeOfDay = /^([01][0-9]|2[0-3]):[0-5][0-9]$/

/** A time of day HH:MM (the server's rule, pkg/bundle ValidTimeOfDay). */
export function validTimeOfDay(s: string): boolean {
  return timeOfDay.test(s)
}

/** The schedule subset the server accepts (pkg/bundle ValidSchedule): optional distinct weekdays, then HH:MM. */
export function validSchedule(s: string): boolean {
  const parts = s.split(' ')
  if (parts.length === 1) return validTimeOfDay(s)
  if (parts.length !== 2 || !validTimeOfDay(parts[1])) return false
  const days = parts[0].split(',')
  return days.every((d) => weekdays.includes(d)) && new Set(days).size === days.length
}

/** Limits of the settings (server: domain/updates). */
export const maxRandomDelayMin = 720
export const maxWarningH = 720
export const maxCriticalH = 2160

export interface SettingsErrors {
  security_daily_at?: string
  regular_schedule?: string
  max_random_delay_min?: string
  staleness_warning_h?: string
  staleness_critical_h?: string
}

/** Message keys of invalid settings. */
export function validateSettings(s: UpdateSettingsUpdate): SettingsErrors {
  const out: SettingsErrors = {}
  if (!validTimeOfDay(s.security_daily_at)) out.security_daily_at = 'updates.settings.timeInvalid'
  if (!validSchedule(s.regular_schedule)) out.regular_schedule = 'updates.settings.scheduleInvalid'
  if (!Number.isInteger(s.max_random_delay_min) || s.max_random_delay_min < 0 || s.max_random_delay_min > maxRandomDelayMin) {
    out.max_random_delay_min = 'updates.settings.delayInvalid'
  }
  if (!Number.isInteger(s.staleness_warning_h) || s.staleness_warning_h < 1 || s.staleness_warning_h > maxWarningH) {
    out.staleness_warning_h = 'updates.settings.warningInvalid'
  }
  if (!Number.isInteger(s.staleness_critical_h) || s.staleness_critical_h <= s.staleness_warning_h || s.staleness_critical_h > maxCriticalH) {
    out.staleness_critical_h = 'updates.settings.criticalInvalid'
  }
  return out
}

const packageName = /^[a-z0-9][a-z0-9+.-]+$/
const packageVersion = /^[A-Za-z0-9.+:~-]+$/

/** A Debian package name (pkg/bundle ValidPackage). */
export function validPackage(name: string): boolean {
  return name.length <= 128 && packageName.test(name)
}

/** A Debian package version (pkg/bundle ValidPackageVersion). */
export function validPackageVersion(v: string): boolean {
  return v.length <= 128 && packageVersion.test(v)
}

function groupParam(p: ListParams): string | undefined {
  return ((p.device_group_id as string[] | undefined) ?? [])[0]
}

/** One page of package holds for DataList. */
export async function listPackageHolds(p: ListParams): Promise<Page<PackageHold>> {
  return listPage(
    await api.GET('/api/v1/package-holds', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as PackageHoldSort, q: p.q, device_group_id: groupParam(p) } },
    }),
  )
}

export interface HoldInput {
  groupID: string | null
  package: string
  version: string
  reason: string
}

/** Message keys of an invalid hold. */
export function validateHold(h: HoldInput): { package?: string; version?: string; reason?: string } {
  const out: { package?: string; version?: string; reason?: string } = {}
  if (!validPackage(h.package)) out.package = 'updates.holds.packageInvalid'
  if (h.version !== '' && !validPackageVersion(h.version)) out.version = 'updates.holds.versionInvalid'
  if ([...h.reason].length > 500) out.reason = 'updates.holds.reasonInvalid'
  return out
}

/** Creates (id null) or changes a hold; null or the problem code. The package and the scope of a hold are fixed. */
export async function savePackageHold(id: string | null, h: HoldInput): Promise<string | null> {
  const version = h.version === '' ? null : h.version
  const { error } = id
    ? await api.PATCH('/api/v1/package-holds/{id}', { params: { path: { id }, header: csrf }, body: { version, reason: h.reason } })
    : await api.POST('/api/v1/package-holds', {
      params: { header: csrf },
      body: { package: h.package, version, reason: h.reason, ...(h.groupID ? { device_group_id: h.groupID } : {}) },
    })
  return error ? problemCode(error) : null
}

/** Removes a hold; null or the problem code. */
export async function deletePackageHold(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/package-holds/{id}', { params: { path: { id }, header: csrf } })
  return error ? problemCode(error) : null
}

/** Splits the packages of the install-now dialog (spaces, commas or lines). */
export function parsePackages(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter((p) => p !== ''))]
}

/** At most this many packages per install-now request. */
export const maxInstallPackages = 20

/** Issues install_now to a device; the command or the problem code (package_on_hold names the package). */
export async function installNow(deviceID: string, packages: string[]): Promise<DeviceCommand | { problem: string; detail?: string }> {
  const { data, error } = await api.POST('/api/v1/devices/{id}/install-now', { params: { path: { id: deviceID }, header: csrf }, body: { packages } })
  return data ?? { problem: problemCode(error), detail: problemDetail(error) }
}

/** Issues install_now to the active devices of a group; the number of commands or the problem code. */
export async function installNowGroup(groupID: string, packages: string[]): Promise<number | { problem: string; detail?: string }> {
  const { data, error } = await api.POST('/api/v1/device-groups/{id}/install-now', { params: { path: { id: groupID }, header: csrf }, body: { packages } })
  return data ? data.commands : { problem: problemCode(error), detail: problemDetail(error) }
}

function problemDetail(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'detail' in error && typeof error.detail === 'string' ? error.detail : undefined
}

/** The update state of a device (plan M5b decision 12). */
export async function getDeviceUpdates(deviceID: string): Promise<DeviceUpdates | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}/updates', { params: { path: { id: deviceID } } })
  return data ?? problemCode(error)
}

/** The attention kinds in the order the filter offers them. */
export const attentionKinds: AttentionKind[] = [
  'presumed_lost', 'stale_critical', 'stale_warning', 'quarantined', 'revocation_pending', 'revocation_expired',
  'disk_not_compliant', 'login_apply_failed', 'sudo_apply_failed', 'agent_outdated',
]

export const attentionFilter: ListFilter = {
  kind: 'enum', key: 'kind', label: 'attention.kind',
  options: attentionKinds.map((value) => ({ value, title: 'attention.kinds.' + value })),
}

/** One page of the attention list for DataList. */
export async function listAttention(p: ListParams): Promise<Page<Attention>> {
  return listPage(
    await api.GET('/api/v1/attention', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as AttentionSort, q: p.q, kind: p.kind as AttentionKind[] } },
    }),
  )
}

/** The number of open conditions (navigation badge, landing page); 0 when the list cannot be read. */
export async function attentionCount(): Promise<number> {
  const { data } = await api.GET('/api/v1/attention', { params: { query: { page_size: 10 } } })
  return data?.total ?? 0
}
