import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'
import type { ReviewSection } from './accessReview'
import type { KpiCell } from './overview'

/** The patch compliance report of the organization (plan M13c decision 18). */
export type PatchComplianceReport = components['schemas']['PatchComplianceReport']
/** The organization's patch SLA (plan M13c decision 17). */
export type PatchSlaSettings = components['schemas']['PatchSlaSettings']
/** The body of a patch SLA change. */
export type PatchSlaSettingsUpdate = components['schemas']['PatchSlaSettingsUpdate']

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** The bounds of every SLA value (the server's rule); 0 means the severity has no SLA. */
export const slaDaysMin = 0
export const slaDaysMax = 365

/** The fields of the SLA, most severe first. */
export const slaFields = ['critical_days', 'high_days', 'medium_days', 'low_days'] as const

/** Whether a number of days is a valid SLA value. */
export function validSlaDays(days: number): boolean {
  return Number.isInteger(days) && days >= slaDaysMin && days <= slaDaysMax
}

/** The patch SLA; the problem code on failure. */
export async function getPatchSla(): Promise<PatchSlaSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/patch-sla')
  return data ?? problemCode(error)
}

/** Replaces the patch SLA; the saved SLA or the problem code. */
export async function savePatchSla(s: PatchSlaSettingsUpdate): Promise<PatchSlaSettings | string> {
  const { data, error } = await api.PUT('/api/v1/settings/patch-sla', { params: { header: csrf }, body: s })
  return data ?? problemCode(error)
}

/** The report, the state at its generation, for all devices or one device group; the problem code on failure. */
export async function getPatchCompliance(group: string): Promise<PatchComplianceReport | string> {
  const { data, error } = await api.GET('/api/v1/patch-compliance', {
    params: { query: group ? { device_group_id: group } : {} },
  })
  return data ?? problemCode(error)
}

/** The URL of an export; the browser fetches it with the session cookie and names the file after the response. */
export function patchExportUrl(group: string, format: 'json' | 'csv'): string {
  const query: Record<string, string> = { format }
  if (group) query.device_group_id = group
  return '/api/v1/patch-compliance/export?' + new URLSearchParams(query).toString()
}

/**
 * The tables of the report page: severities, device groups, one row per breached finding and the pinned required
 * catalog assignments. severity turns a severity into its label. The breach rows are all the API returned; the page
 * states the device cap itself.
 */
export function patchSections(r: PatchComplianceReport, severity: (s: string) => string): ReviewSection[] {
  const empty = { title: 'patchCompliance.emptySection.title', description: 'patchCompliance.emptySection.description' }
  const breaches = r.devices.flatMap((d) =>
    d.breached.map((b) => ({
      hostname: d.hostname, cve: b.cve, package: b.package, severity: severity(b.severity), days_open: b.days_open,
      sla_days: b.sla_days, fixed_version: b.fixed_version,
    })),
  )
  return [
    {
      key: 'severity',
      title: 'patchCompliance.sections.severity',
      total: r.by_severity.length,
      rows: r.by_severity.map((s) => ({ ...s, severity: severity(s.severity) })),
      columns: [
        { key: 'severity', title: 'patchCompliance.columns.severity', role: 'primary' },
        { key: 'findings_open', title: 'patchCompliance.columns.findingsOpen', sortable: true, role: 'meta', align: 'end' },
        { key: 'findings_breached', title: 'patchCompliance.columns.findingsBreached', sortable: true, role: 'meta', align: 'end' },
        { key: 'median_days_open', title: 'patchCompliance.columns.medianDaysOpen', sortable: true, role: 'meta', align: 'end' },
        { key: 'p90_days_open', title: 'patchCompliance.columns.p90DaysOpen', sortable: true, role: 'meta', align: 'end' },
      ],
      defaultSort: '-findings_breached',
      empty,
    },
    {
      key: 'groups',
      title: 'patchCompliance.sections.groups',
      total: r.by_group.length,
      rows: r.by_group.map((g) => ({ device_group: g.device_group, devices: g.devices, breached: g.breached })),
      columns: [
        { key: 'device_group', title: 'patchCompliance.columns.deviceGroup', sortable: true, role: 'primary' },
        { key: 'devices', title: 'patchCompliance.columns.devices', sortable: true, role: 'meta', align: 'end' },
        { key: 'breached', title: 'patchCompliance.columns.breachedDevices', sortable: true, role: 'meta', align: 'end' },
      ],
      defaultSort: 'device_group',
      empty,
    },
    {
      key: 'breaches',
      title: 'patchCompliance.sections.breaches',
      total: breaches.length,
      rows: breaches,
      columns: [
        { key: 'hostname', title: 'patchCompliance.columns.hostname', sortable: true, role: 'primary' },
        { key: 'cve', title: 'patchCompliance.columns.cve', sortable: true, role: 'meta', mono: true },
        { key: 'package', title: 'patchCompliance.columns.package', sortable: true, role: 'meta' },
        { key: 'severity', title: 'patchCompliance.columns.severity', sortable: true, role: 'meta' },
        { key: 'days_open', title: 'patchCompliance.columns.daysOpen', sortable: true, role: 'meta', align: 'end' },
        { key: 'sla_days', title: 'patchCompliance.columns.slaDays', sortable: true, role: 'meta', align: 'end', hideBelow: 'md' },
        { key: 'fixed_version', title: 'patchCompliance.columns.fixedVersion', role: 'meta', mono: true, hideBelow: 'md' },
      ],
      defaultSort: '-days_open',
      empty,
    },
    {
      key: 'catalog',
      title: 'patchCompliance.sections.catalog',
      total: r.catalog.length,
      rows: r.catalog.map((c) => ({ entry: c.entry, required_version: c.required_version, devices_behind: c.devices_behind })),
      columns: [
        { key: 'entry', title: 'patchCompliance.columns.entry', sortable: true, role: 'primary' },
        { key: 'required_version', title: 'patchCompliance.columns.requiredVersion', role: 'meta', mono: true },
        { key: 'devices_behind', title: 'patchCompliance.columns.devicesBehind', sortable: true, role: 'meta', align: 'end' },
      ],
      defaultSort: '-devices_behind',
      empty,
    },
  ]
}

/** The cards of the report: devices in scope, compliant, breached and the SLA the report used (linked to its form). */
export function patchCells(r: PatchComplianceReport): KpiCell[] {
  const s = r.summary
  return [
    { key: 'devices', label: 'patchCompliance.cards.devices', value: s.devices, note: 'patchCompliance.cards.devicesNote', noteValues: {}, status: 'neutral' },
    { key: 'compliant', label: 'patchCompliance.cards.compliant', value: s.compliant, note: 'patchCompliance.cards.compliantNote', noteValues: {}, status: 'ok' },
    {
      key: 'breached', label: 'patchCompliance.cards.breached', value: s.breached, note: 'patchCompliance.cards.breachedNote',
      noteValues: { findings: r.by_severity.reduce((sum, x) => sum + x.findings_breached, 0) }, status: s.breached > 0 ? 'critical' : 'ok',
    },
    {
      key: 'sla', label: 'patchCompliance.cards.sla', value: slaFields.map((f) => r.sla[f]).join(' / '), note: 'patchCompliance.cards.slaNote',
      noteValues: {}, status: 'info', to: '/settings/patch-sla',
    },
  ]
}
