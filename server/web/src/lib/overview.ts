import type { RouteLocationRaw } from 'vue-router'
import {
  api, listPage, problemCode, type AttentionDevice, type AuditEvent, type Overview, type OverviewSeverityBuckets,
} from '../api/client'
import type { Page } from './listQuery'
import type { Status } from './status'

/** The overview of the caller's organization (plan M7c decision 26); a problem code when it cannot be read. */
export async function getOverview(): Promise<Overview | string> {
  const { data, error } = await api.GET('/api/v1/overview')
  return data ?? problemCode(error)
}

/** The first page of the attention list grouped by device, most severe first. */
export async function overviewAttention(): Promise<Page<AttentionDevice>> {
  return listPage(await api.GET('/api/v1/attention/devices', { params: { query: { page_size: 10, sort: '-severity' } } }))
}

/** The newest audit events (readers of the audit log only). */
export async function recentAuditEvents(): Promise<Page<AuditEvent>> {
  return listPage(await api.GET('/api/v1/audit-events', { params: { query: { page: 1, page_size: 10, sort: '-occurred_at' } } }))
}

/** One cell of the KPI strip: label and note are message keys, noteValues their arguments. */
export interface KpiCell {
  key: string
  label: string
  value: number
  note: string
  noteValues: Record<string, number>
  status: Status
  /** The pre-filtered list; absent when none exists (reboot required). */
  to?: RouteLocationRaw
}

/**
 * The KPI cells of the overview (plan M7c decision 28); values come from the API, never from a page of results. Each
 * link is the list whose total equals the value (AC1, amendment 2026-10-10; TestOverviewKPIsEqualListTotals).
 */
export function kpiCells(o: Overview): KpiCell[] {
  const active = o.devices.active
  const silent = o.devices.no_recent_contact + o.devices.silent + o.devices.silent_critical
  const devices = (query: Record<string, string | string[]>): RouteLocationRaw => ({ path: '/devices', query: { state: 'active', ...query } })
  return [
    {
      key: 'online', label: 'overview.kpi.online', value: o.devices.online, note: 'overview.kpi.ofActive', noteValues: { count: active },
      status: 'ok', to: devices({ contact: 'ok' }),
    },
    {
      key: 'silent', label: 'overview.kpi.silent', value: silent, note: 'overview.kpi.silentNote',
      noteValues: { count: silent, critical: o.devices.silent_critical }, status: 'warn',
      to: devices({ contact: ['unseen', 'stale_warning', 'stale_critical'] }),
    },
    {
      key: 'presumed-lost', label: 'overview.kpi.presumedLost', value: o.devices.presumed_lost, note: 'overview.kpi.presumedLostNote',
      noteValues: {}, status: 'critical', to: devices({ contact: 'presumed_lost' }),
    },
    {
      key: 'encrypted', label: 'overview.kpi.encrypted', value: o.encryption.encrypted, note: 'overview.kpi.ofActive', noteValues: { count: active },
      status: 'ok', to: devices({ disk_state: 'compliant' }),
    },
    {
      key: 'not-encrypted', label: 'overview.kpi.notEncrypted', value: o.encryption.not_encrypted, note: 'overview.kpi.notEncryptedNote',
      noteValues: { partial: o.encryption.partial, notReported: o.encryption.not_reported }, status: 'critical',
      to: devices({ disk_state: 'not_encrypted' }),
    },
    {
      key: 'critical-high', label: 'overview.kpi.criticalHigh', value: o.vulnerabilities.critical_high_cves, note: 'overview.kpi.cvesNote',
      noteValues: {}, status: 'critical', to: { path: '/vulnerabilities', query: { severity: ['critical', 'high'] } },
    },
    {
      key: 'security-overdue', label: 'overview.kpi.securityOverdue', value: o.updates.security_overdue, note: 'overview.kpi.securityOverdueNote',
      noteValues: {}, status: 'warn', to: devices({ security_updates: 'overdue' }),
    },
    {
      key: 'reboot-required', label: 'overview.kpi.rebootRequired', value: o.updates.reboot_required, note: 'overview.kpi.activeDevices',
      noteValues: {}, status: 'info',
    },
  ]
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown' | 'none'

export interface SeveritySegment {
  level: SeverityLevel
  count: number
  /** The pre-filtered vulnerability list; none has no list. */
  to?: RouteLocationRaw
}

/** The segments of the severity bar in their order; counts are devices by their worst finding. */
export function severitySegments(b: OverviewSeverityBuckets): SeveritySegment[] {
  const levels: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'unknown', 'none']
  return levels.map((level) => ({
    level, count: b[level], ...(level === 'none' ? {} : { to: { path: '/vulnerabilities', query: { severity: level } } }),
  }))
}
