import {
  api, listPage, problemCode, type AuditEvidenceKey, type AuditExport, type AuditExportCreate, type AuditExportSort,
  type AuditExportStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'

const statuses: AuditExportStatus[] = ['pending', 'running', 'ready', 'failed', 'expired']

/** Filter of the evidence exports (plan M10 decision 37): the status. */
export const exportFilters: ListFilter[] = [
  { kind: 'enum', key: 'status', label: 'auditExports.status', options: statuses.map((value) => ({ value, title: 'auditExports.statuses.' + value })) },
]

/** One page of evidence exports for DataList. */
export async function listAuditExports(p: ListParams): Promise<Page<AuditExport>> {
  return listPage(
    await api.GET('/api/v1/audit/exports', {
      params: {
        query: { page: p.page, page_size: p.page_size, sort: p.sort as AuditExportSort, q: p.q, status: p.status as AuditExportStatus[] },
      },
    }),
  )
}

/** The signing key versions with their fingerprints, or the problem code. */
export async function listAuditKeys(): Promise<AuditEvidenceKey[] | string> {
  const { data, error } = await api.GET('/api/v1/audit/keys')
  return data?.keys ?? problemCode(error)
}

/** Requests an export; the pending export, or the problem code. */
export async function createAuditExport(body: AuditExportCreate): Promise<AuditExport | string> {
  const { data, error } = await api.POST('/api/v1/audit/exports', { params: { header: { 'X-Paddock-CSRF': '1' } }, body })
  return data ?? problemCode(error)
}

/** The URL of the package of a ready export; the browser fetches it with the session cookie (never into memory). */
export function downloadUrl(id: string): string {
  return '/api/v1/audit/exports/' + encodeURIComponent(id) + '/download'
}

/** The chip of an export's status. */
export function exportStatus(s: AuditExportStatus): StatusView {
  const label = 'auditExports.statuses.' + s
  switch (s) {
    case 'ready':
      return { status: 'ok', label }
    case 'failed':
      return { status: 'critical', label }
    case 'pending':
    case 'running':
      return { status: 'info', label }
    default:
      return { status: 'neutral', label }
  }
}

/** The chip of the chain check of a package; null (not built yet, or failed) has none. */
export function chainStatus(ok: boolean | null): StatusView | null {
  if (ok === null) return null
  return ok ? { status: 'ok', label: 'auditExports.chain.intact' } : { status: 'critical', label: 'auditExports.chain.problems' }
}

/** Whether the list still has to follow an export that the audit writer has not finished. */
export function hasOpenExport(items: AuditExport[]): boolean {
  return items.some((e) => e.status === 'pending' || e.status === 'running')
}

function day(d: Date): string {
  return d.toISOString().slice(0, 10)
}

/** The default range of the dialog: the last 365 recording days, ending yesterday (UTC days). */
export function defaultRange(now: Date): { from: string; to: string } {
  const to = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1))
  const from = new Date(to.getTime() - 364 * 86_400_000)
  return { from: day(from), to: day(to) }
}

const dayPattern = /^\d{4}-\d{2}-\d{2}$/

/** Client-side checks of the request; message keys by field. The server decides sealing and the range limit. */
export function validateExport(from: string, to: string, purpose: string): Record<string, string> {
  const errors: Record<string, string> = {}
  if (!dayPattern.test(from)) errors.from = 'auditExports.errors.fromRequired'
  if (!dayPattern.test(to)) errors.to = 'auditExports.errors.toRequired'
  if (!errors.from && !errors.to && from > to) errors.to = 'auditExports.errors.order'
  if (purpose.trim() === '') errors.purpose = 'auditExports.errors.purposeRequired'
  return errors
}

/** A package size in the largest fitting decimal unit with at most one decimal (packages range from kilobytes up). */
export function formatSize(bytes: number, locale: string): string {
  const units = [['byte', 1], ['kilobyte', 1e3], ['megabyte', 1e6], ['gigabyte', 1e9]] as const
  const [unit, factor] = [...units].reverse().find(([, f]) => bytes >= f) ?? units[0]
  return new Intl.NumberFormat(locale, { style: 'unit', unit, unitDisplay: 'short', maximumFractionDigits: 1 }).format(bytes / factor)
}
