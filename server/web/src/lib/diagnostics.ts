import {
  api, listPage, problemCode, type DeviceDiagnosticsSort, type Diagnostics, type DiagnosticsSort, type DiagnosticsState,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'

/** The states of a diagnostics bundle (ADR 0048, plan M12 decision 3). */
export const diagnosticsStates: DiagnosticsState[] = ['requested', 'uploaded', 'stored', 'failed', 'expired', 'purged']

/** Bounds of the reason the device's user is shown (ADR 0048 decision 1). */
export const minReason = 2
export const maxReason = 500

/** The closed content list of a bundle, linked from the request dialog (plan M12 decision 14). */
export const contentListUrl = 'https://github.com/phischl/paddock-mdm/blob/main/docs/operations/diagnostics.md'

/** The state filter of the diagnostics lists. */
export const diagnosticsStateFilter: ListFilter = {
  kind: 'enum', key: 'state', label: 'diagnostics.state',
  options: diagnosticsStates.map((value) => ({ value, title: 'diagnostics.states.' + value })),
}

/** The chip of a bundle's state. */
export function diagnosticsStateView(state: DiagnosticsState): StatusView {
  const status = { requested: 'info', uploaded: 'info', stored: 'ok', failed: 'critical', expired: 'neutral', purged: 'neutral' } as const
  return { status: status[state], label: 'diagnostics.states.' + state }
}

/** Whether a reason has the length the server accepts (counted in characters, as the server does). */
export function validReason(reason: string): boolean {
  const n = [...reason.trim()].length
  return n >= minReason && n <= maxReason
}

/** One page of the bundles of a device for DataList. */
export function listDeviceDiagnostics(id: string): (p: ListParams) => Promise<Page<Diagnostics>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/devices/{id}/diagnostics', {
        params: {
          path: { id },
          query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceDiagnosticsSort, state: p.state as DiagnosticsState[] },
        },
      }),
    )
}

/** One page of every bundle of the organization for DataList. */
export async function listDiagnostics(p: ListParams): Promise<Page<Diagnostics>> {
  return listPage(
    await api.GET('/api/v1/diagnostics', {
      params: {
        query: { page: p.page, page_size: p.page_size, sort: p.sort as DiagnosticsSort, q: p.q, state: p.state as DiagnosticsState[] },
      },
    }),
  )
}

/** Asks the device for a bundle; the bundle or the problem code. */
export async function requestDiagnostics(id: string, reason: string): Promise<Diagnostics | string> {
  const { data, error } = await api.POST('/api/v1/devices/{id}/diagnostics', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body: { reason: reason.trim() },
  })
  return data ?? problemCode(error)
}

/** A downloaded diagnostics archive. */
export interface DiagnosticsFile {
  blob: Blob
  filename: string
}

/** Downloads the decrypted archive of a stored bundle (step-up); the file or the problem code. */
export async function downloadDiagnostics(id: string): Promise<DiagnosticsFile | string> {
  const { data, error, response } = await api.GET('/api/v1/diagnostics/{id}/download', {
    params: { path: { id } }, parseAs: 'blob',
  })
  if (error || !data) return problemCode(error)
  const match = /filename="?([^";]+)"?/.exec(response.headers.get('Content-Disposition') ?? '')
  return { blob: data as Blob, filename: match?.[1] ?? 'paddock-diagnostics-' + id + '.tar.gz' }
}

/** Purges a stored bundle at once; null or the problem code. */
export async function purgeDiagnostics(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/diagnostics/{id}/purge', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}
