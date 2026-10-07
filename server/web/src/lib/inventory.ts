import {
  api, listPage, problemCode, type DeviceSoftwareSort, type FindingSort, type InstalledSoftware, type Severity,
  type SoftwareSort, type SoftwareSummary, type Vulnerability, type VulnerabilityFinding, type VulnerabilitySort,
  type VulnerabilitySummary, type VulnerableDevice, type VulnerableDeviceSort,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

/** Severities of vulnerability findings, highest first; unknown is a finding without score (Fleet free). */
export const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']

/** The severity filter of vulnerability lists. */
export const severityFilter: ListFilter = {
  kind: 'enum', key: 'severity', label: 'inventory.severity',
  options: severities.map((value) => ({ value, title: 'inventory.severities.' + value })),
}

/** The filter of the software list by matched CVEs (one value at a time). */
export const hasVulnerabilitiesFilter: ListFilter = {
  kind: 'enum', key: 'has_vulnerabilities', label: 'inventory.hasVulnerabilities',
  options: [{ value: 'true', title: 'inventory.withVulnerabilities' }, { value: 'false', title: 'inventory.withoutVulnerabilities' }],
}

/** The value of the has_vulnerabilities filter: undefined unless exactly one of true and false is selected. */
export function hasVulnerabilities(p: ListParams): boolean | undefined {
  const values = (p.has_vulnerabilities as string[] | undefined) ?? []
  return values.length === 1 ? values[0] === 'true' : undefined
}

/** A row with a key for DataList's item-value; the inventory rows have composite keys. */
export type Keyed<T> = T & { key: string }

function keyed<T>(page: Page<T>, key: (item: T) => string[]): Page<Keyed<T>> {
  return { ...page, items: page.items.map((item) => ({ ...item, key: key(item).join('\u0000') })) }
}

/** One page of the packages installed on a device for DataList. */
export function listDeviceSoftware(id: string): (p: ListParams) => Promise<Page<Keyed<InstalledSoftware>>> {
  return async (p) =>
    keyed(
      listPage(
        await api.GET('/api/v1/devices/{id}/software', {
          params: { path: { id }, query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceSoftwareSort, q: p.q } },
        }),
      ),
      (s) => [s.name, s.version, s.source],
    )
}

/** One page of the vulnerability findings of a device for DataList. */
export function listDeviceVulnerabilities(id: string): (p: ListParams) => Promise<Page<Keyed<VulnerabilityFinding>>> {
  return async (p) =>
    keyed(
      listPage(
        await api.GET('/api/v1/devices/{id}/vulnerabilities', {
          params: {
            path: { id },
            query: { page: p.page, page_size: p.page_size, sort: p.sort as FindingSort, q: p.q, severity: p.severity as Severity[] },
          },
        }),
      ),
      (f) => [f.cve, f.software_name, f.software_version],
    )
}

/** One page of the organization's software for DataList. */
export async function listSoftware(p: ListParams): Promise<Page<Keyed<SoftwareSummary>>> {
  return keyed(
    listPage(
      await api.GET('/api/v1/software', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as SoftwareSort, q: p.q, has_vulnerabilities: hasVulnerabilities(p),
          },
        },
      }),
    ),
    (s) => [s.name, s.version],
  )
}

/** One page of the organization's vulnerabilities for DataList. */
export async function listVulnerabilities(p: ListParams): Promise<Page<Vulnerability>> {
  return listPage(
    await api.GET('/api/v1/vulnerabilities', {
      params: {
        query: { page: p.page, page_size: p.page_size, sort: p.sort as VulnerabilitySort, q: p.q, severity: p.severity as Severity[] },
      },
    }),
  )
}

/** One page of the devices affected by a CVE for DataList. */
export function listVulnerabilityDevices(cve: string): (p: ListParams) => Promise<Page<Keyed<VulnerableDevice>>> {
  return async (p) =>
    keyed(
      listPage(
        await api.GET('/api/v1/vulnerabilities/{cve}/devices', {
          params: { path: { cve }, query: { page: p.page, page_size: p.page_size, sort: p.sort as VulnerableDeviceSort, q: p.q } },
        }),
      ),
      (d) => [d.device_id, d.software_name, d.software_version],
    )
}

/** The numbers of the start page tile; the problem code on failure. */
export async function getVulnerabilitySummary(): Promise<VulnerabilitySummary | string> {
  const { data, error } = await api.GET('/api/v1/vulnerabilities/summary')
  return data ?? problemCode(error)
}

/** A CVSS score with one decimal, or a dash when unknown. */
export function formatScore(score: number | null | undefined): string {
  return score === null || score === undefined ? '–' : score.toFixed(1)
}
