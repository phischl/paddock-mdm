import {
  api, listPage, type ConfigStatusSort, type DeviceBundle, type DeviceBundleSort, type DeviceDetail, type DeviceResourceStatus,
  type DeviceResourceStatusSort, type ResourceState, type ResourceStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'

const states: ResourceState[] = ['applied', 'failed', 'pending', 'drift_corrected']

/** The status filter of the apply status lists. */
export const resourceStateFilter: ListFilter = {
  kind: 'enum', key: 'status', label: 'configStatus.status',
  options: states.map((value) => ({ value, title: 'configStatus.states.' + value })),
}

/** The chip of a resource's apply status (plan M11 decision 15). */
export function resourceStateView(state: ResourceState): StatusView {
  const status = { applied: 'ok', failed: 'critical', pending: 'warn', drift_corrected: 'info' } as const
  return { status: status[state], label: 'configStatus.states.' + state }
}

/** Whether the device only reports what it would change; the field arrives with the enforce action (plan M11). */
export function isReportOnly(d: DeviceDetail): boolean {
  return (d as DeviceDetail & { config_mode?: string }).config_mode === 'report_only'
}

/** One page of the apply status of a device's resources for DataList. */
export function listDeviceConfigStatus(id: string): (p: ListParams) => Promise<Page<DeviceResourceStatus>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/devices/{id}/config-status', {
        params: {
          path: { id },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as DeviceResourceStatusSort, q: p.q, status: p.status as ResourceState[],
          },
        },
      }),
    )
}

/** One page of the configuration versions of a device for DataList. */
export function listDeviceBundles(id: string): (p: ListParams) => Promise<Page<DeviceBundle>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/devices/{id}/bundles', {
        params: { path: { id }, query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceBundleSort, q: p.q } },
      }),
    )
}

/** One page of the fleet's apply status per resource for DataList. */
export async function listConfigStatus(p: ListParams): Promise<Page<ResourceStatus>> {
  return listPage(
    await api.GET('/api/v1/config-status', {
      params: {
        query: { page: p.page, page_size: p.page_size, sort: p.sort as ConfigStatusSort, q: p.q, status: p.status as ResourceState[] },
      },
    }),
  )
}
