import { api, listPage, problemCode, type DeviceGroup, type DeviceGroupSort } from '../api/client'
import type { DeviceGroupInput } from './deviceGroupPage'
import type { ListParams, Page } from './listQuery'

/** The laptop preset of the contact thresholds (plan M8d decision 13): warning after 5 days, critical after 35. */
export const laptopStaleness = { warning_h: 120, critical_h: 840 }

/** The thresholds a group's members are evaluated with and their source (plan M8d decision 12). */
export function effectiveStaleness(
  group: Pick<DeviceGroup, 'staleness'>,
  org: { staleness_warning_h: number; staleness_critical_h: number } | null,
): { warning: number; critical: number; source: 'device_group' | 'organization' } | null {
  if (group.staleness) return { warning: group.staleness.warning_h, critical: group.staleness.critical_h, source: 'device_group' }
  if (!org) return null
  return { warning: org.staleness_warning_h, critical: org.staleness_critical_h, source: 'organization' }
}

/** One page of device groups for DataList. */
export async function listDeviceGroups(p: ListParams): Promise<Page<DeviceGroup>> {
  return listPage(
    await api.GET('/api/v1/device-groups', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceGroupSort, q: p.q } },
    }),
  )
}

/** Creates a device group; returns null on success, otherwise the problem code. */
export async function createDeviceGroup(form: DeviceGroupInput): Promise<string | null> {
  const { error } = await api.POST('/api/v1/device-groups', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: {
      name: form.name.trim(), description: form.description.trim(), staleness: form.staleness,
      agent_update_policy: form.agent_update_policy,
    },
  })
  return error ? problemCode(error) : null
}

/** Updates a device group; returns null on success, otherwise the problem code. */
export async function updateDeviceGroup(id: string, form: DeviceGroupInput): Promise<string | null> {
  const { error } = await api.PATCH('/api/v1/device-groups/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: {
      name: form.name.trim(), description: form.description.trim(), staleness: form.staleness,
      agent_update_policy: form.agent_update_policy,
    },
  })
  return error ? problemCode(error) : null
}

/** Deletes a device group; returns null on success, otherwise the problem code. */
export async function deleteDeviceGroup(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/device-groups/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}
