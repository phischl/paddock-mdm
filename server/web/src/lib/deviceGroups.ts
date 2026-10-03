import { api, listPage, problemCode, type DeviceGroup, type DeviceGroupSort } from '../api/client'
import type { ListParams, Page } from './listQuery'

/** One page of device groups for DataList. */
export async function listDeviceGroups(p: ListParams): Promise<Page<DeviceGroup>> {
  return listPage(
    await api.GET('/api/v1/device-groups', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceGroupSort, q: p.q } },
    }),
  )
}

/** Creates a device group; returns null on success, otherwise the problem code. */
export async function createDeviceGroup(name: string, description: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/device-groups', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: { name: name.trim(), description: description.trim() },
  })
  return error ? problemCode(error) : null
}

/** Updates a device group; returns null on success, otherwise the problem code. */
export async function updateDeviceGroup(id: string, name: string, description: string): Promise<string | null> {
  const { error } = await api.PATCH('/api/v1/device-groups/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { name: name.trim(), description: description.trim() },
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
