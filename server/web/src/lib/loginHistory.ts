import { api, listPage, type DeviceLoginEvent, type DeviceLoginSort } from '../api/client'
import type { ListParams, Page } from './listQuery'

/** One page of a device's login history for DataList (plan M8d decision 18). */
export function listDeviceLogins(deviceID: string): (p: ListParams) => Promise<Page<DeviceLoginEvent>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/devices/{id}/logins', {
        params: { path: { id: deviceID }, query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceLoginSort, q: p.q } },
      }),
    )
}

/** Whether the organization records its login history; null when the settings cannot be read. */
export async function loginHistoryEnabled(): Promise<boolean | null> {
  const { data } = await api.GET('/api/v1/settings/login').catch(() => ({ data: undefined }))
  return data ? data.login_history_enabled : null
}
