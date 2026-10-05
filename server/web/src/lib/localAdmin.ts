import {
  api, listPage, problemCode, type DeviceCommand, type DeviceCommandSort, type DeviceCommandStatus, type DeviceCommandType,
  type LocalAdmin, type LocalAdminRevealed,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

export const commandStatuses: DeviceCommandStatus[] = ['pending', 'delivered', 'succeeded', 'failed', 'expired', 'cancelled']
export const commandTypes: DeviceCommandType[] = ['rotate_admin_password']

/** The filters of the command list. */
export const commandFilters: ListFilter[] = [
  { kind: 'enum', key: 'status', label: 'commands.status', options: commandStatuses.map((value) => ({ value, title: 'commands.statuses.' + value })) },
  { kind: 'enum', key: 'type', label: 'commands.type', options: commandTypes.map((value) => ({ value, title: 'commands.types.' + value })) },
]

/** One page of the commands of a device for DataList. */
export function listCommands(deviceID: string): (p: ListParams) => Promise<Page<DeviceCommand>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/devices/{id}/commands', {
        params: {
          path: { id: deviceID },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as DeviceCommandSort, q: p.q,
            status: p.status as DeviceCommandStatus[], type: p.type as DeviceCommandType[],
          },
        },
      }),
    )
}

/** The local administrator of a device; the problem code on failure. */
export async function getLocalAdmin(id: string): Promise<LocalAdmin | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}/local-admin', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Issues rotate_admin_password; null on success, otherwise the problem code. */
export async function rotateLocalAdmin(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/devices/{id}/local-admin/rotate', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** Reveals the passwords (step-up and typed hostname); the passwords or the problem code. */
export async function revealLocalAdmin(id: string, hostname: string): Promise<LocalAdminRevealed | string> {
  const { data, error } = await api.POST('/api/v1/devices/{id}/local-admin/reveal', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body: { confirm_hostname: hostname },
  })
  return data ?? problemCode(error)
}

/** Whether the next rotation is overdue (the device rotates only while it reaches the server). */
export function rotationOverdue(state: LocalAdmin, now: Date): boolean {
  return state.next_rotation_at !== null && new Date(state.next_rotation_at) < now
}
