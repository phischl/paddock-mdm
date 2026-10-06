import {
  api, listPage, problemCode, type Device, type DeviceDetail, type DeviceReport, type DeviceSort, type DeviceState, type DiskState,
  type EffectiveConfig,
} from '../api/client'
import { maxListDepth, type ListFilter, type ListParams, type Page } from './listQuery'

export const deviceStates: DeviceState[] = ['pending', 'active', 'quarantined', 'rejected', 'retired']

/** The state filter of device lists. */
export const stateFilter: ListFilter = {
  kind: 'enum', key: 'state', label: 'devices.state',
  options: deviceStates.map((value) => ({ value, title: 'devices.states.' + value })),
}

/** The device group filter; options are the organization's groups. */
export function groupFilter(groups: { id: string; name: string }[]): ListFilter {
  return { kind: 'enum', key: 'device_group_id', label: 'devices.group', options: groups.map((g) => ({ value: g.id, title: g.name })) }
}

/** One page of devices for DataList. */
export async function listDevices(p: ListParams): Promise<Page<Device>> {
  return listPage(
    await api.GET('/api/v1/devices', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as DeviceSort, q: p.q, state: p.state as DeviceState[],
          device_group_id: ((p.device_group_id as string[] | undefined) ?? [])[0], disk_state: p.disk_state as DiskState[],
        },
      },
    }),
  )
}

/** One page of the members of a device group for DataList. */
export function listGroupDevices(groupID: string): (p: ListParams) => Promise<Page<Device>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/device-groups/{id}/devices', {
        params: {
          path: { id: groupID },
          query: { page: p.page, page_size: p.page_size, sort: p.sort as DeviceSort, q: p.q, state: p.state as DeviceState[] },
        },
      }),
    )
}

/** Loads a device with its groups and keys; the problem code on failure. */
export async function getDevice(id: string): Promise<DeviceDetail | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Loads the effective configuration of a device; the problem code on failure. */
export async function getEffectiveConfig(id: string): Promise<EffectiveConfig | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}/effective-config', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Lifecycle actions of a device (custom methods "<id>:<action>" of the admin API). */
export type DeviceAction = 'approve' | 'reject' | 'release-quarantine' | 'retire'

/** Which actions the state allows (architecture §6.5). */
export function actionsFor(state: DeviceState): DeviceAction[] {
  switch (state) {
    case 'pending':
      return ['approve', 'reject']
    case 'active':
      return ['retire']
    case 'quarantined':
      return ['release-quarantine', 'retire']
    default:
      return []
  }
}

const actionPaths = {
  approve: '/api/v1/devices/{id}/approve',
  reject: '/api/v1/devices/{id}/reject',
  'release-quarantine': '/api/v1/devices/{id}/release-quarantine',
  retire: '/api/v1/devices/{id}/retire',
} as const

/** Runs a lifecycle action; null on success, otherwise the problem code. */
export async function runDeviceAction(id: string, action: DeviceAction): Promise<string | null> {
  const { error } = await api.POST(actionPaths[action], { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** Replaces the device group memberships; null on success, otherwise the problem code. */
export async function setDeviceGroups(id: string, groupIDs: string[]): Promise<string | null> {
  const { error } = await api.PUT('/api/v1/devices/{id}/groups', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { device_group_ids: groupIDs },
  })
  return error ? problemCode(error) : null
}

/** All device groups by name (selection lists), paged through the list contract (at most its depth limit). */
export async function allGroups(): Promise<{ id: string; name: string }[]> {
  const out: { id: string; name: string }[] = []
  for (let page = 1; page * 100 <= maxListDepth; page++) {
    const { data } = await api.GET('/api/v1/device-groups', { params: { query: { page, page_size: 100, sort: 'name' } } })
    out.push(...(data?.items ?? []).map((g) => ({ id: g.id, name: g.name })))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

/** Replaces the login assignment of a device; null on success, otherwise the problem code. */
export async function setLoginAssignment(id: string, users: string[], groups: string[]): Promise<string | null> {
  const { error } = await api.PUT('/api/v1/devices/{id}/login-assignment', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { users, groups },
  })
  return error ? problemCode(error) : null
}

/** Suspends or resumes directory logins on a device; null on success, otherwise the problem code. */
export async function setLoginsSuspended(id: string, suspended: boolean): Promise<string | null> {
  const path = suspended ? '/api/v1/devices/{id}/suspend-logins' : '/api/v1/devices/{id}/resume-logins'
  const { error } = await api.POST(path, { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** All devices by hostname (selection lists), paged through the list contract (at most its depth limit). */
export async function allDevices(): Promise<{ id: string; hostname: string }[]> {
  const out: { id: string; hostname: string }[] = []
  for (let page = 1; page * 100 <= maxListDepth; page++) {
    const { data } = await api.GET('/api/v1/devices', { params: { query: { page, page_size: 100, sort: 'hostname' } } })
    out.push(...(data?.items ?? []).map((d) => ({ id: d.id, hostname: d.hostname })))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

type Translate = (key: string, values?: Record<string, unknown>) => string

/** Renders the latest login or sudo report of a device (plan M3b decision 17); unknown event types show the type. */
export function reportText(t: Translate, report: DeviceReport): string {
  const p = report.params
  switch (report.type) {
    case 'login.applied':
      return t('devices.report.events.login_applied', { changed: ((p.changed as string[] | undefined) ?? []).join(', ') })
    case 'login.apply_failed':
      return t('devices.report.events.login_apply_failed', { stage: p.stage ?? '', message: p.message ?? '' })
    case 'sudo.apply_failed':
      return p.username
        ? t('devices.report.events.sudo_apply_failed', { username: p.username, message: p.message ?? '' })
        : t('devices.report.events.sudo_apply_failed_config', { message: p.message ?? '' })
    case 'sudo.user_unresolved':
      return t('devices.report.events.sudo_user_unresolved', { username: p.username ?? '' })
    default:
      return report.type
  }
}
