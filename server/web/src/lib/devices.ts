import {
  api, listPage, problemCode, type Device, type DeviceContact, type DeviceDetail, type DeviceReport, type DeviceSort, type DeviceState, type DiskState,
  type EffectiveConfig,
} from '../api/client'
import { maxListDepth, type ListFilter, type ListParams, type Page } from './listQuery'

export const deviceStates: DeviceState[] = ['pending', 'active', 'quarantined', 'rejected', 'retired']

/** The state filter of device lists. */
export const stateFilter: ListFilter = {
  kind: 'enum', key: 'state', label: 'devices.state',
  options: deviceStates.map((value) => ({ value, title: 'devices.states.' + value })),
}

export const deviceContacts: DeviceContact[] = ['ok', 'unseen', 'stale_warning', 'stale_critical', 'presumed_lost', 'never']

/** The contact filter of the device list (plan M7c §12 open point 1): the overview's KPI cells link to it. */
export const contactFilter: ListFilter = {
  kind: 'enum', key: 'contact', label: 'devices.contactFilter', hint: 'devices.contactHint',
  options: deviceContacts.map((value) => ({ value, title: 'devices.contact.' + value })),
}

/** The security update filter (plan M7c amendment 2026-10-10): the overview's "Security updates overdue" links to it. */
/** The component filter of the device list (plan M8d decision 56). */
export const componentFilter: ListFilter = {
  kind: 'enum', key: 'component_outdated', label: 'devices.componentFilter',
  options: [{ value: 'true', title: 'devices.components.status.outdated' }],
}

export const securityFilter: ListFilter = {
  kind: 'enum', key: 'security_updates', label: 'devices.securityFilter', options: [{ value: 'overdue', title: 'devices.securityUpdates.overdue' }],
}

/** The device group filter; options are the organization's groups. */
export function groupFilter(groups: { id: string; name: string }[]): ListFilter {
  return { kind: 'enum', key: 'device_group_id', label: 'devices.group', options: groups.map((g) => ({ value: g.id, title: g.name })) }
}

/** The owner filter of the device list (plan M8d decision 5); options are the organization's users. */
export function ownerFilter(users: { id: string; username: string }[]): ListFilter {
  return { kind: 'enum', key: 'owner_id', label: 'devices.ownerFilter', options: users.map((u) => ({ value: u.id, title: u.username })) }
}

/** The owners of a list row joined for the Owners column. */
export function ownerNames(d: Device): string {
  return d.owners.map((o) => o.username).join(', ')
}

/** One page of devices for DataList. */
export async function listDevices(p: ListParams): Promise<Page<Device>> {
  return listPage(
    await api.GET('/api/v1/devices', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as DeviceSort, q: p.q, state: p.state as DeviceState[],
          device_group_id: ((p.device_group_id as string[] | undefined) ?? [])[0], disk_state: p.disk_state as DiskState[],
          contact: p.contact as DeviceContact[],
          security_updates: ((p.security_updates as string[] | undefined) ?? [])[0] as 'overdue' | undefined,
          owner_id: ((p.owner_id as string[] | undefined) ?? [])[0],
          component_outdated: ((p.component_outdated as string[] | undefined) ?? [])[0] === 'true' ? true : undefined,
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

/** Replaces the owners of a device; null on success, otherwise the problem code. */
export async function setDeviceOwners(id: string, userIDs: string[]): Promise<string | null> {
  const { error } = await api.PUT('/api/v1/devices/{id}/owners', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { user_ids: userIDs },
  })
  return error ? problemCode(error) : null
}

/** Asks the device to install the offered agent release at its next check-in (plan M8d decision 26); null on
 * success, otherwise the problem code and detail. */
export async function requestAgentUpdate(id: string): Promise<{ problem: string; detail?: string } | null> {
  const { error } = await api.POST('/api/v1/devices/{id}/update-agent', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? { problem: problemCode(error), detail: (error as { detail?: string } | undefined)?.detail } : null
}

/** The message key of a refused update-now request: the two expected refusals have their own texts. */
export function agentUpdateProblemKey(res: { problem: string; detail?: string }): string | null {
  if (res.detail === 'no agent release is being offered') return 'devices.updateAgent.noRelease'
  if (res.detail?.startsWith('the device already runs')) return 'devices.updateAgent.upToDate'
  return null
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
