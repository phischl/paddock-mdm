import type { LocationQuery } from 'vue-router'
import type { AttentionKind, DeviceDetail, DeviceReport, DeviceUpdates, DiskState, RevocationRequest } from '../api/client'
import { deviceStatus, encryptionStatus, type StatusView } from './status'

/**
 * The health rows of a device's Overview tab and the chips of its header band (plan M7c decision 29). Pure
 * functions: the frame loads the data, the components render it. Labels are message keys.
 */
export interface HealthRow {
  key: 'contact' | 'encryption' | 'agent' | 'security' | 'reboot' | 'login' | 'sudo'
  /** Message key of the row's name. */
  label: string
  view: StatusView
}

/** The inputs of the health rows; null where a source could not be read. */
export interface HealthInput {
  device: DeviceDetail
  diskState: DiskState | null
  updates: DeviceUpdates | null
  /** The device's open attention conditions (the server's rules for an outdated agent and failed configuration). */
  conditions: AttentionKind[]
}

const notReported: StatusView = { status: 'neutral', label: 'devices.health.notReported' }

function securityView(run: DeviceReport | null | undefined): StatusView {
  if (!run) return notReported
  return run.params.result === 'ok' ? { status: 'ok', label: 'devices.health.securityOk' } : { status: 'warn', label: 'devices.health.securityFailed' }
}

function configView(report: DeviceReport | null, failed: boolean): StatusView {
  if (failed) return { status: 'warn', label: 'devices.health.configFailed' }
  if (!report) return notReported
  return report.type.endsWith('apply_failed') || report.type.endsWith('unresolved')
    ? { status: 'warn', label: 'devices.health.configFailed' }
    : { status: 'ok', label: 'devices.health.configApplied' }
}

export function healthRows(h: HealthInput): HealthRow[] {
  const d = h.device
  const agent: StatusView = h.conditions.includes('agent_outdated')
    ? { status: 'warn', label: 'devices.health.agentOutdated' }
    : d.agent_version ? { status: 'ok', label: 'devices.health.agentCurrent' } : notReported
  const reboot: StatusView = !h.updates
    ? notReported
    : h.updates.reboot_required ? { status: 'warn', label: 'devices.health.rebootRequired' } : { status: 'ok', label: 'devices.health.rebootNone' }
  return [
    { key: 'contact', label: 'devices.health.contact', view: deviceStatus(d) },
    { key: 'encryption', label: 'devices.health.encryption', view: encryptionStatus(h.diskState) },
    { key: 'agent', label: 'devices.health.agent', view: agent },
    { key: 'security', label: 'devices.health.security', view: h.updates ? securityView(h.updates.last_security_run) : notReported },
    { key: 'reboot', label: 'devices.health.reboot', view: reboot },
    { key: 'login', label: 'devices.health.login', view: configView(d.login_status.login, h.conditions.includes('login_apply_failed')) },
    { key: 'sudo', label: 'devices.health.sudo', view: configView(d.login_status.sudo, h.conditions.includes('sudo_apply_failed')) },
  ]
}

/** Whether the device's latest Lock is in force or on its way (the header's "Locked" chip). */
export function lockedByRevocation(requests: RevocationRequest[]): boolean {
  const lock = [...requests].filter((r) => r.action === 'lock').sort((a, b) => b.requested_at.localeCompare(a.requested_at))[0]
  return !!lock && (lock.status === 'issued' || lock.status === 'delivered' || lock.status === 'confirmed')
}

/** The query keys of the device list that the device pane takes over, prefixed with pane. (plan M7c decision 29). */
const paneKeys = ['q', 'state', 'device_group_id', 'sort', 'page']

/** The pane query for a device opened from the device list, so the pane shows the list the admin came from. */
export function paneQuery(listQuery: LocationQuery): LocationQuery {
  const out: LocationQuery = {}
  for (const key of paneKeys) {
    if (listQuery[key] !== undefined) out['pane.' + key] = listQuery[key]
  }
  return out
}

/** The pane's own query keys, kept when the admin switches devices or tabs. */
export function paneOnly(query: LocationQuery): LocationQuery {
  return Object.fromEntries(Object.entries(query).filter(([k]) => k.startsWith('pane.')))
}
