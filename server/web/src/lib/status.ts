import type {
  AgentReleaseStatus, AgentRolloutStatus, AttentionKind, AuditActorType, AuditOutcome, DeviceCommandStatus, DeviceComponent, DeviceContact, DeviceState,
  DiskState, OrganizationStatus, RevocationStatus,
} from '../api/client'

/**
 * One status vocabulary for every chip of the portal (plan M7c decision 19): ok, warn, critical, info, neutral,
 * each shown as a dot and a label, never as colour alone. The functions here are pure; the label is a message key.
 */
export type Status = 'ok' | 'warn' | 'critical' | 'info' | 'neutral'

export interface StatusView {
  status: Status
  /** Message key of the label. */
  label: string
}

export function deviceStatus(d: { state: DeviceState; contact: DeviceContact }): StatusView {
  switch (d.state) {
    case 'retired':
      return { status: 'neutral', label: 'devices.states.retired' }
    case 'rejected':
      return { status: 'neutral', label: 'devices.states.rejected' }
    case 'pending':
      return { status: 'info', label: 'devices.states.pending' }
    case 'quarantined':
      return { status: 'critical', label: 'devices.states.quarantined' }
    case 'active':
      switch (d.contact) {
        case 'presumed_lost':
          return { status: 'critical', label: 'devices.contact.presumed_lost' }
        case 'stale_critical':
          return { status: 'critical', label: 'devices.contact.stale_critical' }
        case 'stale_warning':
          return { status: 'warn', label: 'devices.contact.stale_warning' }
        case 'unseen':
          return { status: 'warn', label: 'devices.contact.unseen' }
        case 'never':
          return { status: 'neutral', label: 'devices.contact.never' }
        case 'ok':
          return { status: 'ok', label: 'devices.contact.ok' }
      }
  }
}

export function encryptionStatus(state: DiskState | '' | null | undefined): StatusView {
  switch (state) {
    case 'compliant':
      return { status: 'ok', label: 'status.encrypted' }
    case 'escrow_pending':
      return { status: 'warn', label: 'devices.disk.states.escrow_pending' }
    case 'encrypting':
      return { status: 'warn', label: 'devices.disk.states.encrypting' }
    case 'unmanaged':
      return { status: 'warn', label: 'devices.disk.states.unmanaged' }
    case 'tpm_missing':
      return { status: 'warn', label: 'devices.disk.states.tpm_missing' }
    case 'tpm_pin_missing':
      return { status: 'warn', label: 'devices.disk.states.tpm_pin_missing' }
    case 'unlock_mode_mismatch':
      return { status: 'warn', label: 'devices.disk.unlockModeMismatch' }
    case 'not_encrypted':
      return { status: 'critical', label: 'devices.disk.states.not_encrypted' }
    case '':
    case null:
    case undefined:
      return { status: 'neutral', label: 'status.notReported' }
  }
}

export function outcomeStatus(o: AuditOutcome): StatusView {
  const label = 'audit.outcomes.' + o
  switch (o) {
    case 'success':
      return { status: 'ok', label }
    case 'failure':
      return { status: 'warn', label }
    case 'denied':
      return { status: 'critical', label }
    case 'unknown':
      return { status: 'neutral', label }
  }
}

export function attentionStatus(kind: AttentionKind): StatusView {
  const label = 'attention.kinds.' + kind
  switch (kind) {
    case 'presumed_lost':
    case 'stale_critical':
    case 'quarantined':
    case 'revocation_expired':
      return { status: 'critical', label }
    case 'stale_warning':
    case 'disk_not_compliant':
    case 'agent_outdated':
    case 'agent_rollback_pending':
    case 'agent_not_running':
    case 'uninstall_pending':
    case 'config_behind':
    case 'disk_conversion_failed':
    case 'clock_drift':
    case 'login_apply_failed':
    case 'sudo_apply_failed':
      return { status: 'warn', label }
    case 'revocation_pending':
      return { status: 'info', label }
  }
}

/** The severity rank of an attention kind: critical 2, warn 1, info 0 (the API's -severity sort). */
export function attentionRank(kind: AttentionKind): 0 | 1 | 2 {
  switch (attentionStatus(kind).status) {
    case 'critical':
      return 2
    case 'warn':
      return 1
    default:
      return 0
  }
}

export function commandStatus(s: DeviceCommandStatus): StatusView {
  const label = 'commands.statuses.' + s
  switch (s) {
    case 'pending':
    case 'delivered':
      return { status: 'info', label }
    case 'succeeded':
      return { status: 'ok', label }
    case 'failed':
      return { status: 'critical', label }
    case 'expired':
      return { status: 'warn', label }
    case 'cancelled':
      return { status: 'neutral', label }
  }
}

export function revocationStatus(s: RevocationStatus): StatusView {
  const label = 'revocations.statuses.' + s
  switch (s) {
    case 'requested':
    case 'approved':
    case 'issued':
    case 'delivered':
      return { status: 'info', label }
    case 'confirmed':
      return { status: 'ok', label }
    case 'failed':
      return { status: 'critical', label }
    case 'expired':
      return { status: 'warn', label }
    case 'rejected':
    case 'cancelled':
      return { status: 'neutral', label }
  }
}

export type TokenStatus = 'active' | 'expired' | 'revoked' | 'exhausted'

/** Enrollment and API tokens; labels is the page's key group (tokens.statuses or apiTokens.statuses). */
export function tokenStatus(s: TokenStatus, labels = 'tokens.statuses'): StatusView {
  const label = labels + '.' + s
  switch (s) {
    case 'active':
      return { status: 'ok', label }
    case 'expired':
      return { status: 'warn', label }
    case 'revoked':
    case 'exhausted':
      return { status: 'neutral', label }
  }
}

export function rolloutStatus(s: AgentRolloutStatus): StatusView {
  const label = 'agentReleases.rolloutStatuses.' + s
  switch (s) {
    case 'running':
      return { status: 'info', label }
    case 'halted':
      return { status: 'critical', label }
    case 'completed':
      return { status: 'ok', label }
  }
}

export function releaseStatus(s: AgentReleaseStatus): StatusView {
  const label = 'agentReleases.statuses.' + s
  switch (s) {
    case 'draft':
      return { status: 'neutral', label }
    case 'published':
      return { status: 'ok', label }
  }
}

export function organizationStatus(s: OrganizationStatus): StatusView {
  const label = 'organizations.statuses.' + s
  switch (s) {
    case 'active':
      return { status: 'ok', label }
    case 'provisioning':
      return { status: 'info', label }
    case 'provisioning_failed':
      return { status: 'critical', label }
    case 'suspended':
      return { status: 'warn', label }
  }
}

export function userLockStatus(locked: boolean): StatusView {
  return locked ? { status: 'critical', label: 'status.locked' } : { status: 'ok', label: 'status.active' }
}

/** The actor type of an audit event (stored as text; a type this portal does not know is neutral). */
export function actorStatus(type: AuditActorType | string): StatusView {
  const label = 'audit.actorTypes.' + type
  switch (type) {
    case 'admin':
    case 'platform_admin':
    case 'api_token':
      return { status: 'info', label }
    default:
      return { status: 'neutral', label }
  }
}

/** The status of a component of a device (plan M8d decision 56). */
export function componentStatus(s: DeviceComponent['status']): StatusView {
  const label = 'devices.components.status.' + s
  switch (s) {
    case 'ok':
      return { status: 'ok', label }
    case 'outdated':
      return { status: 'warn', label }
    case 'missing':
    case 'unknown':
      return { status: 'neutral', label }
  }
}
