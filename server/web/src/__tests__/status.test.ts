import { describe, expect, it } from 'vitest'
import type {
  AgentRolloutStatus, AttentionKind, AuditOutcome, DeviceCommandStatus, DeviceContact, DeviceState, DiskState, OrganizationStatus,
  RevocationStatus,
} from '../api/client'
import {
  actorStatus, attentionRank, attentionStatus, commandStatus, deviceStatus, encryptionStatus, organizationStatus, outcomeStatus, releaseStatus,
  revocationStatus, rolloutStatus, tokenStatus, userLockStatus, type Status,
} from '../lib/status'
import en from '../locales/en.json'

const resolve = (key: string): unknown => key.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown>)?.[k], en)

// Every enum value is listed, so a new value fails to compile here before it can slip through a mapping.
const deviceStates = ['pending', 'active', 'rejected', 'quarantined', 'retired'] as const satisfies readonly DeviceState[]
const contacts = ['never', 'ok', 'unseen', 'stale_warning', 'stale_critical', 'presumed_lost'] as const satisfies readonly DeviceContact[]
const diskStates = ['not_encrypted', 'unmanaged', 'tpm_missing', 'tpm_pin_missing', 'unlock_mode_mismatch', 'escrow_pending', 'compliant'] as const satisfies readonly DiskState[]
const outcomes = ['success', 'failure', 'denied', 'unknown'] as const satisfies readonly AuditOutcome[]
const kinds = [
  'stale_warning', 'stale_critical', 'presumed_lost', 'quarantined', 'disk_not_compliant', 'agent_outdated', 'login_apply_failed',
  'sudo_apply_failed', 'revocation_pending', 'revocation_expired', 'agent_rollback_pending',
  'agent_not_running', 'uninstall_pending', 'config_behind', 'clock_drift',
] as const satisfies readonly AttentionKind[]
const commands = ['pending', 'delivered', 'succeeded', 'failed', 'expired', 'cancelled'] as const satisfies readonly DeviceCommandStatus[]
const revocations = ['requested', 'approved', 'issued', 'delivered', 'confirmed', 'failed', 'rejected', 'cancelled', 'expired'] as const satisfies readonly RevocationStatus[]
const rollouts = ['running', 'halted', 'completed'] as const satisfies readonly AgentRolloutStatus[]

describe('status mappings (plan M7c decision 19)', () => {
  it('maps every device state and contact, the contact only for active devices', () => {
    const want: Record<DeviceContact, [Status, string]> = {
      presumed_lost: ['critical', 'Presumed lost'], stale_critical: ['critical', 'Silent (critical)'], stale_warning: ['warn', 'Silent'],
      never: ['neutral', 'Never contacted'], ok: ['ok', 'Online'], unseen: ['warn', 'No recent contact'],
    }
    for (const contact of contacts) {
      const v = deviceStatus({ state: 'active', contact })
      expect([v.status, resolve(v.label)], contact).toEqual(want[contact])
    }
    for (const state of deviceStates) {
      for (const contact of contacts) {
        const v = deviceStatus({ state, contact })
        expect(resolve(v.label), `${state}/${contact}`).toBeTypeOf('string')
        if (state !== 'active') expect(v.label).toBe('devices.states.' + state)
      }
    }
    expect(deviceStatus({ state: 'retired', contact: 'presumed_lost' }).status).toBe('neutral')
    expect(deviceStatus({ state: 'rejected', contact: 'ok' }).status).toBe('neutral')
    expect(deviceStatus({ state: 'pending', contact: 'never' }).status).toBe('info')
    expect(deviceStatus({ state: 'quarantined', contact: 'ok' }).status).toBe('critical')
  })

  it('maps every disk state and the missing report', () => {
    const want: Record<DiskState, Status> = {
      compliant: 'ok', escrow_pending: 'warn', unmanaged: 'warn', tpm_missing: 'warn', tpm_pin_missing: 'warn', not_encrypted: 'critical',
      unlock_mode_mismatch: 'warn', encrypting: 'warn',
    }
    for (const state of diskStates) {
      const v = encryptionStatus(state)
      expect(v.status, state).toBe(want[state])
      expect(resolve(v.label), state).toBeTypeOf('string')
    }
    expect(resolve(encryptionStatus('compliant').label)).toBe('Encrypted')
    for (const none of ['', null, undefined] as const) {
      expect(encryptionStatus(none)).toEqual({ status: 'neutral', label: 'status.notReported' })
    }
  })

  it('maps outcomes, attention kinds with their rank, commands, revocations, tokens, rollouts, releases, locks, actors', () => {
    expect(outcomes.map((o) => outcomeStatus(o).status)).toEqual(['ok', 'warn', 'critical', 'neutral'])
    const kindStatus: Record<AttentionKind, Status> = {
      presumed_lost: 'critical', stale_critical: 'critical', quarantined: 'critical', revocation_expired: 'critical',
      stale_warning: 'warn', disk_not_compliant: 'warn', agent_outdated: 'warn', login_apply_failed: 'warn', sudo_apply_failed: 'warn',
      agent_rollback_pending: 'warn', agent_not_running: 'warn', uninstall_pending: 'warn', config_behind: 'warn',
      disk_conversion_failed: 'warn', clock_drift: 'warn', revocation_pending: 'info',
    }
    for (const kind of kinds) {
      expect(attentionStatus(kind), kind).toEqual({ status: kindStatus[kind], label: 'attention.kinds.' + kind })
      expect(attentionRank(kind), kind).toBe({ critical: 2, warn: 1, info: 0, ok: 0, neutral: 0 }[kindStatus[kind]])
      expect(resolve('attention.kinds.' + kind)).toBeTypeOf('string')
    }
    expect(commands.map((c) => commandStatus(c).status)).toEqual(['info', 'info', 'ok', 'critical', 'warn', 'neutral'])
    expect(revocations.map((r) => revocationStatus(r).status)).toEqual(['info', 'info', 'info', 'info', 'ok', 'critical', 'neutral', 'neutral', 'warn'])
    for (const r of revocations) expect(resolve(revocationStatus(r).label), r).toBeTypeOf('string')
    expect(tokenStatus('active')).toEqual({ status: 'ok', label: 'tokens.statuses.active' })
    expect(tokenStatus('expired').status).toBe('warn')
    expect(tokenStatus('revoked').status).toBe('neutral')
    expect(tokenStatus('exhausted').status).toBe('neutral')
    expect(tokenStatus('revoked', 'apiTokens.statuses').label).toBe('apiTokens.statuses.revoked')
    expect(rollouts.map((r) => rolloutStatus(r).status)).toEqual(['info', 'critical', 'ok'])
    expect(releaseStatus('draft').status).toBe('neutral')
    expect(releaseStatus('published').status).toBe('ok')
    const orgs: OrganizationStatus[] = ['active', 'provisioning', 'provisioning_failed', 'suspended']
    expect(orgs.map((o) => organizationStatus(o).status)).toEqual(['ok', 'info', 'critical', 'warn'])
    for (const o of orgs) expect(resolve(organizationStatus(o).label), o).toBeTypeOf('string')
    expect(userLockStatus(true)).toEqual({ status: 'critical', label: 'status.locked' })
    expect(userLockStatus(false)).toEqual({ status: 'ok', label: 'status.active' })
    expect(['admin', 'platform_admin', 'api_token'].map((a) => actorStatus(a).status)).toEqual(['info', 'info', 'info'])
    expect(['system', 'device', 'anonymous', 'later'].map((a) => actorStatus(a).status)).toEqual(['neutral', 'neutral', 'neutral', 'neutral'])
  })
})
