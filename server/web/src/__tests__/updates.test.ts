import { describe, expect, it } from 'vitest'
import type { AttentionKind } from '../api/client'
import {
  attentionFilter, attentionKinds, parsePackages, validateHold, validateSettings, validateStaleness, validPackage, validSchedule,
} from '../lib/updates'
import en from '../locales/en.json'

// A Record over the enum fails to compile when the API adds a kind, so the filter check below cannot miss one.
const everyKind: Record<AttentionKind, true> = {
  stale_warning: true, stale_critical: true, presumed_lost: true, quarantined: true, disk_not_compliant: true, agent_outdated: true,
  login_apply_failed: true, sudo_apply_failed: true, revocation_pending: true, revocation_expired: true, agent_rollback_pending: true,
  agent_not_running: true, uninstall_pending: true, config_behind: true, disk_conversion_failed: true, clock_drift: true, event_gap: true,
}

const settings = {
  security_daily_at: '03:00', regular_schedule: 'Sat 04:00', regular_updates_enabled: true, max_random_delay_min: 60,
  staleness_warning_h: 24, staleness_critical_h: 168,
}

describe('updates', () => {
  it('accepts the schedule subset of the server and nothing else', () => {
    for (const s of ['Sat 04:00', 'Mon,Thu 12:30', '02:00', 'Mon,Tue,Wed,Thu,Fri,Sat,Sun 23:59']) expect(validSchedule(s)).toBe(true)
    for (const s of ['Sat 4:00', 'Sat 24:00', 'Sat,Sat 04:00', 'sat 04:00', 'Mon..Fri 04:00', '*-*-* 04:00', 'Sat  04:00', '']) {
      expect(validSchedule(s)).toBe(false)
    }
  })

  it('validates the settings like the server', () => {
    expect(validateSettings(settings)).toEqual({})
    expect(validateSettings({ ...settings, security_daily_at: '3:00', regular_schedule: 'weekly' })).toEqual({
      security_daily_at: 'updates.settings.timeInvalid', regular_schedule: 'updates.settings.scheduleInvalid',
    })
    expect(validateSettings({ ...settings, max_random_delay_min: 721 }).max_random_delay_min).toBeTruthy()
    expect(validateSettings({ ...settings, staleness_warning_h: 0 }).staleness_warning_h).toBeTruthy()
    expect(validateSettings({ ...settings, staleness_critical_h: 24 }).staleness_critical_h).toBeTruthy()
    expect(validateSettings({ ...settings, staleness_critical_h: 2161 }).staleness_critical_h).toBeTruthy()
  })

  it('validates a pair of contact thresholds like updates.ValidateThresholds', () => {
    expect(validateStaleness(1, 2)).toEqual({})
    expect(validateStaleness(720, 2160)).toEqual({})
    expect(validateStaleness(0, 10)).toEqual({ warning_h: 'updates.settings.warningInvalid' })
    expect(validateStaleness(721, 2160)).toEqual({ warning_h: 'updates.settings.warningInvalid' })
    expect(validateStaleness(200, 100)).toEqual({ critical_h: 'updates.settings.criticalInvalid' })
    expect(validateStaleness(200, 200)).toEqual({ critical_h: 'updates.settings.criticalInvalid' })
    expect(validateStaleness(24, 2161)).toEqual({ critical_h: 'updates.settings.criticalInvalid' })
    expect(validateStaleness(1.5, 10)).toEqual({ warning_h: 'updates.settings.warningInvalid' })
    expect(validateStaleness('', '')).toEqual({ warning_h: 'updates.settings.warningInvalid', critical_h: 'updates.settings.criticalInvalid' })
  })

  it('validates holds and package names', () => {
    expect(validPackage('libstdc++6')).toBe(true)
    expect(validPackage('-oAPT')).toBe(false)
    expect(validateHold({ groupID: null, package: 'openssl', version: '', reason: '' })).toEqual({})
    expect(validateHold({ groupID: null, package: 'Open SSL', version: '1 0', reason: 'x'.repeat(501) })).toEqual({
      package: 'updates.holds.packageInvalid', version: 'updates.holds.versionInvalid', reason: 'updates.holds.reasonInvalid',
    })
  })

  it('splits the packages of install now and drops duplicates', () => {
    expect(parsePackages(' htop, curl\nhtop  openssl ')).toEqual(['htop', 'curl', 'openssl'])
    expect(parsePackages('  ')).toEqual([])
  })

  it('filters the attention list by every kind, each with a label and an action', () => {
    expect(attentionFilter.kind === 'enum' && attentionFilter.options.map((o) => o.value)).toEqual(attentionKinds)
    for (const k of attentionKinds) {
      expect(en.attention.kinds[k]).toBeTruthy()
      expect(en.attention.action[k]).toBeTruthy()
    }
    expect(attentionKinds).toContain('agent_rollback_pending')
  })

  it('offers every attention kind exactly once in the filter', () => {
    expect([...attentionKinds].sort()).toEqual(Object.keys(everyKind).sort())
    expect(attentionKinds).toContain('disk_conversion_failed')
  })
})
