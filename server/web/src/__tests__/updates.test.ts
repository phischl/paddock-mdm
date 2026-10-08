import { describe, expect, it } from 'vitest'
import {
  attentionFilter, attentionKinds, parsePackages, validateHold, validateSettings, validPackage, validSchedule,
} from '../lib/updates'
import en from '../locales/en.json'

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
  })
})
