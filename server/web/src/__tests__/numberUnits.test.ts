import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DMSSettings, LoginSettings, UpdateSettings } from '../api/client'
import DeviceGroupForm from '../components/DeviceGroupForm.vue'
import ProfileForm from '../components/ProfileForm.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import DMSSettingsView from '../views/DMSSettings.vue'
import LoginSettingsView from '../views/LoginSettings.vue'
import UpdateSettingsView from '../views/UpdateSettings.vue'

vi.mock('../lib/loginSettings', async (original) => ({
  ...(await original<typeof import('../lib/loginSettings')>()),
  getLoginSettings: () => Promise.resolve({
    hello_enabled: true, hello_pin_min_length: 6, user_lock_session_action: 'lock_screen', break_glass_accounts: [],
    sudoers_d_allowlist: [], sudo_lecture_text: '', local_admin_username: 'paddock-admin', local_admin_rotation_days: 30,
    rotate_after_reveal_hours: 4, notice_text: '', boot_pin_min_length: 8, login_history_enabled: true,
    login_history_days: 90, disk_unlock_mode: 'tpm_pin', updated_at: '2026-10-25T10:00:00Z',
  } as LoginSettings),
}))
vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  getUpdateSettings: () => Promise.resolve({
    security_daily_at: '03:00', regular_schedule: 'Sat 04:00', regular_updates_enabled: true, max_random_delay_min: 60,
    staleness_warning_h: 24, staleness_critical_h: 168, updated_at: '2026-10-25T10:00:00Z',
  } as UpdateSettings),
}))
vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  getDMS: () => Promise.resolve({ enabled: false, period_days: 30, warn_days: [3, 1], updated_at: '2026-10-25T10:00:00Z' } as DMSSettings),
}))

let wrapper: VueWrapper | null = null
beforeEach(() => {
  setActivePinia(createPinia())
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountInApp(view: object, locale: PortalLocale, props: Record<string, unknown> = {}): Promise<void> {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { render: () => null } }] })
  await router.push('/')
  const Frame = defineComponent({ setup: () => () => h(VApp, null, { default: () => h(view, props) }) })
  wrapper = mount(Frame, { global: { plugins: [createPortalI18n(locale), vuetify, router] }, attachTo: document.body })
  await flushPromises()
}

/** The visible text of the Vuetify field around the input with this id: label, suffix and hint. */
function field(id: string): { label: string; suffix: string; hint: string } {
  const root = document.getElementById(id)?.closest('.v-input')
  return {
    label: root?.querySelector('label')?.textContent?.trim() ?? '',
    suffix: root?.querySelector('.v-text-field__suffix')?.textContent?.trim() ?? '',
    hint: root?.querySelector('.v-messages')?.textContent?.trim() ?? '',
  }
}

// PDK-429: the unit stood at the end of a long label and was cut off in narrow fields.
describe('number fields show their unit as a suffix (PDK-429)', () => {
  it.each([
    ['en', 'Password rotation interval', 'days', '1–365 days', 'Rotation after a reveal', 'hours', 'History retention'],
    ['de', 'Rotationsintervall Passwort', 'Tage', '1–365 Tage', 'Rotation nach einer Anzeige', 'Stunden', 'Aufbewahrung des Verlaufs'],
  ] as const)('login settings in %s', async (locale, rotationLabel, days, rotationRange, revealLabel, hours, historyLabel) => {
    await mountInApp(LoginSettingsView, locale)
    expect(field('settings-rotation-days')).toEqual({ label: rotationLabel, suffix: days, hint: rotationRange })
    const reveal = field('settings-reveal-hours')
    expect(reveal.label).toBe(revealLabel)
    expect(reveal.suffix).toBe(hours)
    expect(reveal.hint).toContain(`1–168 ${hours}`)
    expect(field('settings-login-history-days')).toEqual({ label: historyLabel, suffix: days, hint: `7–365 ${days}` })
  })

  it('update settings', async () => {
    await mountInApp(UpdateSettingsView, 'en')
    expect(field('max-random-delay').suffix).toBe('minutes')
    expect(field('staleness-warning')).toEqual({ label: 'Warning after no contact for', suffix: 'hours', hint: '1–720 hours.' })
    expect(field('staleness-critical').suffix).toBe('hours')
    expect(field('staleness-critical').hint).toContain('at most 2160 hours')
  })

  it('dead man\'s switch period', async () => {
    await mountInApp(DMSSettingsView, 'de')
    expect(field('dms-period').label).toBe('Frist')
    expect(field('dms-period').suffix).toBe('Tage')
    expect(field('dms-period').hint).toContain('7–365 Tage')
  })

  it('permission profile password timeout', async () => {
    await mountInApp(ProfileForm, 'en', { submitLabel: 'Create' })
    expect(field('profile-timeout')).toEqual({ label: 'Password remembered for', suffix: 'minutes', hint: '0–60 minutes' })
  })

  it('device group staleness override', async () => {
    await mountInApp(DeviceGroupForm, 'de', { submitLabel: 'Anlegen' })
    expect(field('device-group-staleness-warning').suffix).toBe('Stunden')
    expect(field('device-group-staleness-warning').hint).toBe('1–720 Stunden ohne Kontakt.')
    expect(field('device-group-staleness-critical').suffix).toBe('Stunden')
  })
})

// PDK-461: the security-update time label was cut off at 375 px in German. jsdom does no layout, so the width itself is
// checked in the browser; this pins the full label in every locale.
describe('security-update time field (PDK-461)', () => {
  it.each([
    ['en', 'Time of the security updates'],
    ['de', 'Uhrzeit der Sicherheitsupdates'],
  ] as const)('shows the full label in %s', async (locale, label) => {
    await mountInApp(UpdateSettingsView, locale)
    expect(field('security-daily-at').label).toBe(label)
  })
})
