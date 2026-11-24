import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import MfaEnrolmentBanner from '../components/MfaEnrolmentBanner.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

let wrapper: VueWrapper | null = null

beforeEach(() => localStorage.clear())
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  vi.restoreAllMocks()
})

async function mountBanner(role: string, notice: { until: string; pending: number } | null, locale = 'en'): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale, organization: null,
    mfa_enrolment_notice: notice } as never
  const i18n = createPortalI18n()
  i18n.global.locale.value = locale as never
  wrapper = mount(() => h(VApp, null, { default: () => h(MfaEnrolmentBanner) }), {
    global: { plugins: [i18n, vuetify, pinia] }, attachTo: document.body,
  })
  await flushPromises()
}

function banner(): HTMLElement | null {
  return document.body.querySelector('[data-testid="mfa-enrolment-notice"]')
}

const until = '2026-12-14T10:00:00Z'

describe('the second-factor announcement (ADR 0053 decision 6)', () => {
  it.each(['org_admin', 'org_operator', 'org_auditor', 'platform_admin'])('shows %s the pending count until the end of the 30 days', async (role) => {
    await mountBanner(role, { until, pending: 3 })
    expect(banner()?.textContent).toContain('3 administrators have not set up a passkey yet')
    expect(banner()?.textContent).toContain('one-time sign-in setup link')
  })

  it('names one administrator in the singular and none when every administrator has a passkey', async () => {
    await mountBanner('org_admin', { until, pending: 1 })
    expect(banner()?.textContent).toContain('1 administrator has not set up a passkey yet')
    wrapper?.unmount()
    await mountBanner('org_admin', { until, pending: 0 })
    expect(banner()?.textContent).toContain('Every administrator now signs in with a passkey.')
  })

  it('is translated', async () => {
    await mountBanner('org_admin', { until, pending: 2 }, 'de')
    expect(banner()?.textContent).toContain('2 Administratoren haben noch keinen Passkey eingerichtet')
  })

  it('is not shown without an announcement (before the upgrade, after the 30 days)', async () => {
    await mountBanner('org_admin', null)
    expect(banner()).toBeNull()
  })

  it('stays dismissed for the same announcement and shows a new one again', async () => {
    await mountBanner('org_admin', { until, pending: 2 })
    const close = banner()?.querySelector<HTMLButtonElement>('button[aria-label="Dismiss"]')
    expect(close).not.toBeNull()
    close?.click()
    await flushPromises()
    expect(banner()).toBeNull()
    wrapper?.unmount()
    await mountBanner('org_admin', { until, pending: 2 })
    expect(banner()).toBeNull()
    wrapper?.unmount()
    await mountBanner('org_admin', { until: '2027-01-30T10:00:00Z', pending: 2 })
    expect(banner()).not.toBeNull()
  })

  it('still shows and closes when the browser refuses its storage', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('denied', 'SecurityError') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('denied', 'SecurityError') })
    await mountBanner('org_admin', { until, pending: 2 })
    expect(banner()?.textContent).toContain('2 administrators have not set up a passkey yet')
    banner()?.querySelector<HTMLButtonElement>('button[aria-label="Dismiss"]')?.click()
    await flushPromises()
    expect(banner()).toBeNull()
  })
})
