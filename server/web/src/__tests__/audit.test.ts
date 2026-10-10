import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AuditEvent } from '../api/client'
import AuditEventList from '../components/AuditEventList.vue'
import { createPortalI18n } from '../i18n'
import { auditText } from '../lib/format'
import { vuetify } from '../plugins/vuetify'

const deviceID = '0199c0a0-0000-7000-8000-0000000000d1'
function eventOf(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    event_id: 'e1', occurred_at: '2026-10-10T12:00:05Z', recorded_at: '2026-10-10T12:00:05Z', code: 'device.approved', outcome: 'success',
    source: 'admin-api', correlation_id: 'corr-1', actor: { type: 'admin', display: 'alice@acme.test', ip: '10.0.0.1', step_up: false },
    target: { type: 'device', id: deviceID, display: '' }, params: {}, device: { id: deviceID, hostname: 'acme-lt-0142' }, ...over,
  } as AuditEvent
}

describe('audit texts with the device resolved at read time (plan M7c decision 32)', () => {
  const { t, te } = createPortalI18n().global
  it('names the device by its hostname instead of its id when the stored event has neither', () => {
    expect(auditText(t, te, eventOf())).toBe('alice@acme.test approved the device acme-lt-0142')
    const applied = eventOf({ code: 'device.bundle_applied', params: { bundle_version: 3 }, actor: { type: 'device', step_up: false } })
    expect(auditText(t, te, applied)).toBe('The device acme-lt-0142 applied bundle 3')
  })

  it('keeps the stored hostname and display, and falls back to the id only without a known device', () => {
    expect(auditText(t, te, eventOf({ params: { hostname: 'old-name' } }))).toBe('alice@acme.test approved the device old-name')
    expect(auditText(t, te, eventOf({ target: { type: 'device', id: deviceID, display: 'lt-at-the-time' } })))
      .toBe('alice@acme.test approved the device lt-at-the-time')
    expect(auditText(t, te, eventOf({ device: { id: deviceID, hostname: null } }))).toBe(`alice@acme.test approved the device ${deviceID}`)
  })

  it('does not change the stored params', () => {
    const ev = eventOf({ params: { device_id: deviceID } })
    auditText(t, te, ev)
    expect(ev.params).toEqual({ device_id: deviceID })
  })
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountList(events: AuditEvent[], showDevice = true): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const stub = { render: () => null }
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/audit', component: stub }, { path: '/devices/:id', name: 'device', component: stub }] })
  await router.push('/audit')
  const fetch = () => Promise.resolve({ items: events, page: 1, page_size: 25, total: events.length, total_capped: false, sort: '-occurred_at' })
  wrapper = mount(() => h(VApp, null, { default: () => h(AuditEventList, { fetch, showDevice }) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('audit event list (plan M7c decisions 32 and 34)', () => {
  it('shows time, actor chip, sentence, device link, code and outcome chip', async () => {
    const w = await mountList([eventOf()])
    const headers = w.findAll('th').map((th) => th.text()).filter(Boolean)
    expect(headers).toEqual(['Time', 'Actor', 'Event', 'Device', 'Code', 'Outcome'])
    const row = w.find('tbody tr')
    expect(row.find('time').attributes('datetime')).toBe('2026-10-10T12:00:05Z')
    expect(row.find('.pd-actor').text()).toContain('Administrator')
    expect(row.text()).toContain('alice@acme.test approved the device acme-lt-0142')
    expect(row.find(`a[href="/devices/${deviceID}"]`).text()).toBe('acme-lt-0142')
    expect(row.find('.outcome').text()).toBe('Success')
  })

  it('expands a row to the stored fields with the params unchanged', async () => {
    const w = await mountList([eventOf({ params: { device_id: deviceID, reason: 'stolen' } })])
    const toggle = w.find('button[aria-expanded]')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    await toggle.trigger('click')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    const details = w.find('[data-testid="audit-details"]').text()
    expect(details).toContain('corr-1')
    expect(details).toContain('params.reason')
    expect(details).toContain('stolen')
  })

  it('leaves out the device column on the device tab', async () => {
    const w = await mountList([eventOf()], false)
    expect(w.findAll('th').map((th) => th.text())).not.toContain('Device')
  })
})
