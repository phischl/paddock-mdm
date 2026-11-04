import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SoftwareStateChip from '../components/SoftwareStateChip.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import type { DeviceSoftwareState } from '../api/client'

function chip(state: DeviceSoftwareState, extra: Record<string, unknown> = {}) {
  return mount(SoftwareStateChip, { props: { state, ...extra }, global: { plugins: [createPortalI18n(), vuetify] } }).find('.pd-chip')
}

describe('SoftwareStateChip (plan M13a decision 32)', () => {
  it.each([
    ['installed', 'Installed', 'ok'],
    ['held', 'Held', 'info'],
    ['absent', 'Not installed', 'neutral'],
    ['pending', 'Pending', 'warn'],
    ['failed', 'Failed', 'critical'],
    ['not_applicable', 'Not applicable', 'neutral'],
    ['unknown', 'No report yet', 'neutral'],
  ] as const)('%s reads %s with the %s look', (state, text, status) => {
    const c = chip(state)
    expect(c.text()).toBe(text)
    expect(c.classes()).toContain('pd-chip--' + status)
  })

  it('explains a pending state with the reason and a failed one with reason and error', () => {
    expect(chip('pending', { reason: 'dpkg_locked' }).attributes('title')).toBe('Another package operation is running; the device retries.')
    expect(chip('failed', { reason: 'no_candidate', error: 'E: Unable to locate package x' }).attributes('title')).toBe(
      "The package or version is not available from the device's sources. - E: Unable to locate package x",
    )
    expect(chip('failed', { reason: 'something_new' }).attributes('title')).toBe('something_new')
    expect(chip('installed', { reason: 'dpkg_locked' }).attributes('title')).toBeUndefined()
  })
})
