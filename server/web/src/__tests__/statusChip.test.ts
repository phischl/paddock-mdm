import { describe, expect, it } from 'vitest'
import { h } from 'vue'
import { mount } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import StatusChip from '../components/StatusChip.vue'
import SeverityChip from '../components/SeverityChip.vue'
import ActorChip from '../components/ActorChip.vue'
import TimeCell from '../components/TimeCell.vue'
import EmptyState from '../components/EmptyState.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

const mountIn = (component: unknown, props: Record<string, unknown>, slots?: Record<string, () => unknown>) =>
  mount(() => h(VApp, null, { default: () => h(component as never, props, slots) }), { global: { plugins: [createPortalI18n(), vuetify] } })

describe('StatusChip', () => {
  it('renders a hidden dot and the label, not a button', () => {
    const w = mountIn(StatusChip, { status: 'critical', label: 'Presumed lost', title: 'since 2026-09-30' })
    const chip = w.find('.pd-chip')
    expect(chip.element.tagName).toBe('SPAN')
    expect(chip.classes()).toContain('pd-chip--critical')
    expect(chip.find('.pd-chip-dot').attributes('aria-hidden')).toBe('true')
    expect(chip.text()).toBe('Presumed lost')
    expect(chip.attributes('title')).toBe('since 2026-09-30')
    expect(chip.find('button').exists()).toBe(false)
  })
})

describe('SeverityChip', () => {
  it('uses the severity scale with its own class per level', () => {
    for (const severity of ['critical', 'high', 'medium', 'low', 'unknown'] as const) {
      const w = mountIn(SeverityChip, { severity })
      expect(w.find('.pd-chip').classes()).toContain('pd-chip--sev-' + severity)
      expect(w.find('.pd-chip-dot').exists()).toBe(true)
    }
    expect(mountIn(SeverityChip, { severity: 'high' }).text()).toBe('High')
  })
})

describe('ActorChip', () => {
  it('shows the type chip and the display name in mono; nothing for a system actor without one', () => {
    const w = mountIn(ActorChip, { actor: { type: 'api_token', display: 'ci-inventory' } })
    expect(w.find('.pd-chip').text()).toBe('API token')
    expect(w.find('.pd-chip').classes()).toContain('pd-chip--info')
    expect(w.find('.mono').text()).toBe('ci-inventory')
    const system = mountIn(ActorChip, { actor: { type: 'system', display: '' } })
    expect(system.find('.pd-chip').text()).toBe('System')
    expect(system.find('.mono').exists()).toBe(false)
  })
})

describe('TimeCell', () => {
  it('is a time element in mono with the full value as tooltip', () => {
    const iso = new Date(2026, 8, 30, 17, 4, 9).toISOString()
    const w = mountIn(TimeCell, { iso, precision: 'second' })
    const time = w.find('time')
    expect(time.attributes('datetime')).toBe(iso)
    expect(time.attributes('title')).toBe('2026-09-30 17:04:09')
    expect(time.text()).toBe('2026-09-30 17:04:09')
    expect(time.classes()).toContain('mono')
    const relative = mountIn(TimeCell, { iso: new Date(Date.now() - 3 * 86400_000).toISOString(), mode: 'relative' })
    expect(relative.find('time').text()).toBe('3d ago')
  })
})

describe('EmptyState', () => {
  it('shows the icon, title, description and the action only when given', () => {
    const w = mountIn(EmptyState, { icon: 'folder', title: 'No device groups yet', description: 'Groups scope configuration.' }, {
      default: () => h('button', 'Create device group'),
    })
    expect(w.find('svg.pd-icon').attributes('aria-hidden')).toBe('true')
    expect(w.find('.pd-empty-title').text()).toBe('No device groups yet')
    expect(w.find('.pd-empty-text').text()).toBe('Groups scope configuration.')
    expect(w.find('.pd-empty-action button').text()).toBe('Create device group')
    const plain = mountIn(EmptyState, { icon: 'folder', title: 'No events', description: 'Widen the range.' })
    expect(plain.find('.pd-empty-action').exists()).toBe(false)
  })
})
