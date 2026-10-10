import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h, ref } from 'vue'
import { VApp } from 'vuetify/components'
import CommandPalette from '../components/CommandPalette.vue'
import { createPortalI18n } from '../i18n'
import type { PaletteContext } from '../lib/commands'
import { vuetify } from '../plugins/vuetify'

// jsdom does not lay out; the palette scrolls the active option into view.
Element.prototype.scrollIntoView ??= () => undefined

const go = vi.fn()
const openHelp = vi.fn()
const goDangerZone = vi.fn()
const i18n = createPortalI18n()
const context: PaletteContext = {
  pages: [{ to: '/', label: 'Overview', shortcut: 'g o' }, { to: '/devices', label: 'Devices', shortcut: 'g d' }],
  canReadDevices: true, preference: 'system', resolvedTheme: 'light', locale: 'en', navCollapsed: false, density: 'compact',
  deviceHostname: 'acme-lt-0142',
  t: (key, values) => i18n.global.t(key, values ?? {}),
  go, setTheme: vi.fn(), setLocale: vi.fn(), toggleNav: vi.fn(), openHelp, setDensity: vi.fn(), goDangerZone,
  fetchDevices: () => Promise.resolve([{ id: 'd1', hostname: 'acme-lt-0142' }]),
  fetchGroups: () => Promise.resolve([{ id: 'g1', name: 'Acme laptops' }]),
}

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  vi.clearAllMocks()
  vi.useRealTimers()
})

async function openPalette(): Promise<{ open: ReturnType<typeof ref<boolean>> }> {
  const open = ref(false)
  wrapper = mount(() => h(VApp, null, {
    default: () => h(CommandPalette, { modelValue: open.value, context, 'onUpdate:modelValue': (v: boolean) => (open.value = v) }),
  }), { global: { plugins: [i18n, vuetify] }, attachTo: document.body })
  open.value = true
  await flushPromises()
  return { open }
}

const input = () => document.querySelector<HTMLInputElement>('[data-testid="palette-input"]')!
const options = () => [...document.querySelectorAll<HTMLElement>('[role="option"]')]
const key = async (k: string) => {
  input().dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }))
  await flushPromises()
}

describe('command palette (plan M7c decision 16)', () => {
  it('is a combobox over a listbox of grouped options with the active one announced', async () => {
    await openPalette()
    expect(input().getAttribute('role')).toBe('combobox')
    const listbox = document.getElementById(input().getAttribute('aria-controls')!)
    expect(listbox?.getAttribute('role')).toBe('listbox')
    expect([...listbox!.querySelectorAll('[role="presentation"]')].map((g) => g.textContent?.trim())).toEqual(['Pages', 'Actions'])
    const first = options()[0]
    expect(first.textContent).toContain('Overview')
    expect(input().getAttribute('aria-activedescendant')).toBe(first.id)
    expect(first.getAttribute('aria-selected')).toBe('true')
  })

  it('moves with Up and Down, wraps, and runs the active option with Enter, then closes', async () => {
    const { open } = await openPalette()
    await key('ArrowDown')
    expect(input().getAttribute('aria-activedescendant')).toBe(options()[1].id)
    expect(options()[1].textContent).toContain('Devices')
    await key('ArrowUp')
    await key('ArrowUp')
    expect(input().getAttribute('aria-activedescendant')).toBe(options()[options().length - 1].id)
    await key('ArrowDown')
    await key('ArrowDown')
    await key('Enter')
    expect(go).toHaveBeenCalledWith('/devices')
    expect(open.value).toBe(false)
  })

  it('closes on Esc without running anything', async () => {
    const { open } = await openPalette()
    await key('Escape')
    expect(open.value).toBe(false)
    expect(go).not.toHaveBeenCalled()
  })

  it('finds devices and groups after typing, and never offers a destructive or security-relevant action', async () => {
    vi.useFakeTimers()
    await openPalette()
    input().value = 'acme'
    input().dispatchEvent(new Event('input'))
    await vi.advanceTimersByTimeAsync(200)
    await flushPromises()
    const labels = options().map((o) => o.textContent ?? '')
    expect(labels.some((l) => l.includes('acme-lt-0142'))).toBe(true)
    expect(labels.some((l) => l.includes('Acme laptops'))).toBe(true)
    // Every entry the palette can show for an empty query (all actions, including the device-page one).
    input().value = ''
    input().dispatchEvent(new Event('input'))
    await vi.advanceTimersByTimeAsync(200)
    await flushPromises()
    const all = options().map((o) => o.textContent ?? '')
    expect(all.some((l) => l.includes('danger zone'))).toBe(true)
    for (const label of all.filter((l) => !l.includes('danger zone'))) {
      expect(label).not.toMatch(/lock|destroy|retire|revoke|reveal|rotate|suspend|approve|install/i)
    }
    // The danger-zone entry only navigates there.
    options().find((o) => o.textContent?.includes('danger zone'))!.click()
    expect(goDangerZone).toHaveBeenCalled()
  })
})
