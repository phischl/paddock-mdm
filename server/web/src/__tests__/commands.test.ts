import { describe, expect, it, vi } from 'vitest'
import { paletteActions, paletteEntries, type PaletteContext } from '../lib/commands'
import en from '../locales/en.json'

function context(extra: Partial<PaletteContext> = {}): PaletteContext & { calls: string[] } {
  const calls: string[] = []
  const resolve = (key: string): string => key.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown>)?.[k], en) as string
  return {
    calls,
    pages: [
      { to: '/', label: 'Overview', shortcut: 'g o' },
      { to: '/devices', label: 'Devices', shortcut: 'g d' },
      { to: '/device-groups', label: 'Device groups' },
      { to: '/audit', label: 'Audit log', shortcut: 'g l' },
    ],
    canReadDevices: true,
    preference: 'system',
    resolvedTheme: 'light',
    locale: 'en',
    navCollapsed: false,
    density: 'compact',
    t: (key, values) => {
      let text = resolve(key) ?? key
      for (const [k, v] of Object.entries(values ?? {})) text = text.replace(`{${k}}`, String(v))
      return text
    },
    go: (to) => calls.push('go ' + to),
    setTheme: (p) => calls.push('theme ' + p),
    setLocale: (l) => calls.push('locale ' + l),
    toggleNav: () => calls.push('nav'),
    openHelp: () => calls.push('help'),
    setDensity: (d) => calls.push('density ' + d),
    goDangerZone: () => calls.push('danger'),
    fetchDevices: vi.fn((q: string) => Promise.resolve(q === 'acme' ? [{ id: 'd1', hostname: 'acme-lt-0142' }] : [])),
    fetchGroups: vi.fn((q: string) => Promise.resolve(q === 'acme' ? [{ id: 'g1', hostname: '', name: 'Acme laptops' }] : [])),
    ...extra,
  }
}

describe('paletteEntries (plan M7c decision 16)', () => {
  it('lists every page and action for an empty query, in group order, without searching', async () => {
    const ctx = context()
    const entries = await paletteEntries('', ctx)
    expect(entries.map((e) => e.group)).toEqual(['pages', 'pages', 'pages', 'pages', ...Array(6).fill('actions')])
    expect(entries[1]).toMatchObject({ label: 'Devices', hint: 'g d' })
    expect(ctx.fetchDevices).not.toHaveBeenCalled()
    entries[1].run()
    expect(ctx.calls).toEqual(['go /devices'])
  })

  it('matches pages by a case-insensitive substring of the label', async () => {
    const entries = await paletteEntries('GROUP', context())
    expect(entries.filter((e) => e.group === 'pages').map((e) => e.label)).toEqual(['Device groups'])
  })

  it('searches devices and groups from two characters when the role may read devices', async () => {
    const ctx = context()
    expect((await paletteEntries('a', ctx)).filter((e) => e.group === 'devices')).toEqual([])
    expect(ctx.fetchDevices).not.toHaveBeenCalled()
    const entries = await paletteEntries('acme', ctx)
    expect(entries.filter((e) => e.group === 'devices').map((e) => e.label)).toEqual(['acme-lt-0142'])
    expect(entries.filter((e) => e.group === 'groups').map((e) => e.label)).toEqual(['Acme laptops'])
    entries.find((e) => e.group === 'devices')?.run()
    entries.find((e) => e.group === 'groups')?.run()
    expect(ctx.calls).toEqual(['go /devices/d1', 'go /device-groups/g1'])
    const reader = context({ canReadDevices: false })
    await paletteEntries('acme', reader)
    expect(reader.fetchDevices).not.toHaveBeenCalled()
  })

  it('offers to open a CVE id', async () => {
    const ctx = context()
    const entries = await paletteEntries('cve-2026-31337', ctx)
    const cve = entries.filter((e) => e.group === 'cve')
    expect(cve.map((e) => e.label)).toEqual(['Open CVE-2026-31337'])
    cve[0].run()
    expect(ctx.calls).toEqual(['go /vulnerabilities/CVE-2026-31337'])
    expect((await paletteEntries('CVE-2026', ctx)).filter((e) => e.group === 'cve')).toEqual([])
  })

  it('phrases the actions by the current state', async () => {
    const light = paletteActions(context()).map((a) => a.label)
    expect(light).toEqual([
      'Switch to the dark theme', 'Use the system theme', 'Switch to Deutsch', 'Collapse the navigation', 'Keyboard shortcuts', 'Comfortable density',
    ])
    const dark = paletteActions(context({ resolvedTheme: 'dark', locale: 'de', navCollapsed: true, density: 'comfortable', deviceHostname: 'acme-lt-0142' }))
    expect(dark.map((a) => a.label)).toEqual([
      'Switch to the light theme', 'Use the system theme', 'Switch to English', 'Expand the navigation', 'Keyboard shortcuts', 'Compact density',
      'Go to the danger zone of acme-lt-0142',
    ])
    const ctx = context({ resolvedTheme: 'dark', deviceHostname: 'h' })
    for (const a of paletteActions(ctx)) a.run()
    expect(ctx.calls).toEqual(['theme light', 'theme system', 'locale de', 'nav', 'help', 'density comfortable', 'danger'])
  })

  it('never offers a destructive or security-relevant action', async () => {
    const ctx = context({ deviceHostname: 'acme-lt-0142' })
    const all = [...(await paletteEntries('', ctx)), ...(await paletteEntries('acme', ctx)), ...(await paletteEntries('lock', ctx))]
    for (const e of all) {
      expect(e.label).not.toMatch(/lock|destroy|retire|revoke|reveal|rotate|suspend|approve|install/i)
    }
    const labels = Object.values(en.palette.actions)
    for (const label of labels) expect(label).not.toMatch(/lock|destroy|retire|revoke|reveal|rotate|suspend|approve|install/i)
  })
})
