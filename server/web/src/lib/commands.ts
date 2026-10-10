import { api } from '../api/client'
import type { PortalLocale } from '../i18n'
import type { ThemePreference } from './theme'

/**
 * The entries of the command palette (plan M7c decision 16): pages, devices, device groups, a CVE and
 * non-destructive actions. Nothing here locks, destroys, retires, reveals, rotates, suspends, revokes, approves or
 * installs — those stay behind their confirm dialogs on the pages.
 */
export type PaletteGroup = 'pages' | 'devices' | 'groups' | 'cve' | 'actions'

export interface PaletteEntry {
  id: string
  group: PaletteGroup
  label: string
  hint?: string
  run: () => void
}

export type Density = 'compact' | 'comfortable'

export interface PaletteContext {
  pages: { to: string; label: string; shortcut?: string }[]
  canReadDevices: boolean
  preference: ThemePreference
  resolvedTheme: 'light' | 'dark'
  locale: PortalLocale
  navCollapsed: boolean
  density: Density
  /** The hostname of the device page shown, when one is. */
  deviceHostname?: string
  t: (key: string, values?: Record<string, string | number>) => string
  go(to: string): void
  setTheme(pref: ThemePreference): void
  setLocale(locale: PortalLocale): void
  toggleNav(): void
  openHelp(): void
  setDensity(density: Density): void
  goDangerZone(): void
  fetchDevices(q: string): Promise<{ id: string; hostname: string }[]>
  fetchGroups(q: string): Promise<{ id: string; name: string }[]>
}

/** Characters before the device and group searches start (list contract minimum). */
export const paletteSearchMin = 2
const cvePattern = /^CVE-\d{4}-\d{4,}$/i

export async function fetchPaletteDevices(q: string): Promise<{ id: string; hostname: string }[]> {
  const { data } = await api.GET('/api/v1/devices', { params: { query: { q, page_size: 10, sort: 'hostname' } } })
  return data?.items.map((d) => ({ id: d.id, hostname: d.hostname })) ?? []
}

/** Device groups shown in the palette; the list contract has no page size below 10, so the page is cut here. */
export const paletteGroupLimit = 5

export async function fetchPaletteGroups(q: string): Promise<{ id: string; name: string }[]> {
  const { data } = await api.GET('/api/v1/device-groups', { params: { query: { q, page_size: 10, sort: 'name' } } })
  return data?.items.slice(0, paletteGroupLimit).map((g) => ({ id: g.id, name: g.name })) ?? []
}

function matches(label: string, query: string): boolean {
  return query === '' || label.toLowerCase().includes(query.toLowerCase())
}

/** The static, non-destructive actions. */
export function paletteActions(ctx: PaletteContext): PaletteEntry[] {
  const other = ctx.resolvedTheme === 'dark' ? 'light' : 'dark'
  const entries: PaletteEntry[] = [
    { id: 'theme-toggle', group: 'actions', label: ctx.t(`palette.actions.${other}Theme`), run: () => ctx.setTheme(other) },
    { id: 'theme-system', group: 'actions', label: ctx.t('palette.actions.systemTheme'), run: () => ctx.setTheme('system') },
    {
      id: 'language', group: 'actions', label: ctx.t('palette.actions.language', { language: ctx.t('app.languages.' + (ctx.locale === 'de' ? 'en' : 'de')) }),
      run: () => ctx.setLocale(ctx.locale === 'de' ? 'en' : 'de'),
    },
    { id: 'nav', group: 'actions', label: ctx.t(ctx.navCollapsed ? 'palette.actions.expandNav' : 'palette.actions.collapseNav'), hint: '[', run: () => ctx.toggleNav() },
    { id: 'shortcuts', group: 'actions', label: ctx.t('palette.actions.shortcuts'), hint: '?', run: () => ctx.openHelp() },
    {
      id: 'density', group: 'actions', label: ctx.t(ctx.density === 'compact' ? 'palette.actions.comfortable' : 'palette.actions.compact'),
      run: () => ctx.setDensity(ctx.density === 'compact' ? 'comfortable' : 'compact'),
    },
  ]
  if (ctx.deviceHostname) {
    entries.push({ id: 'danger-zone', group: 'actions', label: ctx.t('palette.actions.dangerZone', { hostname: ctx.deviceHostname }), run: () => ctx.goDangerZone() })
  }
  return entries
}

/** The entries for a query, grouped in the order pages, devices, groups, CVE, actions. */
export async function paletteEntries(query: string, ctx: PaletteContext): Promise<PaletteEntry[]> {
  const q = query.trim()
  const pages: PaletteEntry[] = ctx.pages
    .filter((p) => matches(p.label, q))
    .map((p) => ({ id: 'page:' + p.to, group: 'pages', label: p.label, hint: p.shortcut, run: () => ctx.go(p.to) }))
  const actions = paletteActions(ctx).filter((a) => matches(a.label, q))
  const cve: PaletteEntry[] = cvePattern.test(q)
    ? [{ id: 'cve:' + q.toUpperCase(), group: 'cve', label: ctx.t('palette.openCve', { cve: q.toUpperCase() }), run: () => ctx.go('/vulnerabilities/' + q.toUpperCase()) }]
    : []
  let devices: PaletteEntry[] = []
  let groups: PaletteEntry[] = []
  if (ctx.canReadDevices && [...q].length >= paletteSearchMin) {
    const [d, g] = await Promise.all([ctx.fetchDevices(q), ctx.fetchGroups(q)])
    devices = d.map((x) => ({ id: 'device:' + x.id, group: 'devices', label: x.hostname, run: () => ctx.go('/devices/' + x.id) }))
    groups = g.map((x) => ({ id: 'group:' + x.id, group: 'groups', label: x.name, run: () => ctx.go('/device-groups/' + x.id) }))
  }
  return [...pages, ...devices, ...groups, ...cve, ...actions]
}
