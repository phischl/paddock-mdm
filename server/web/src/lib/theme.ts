/** The account's theme preference (Me.theme). */
export type ThemePreference = 'system' | 'light' | 'dark'
/** The theme in effect. */
export type ResolvedTheme = 'light' | 'dark'

/** localStorage: the preference, an early-paint cache only; the account (GET /api/v1/me) is the truth. */
export const themeCacheKey = 'paddock.theme'

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === 'system' || value === 'light' || value === 'dark'
}

/** The cached preference; system when storage is unavailable or holds nothing usable. */
export function cachedPreference(): ThemePreference {
  try {
    const value = localStorage.getItem(themeCacheKey)
    return isThemePreference(value) ? value : 'system'
  } catch {
    return 'system'
  }
}

export function resolveTheme(pref: ThemePreference, systemDark: boolean): ResolvedTheme {
  if (pref === 'system') return systemDark ? 'dark' : 'light'
  return pref
}

export function vuetifyThemeName(resolved: ResolvedTheme): 'paddockLight' | 'paddockDark' {
  return resolved === 'dark' ? 'paddockDark' : 'paddockLight'
}

const darkQuery = '(prefers-color-scheme: dark)'

export function systemPrefersDark(): boolean {
  return typeof matchMedia === 'function' && matchMedia(darkQuery).matches
}

let preference: ThemePreference = 'system'
let subscribed = false
let switcher: ((name: 'paddockLight' | 'paddockDark') => void) | null = null

/**
 * Registers how the Vuetify theme is switched (plugins/vuetify.ts does, with change(name, false): no cross-fade,
 * design spec §6). Injected so this module stays free of the Vuetify instance and the plugin can use the pure
 * functions above for the first paint without an import cycle.
 */
export function installThemeSwitcher(fn: (name: 'paddockLight' | 'paddockDark') => void): void {
  switcher = fn
}

function apply(resolved: ResolvedTheme): void {
  switcher?.(vuetifyThemeName(resolved))
  document.documentElement.dataset.theme = resolved
}

/** Applies a preference now, caches it and keeps following the system while the preference is system. */
export function applyTheme(pref: ThemePreference): void {
  preference = pref
  apply(resolveTheme(pref, systemPrefersDark()))
  try {
    localStorage.setItem(themeCacheKey, pref)
  } catch {
    // Not cached; the first paint of the next visit uses the default until GET /me answers.
  }
  if (!subscribed && typeof matchMedia === 'function') {
    subscribed = true
    matchMedia(darkQuery).addEventListener('change', (e) => {
      if (preference === 'system') apply(resolveTheme('system', e.matches))
    })
  }
}

/** The theme in effect now. */
export function currentTheme(): ResolvedTheme {
  return resolveTheme(preference, systemPrefersDark())
}
