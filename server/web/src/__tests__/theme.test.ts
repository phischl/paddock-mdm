import { afterEach, describe, expect, it } from 'vitest'
import tokensCss from '../styles/tokens.css?raw'
import { paddockDark, paddockLight, pdTokens } from '../plugins/theme'
import { cachedPreference, resolveTheme, themeCacheKey, vuetifyThemeName } from '../lib/theme'

/** The declarations of one CSS block, selected by its exact selector text. */
function block(selector: string): Record<string, string> {
  const start = tokensCss.indexOf(selector + ' {')
  expect(start, `block ${selector}`).toBeGreaterThanOrEqual(0)
  const body = tokensCss.slice(start + selector.length + 2, tokensCss.indexOf('}', start))
  return Object.fromEntries(
    body
      .split(';')
      .map((d: string) => d.trim())
      .filter((d: string) => d !== '')
      .map((d: string) => {
        const i = d.indexOf(':')
        return [d.slice(0, i).trim(), d.slice(i + 1).trim()]
      }),
  )
}

describe('tokens.css mirrors plugins/theme.ts (ADR 0023)', () => {
  it('light block', () => {
    expect(block(':root, :root[data-theme="light"]')).toEqual(pdTokens.light)
  })
  it('dark block', () => {
    expect(block(':root[data-theme="dark"]')).toEqual(pdTokens.dark)
  })
  it('system fallback block equals the dark tokens', () => {
    expect(block(':root:not([data-theme="light"])')).toEqual(pdTokens.dark)
  })
  it('both themes define the same token names', () => {
    expect(Object.keys(pdTokens.dark).sort()).toEqual(Object.keys(pdTokens.light).sort())
  })
  it('Vuetify themes carry the spec surfaces and accent', () => {
    expect(paddockLight.colors?.background).toBe(pdTokens.light['--pd-surface-0'])
    expect(paddockLight.colors?.primary).toBe(pdTokens.light['--pd-accent'])
    expect(paddockDark.colors?.background).toBe(pdTokens.dark['--pd-surface-0'])
    expect(paddockDark.colors?.primary).toBe(pdTokens.dark['--pd-accent'])
    expect(paddockDark.dark).toBe(true)
  })
})

describe('resolveTheme', () => {
  it.each([
    ['system', true, 'dark'],
    ['system', false, 'light'],
    ['light', true, 'light'],
    ['dark', false, 'dark'],
  ] as const)('%s with systemDark=%s → %s', (pref, systemDark, want) => {
    expect(resolveTheme(pref, systemDark)).toBe(want)
    expect(vuetifyThemeName(want)).toBe(want === 'dark' ? 'paddockDark' : 'paddockLight')
  })
})

describe('cachedPreference', () => {
  afterEach(() => localStorage.removeItem(themeCacheKey))
  it('falls back to system without a usable value', () => {
    expect(cachedPreference()).toBe('system')
    localStorage.setItem(themeCacheKey, 'neon')
    expect(cachedPreference()).toBe('system')
  })
  it('reads a stored preference', () => {
    localStorage.setItem(themeCacheKey, 'dark')
    expect(cachedPreference()).toBe('dark')
  })
})
