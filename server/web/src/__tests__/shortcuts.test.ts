import { describe, expect, it } from 'vitest'
import { resolveShortcut, sequenceTimeout, type KeyContext, type ShortcutState } from '../composables/useShortcuts'

const key = (k: string, extra: Partial<KeyContext> = {}): KeyContext => ({
  key: k, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, inInput: false, onControl: false, overlayOpen: false, dialogOpen: false, ...extra,
})
const state = (extra: Partial<ShortcutState> = {}): ShortcutState => ({ pendingG: null, now: 10_000, singleKey: true, ...extra })

describe('resolveShortcut (plan M7c decision 17)', () => {
  it('opens the palette with Ctrl K or ⌘ K, also inside inputs, not inside a dialog', () => {
    expect(resolveShortcut(key('k', { ctrlKey: true }), state()).action).toEqual({ kind: 'palette' })
    expect(resolveShortcut(key('K', { metaKey: true, inInput: true }), state()).action).toEqual({ kind: 'palette' })
    expect(resolveShortcut(key('k', { ctrlKey: true, dialogOpen: true }), state()).action).toBeNull()
    expect(resolveShortcut(key('k', { ctrlKey: true }), state({ singleKey: false })).action).toEqual({ kind: 'palette' })
  })

  it('maps the single keys and / to their actions', () => {
    expect(resolveShortcut(key('/'), state()).action).toEqual({ kind: 'palette' })
    expect(resolveShortcut(key('?'), state()).action).toEqual({ kind: 'help' })
    expect(resolveShortcut(key('['), state()).action).toEqual({ kind: 'nav' })
    expect(resolveShortcut(key('j'), state()).action).toEqual({ kind: 'list', action: 'down' })
    expect(resolveShortcut(key('k'), state()).action).toEqual({ kind: 'list', action: 'up' })
    expect(resolveShortcut(key('o'), state()).action).toEqual({ kind: 'list', action: 'open' })
    expect(resolveShortcut(key('Enter'), state()).action).toEqual({ kind: 'list', action: 'open' })
    expect(resolveShortcut(key('Enter', { onControl: true }), state()).action).toBeNull()
    expect(resolveShortcut(key('x'), state()).action).toBeNull()
  })

  it('ignores single keys in inputs and while an overlay is open', () => {
    for (const k of ['/', '?', '[', 'j', 'k', 'o', 'g']) {
      expect(resolveShortcut(key(k, { inInput: true }), state()).action, k).toBeNull()
      expect(resolveShortcut(key(k, { overlayOpen: true }), state()).action, k).toBeNull()
    }
    expect(resolveShortcut(key('g', { inInput: true }), state()).pendingG).toBeNull()
  })

  it('ignores letters with a modifier so browser shortcuts keep working', () => {
    expect(resolveShortcut(key('j', { ctrlKey: true }), state()).action).toBeNull()
    expect(resolveShortcut(key('/', { metaKey: true }), state()).action).toBeNull()
    expect(resolveShortcut(key('?', { altKey: true }), state()).action).toBeNull()
  })

  it('runs g-sequences within one second and forgets a stale g', () => {
    const first = resolveShortcut(key('g'), state())
    expect(first).toEqual({ action: null, pendingG: 10_000 })
    expect(resolveShortcut(key('d'), state({ pendingG: 10_000, now: 10_000 + sequenceTimeout })).action).toEqual({ kind: 'go', key: 'd' })
    for (const k of ['o', 'a', 's', 'v', 'l']) {
      expect(resolveShortcut(key(k), state({ pendingG: 10_000, now: 10_500 })).action).toEqual({ kind: 'go', key: k })
    }
    // Too late: d is no longer a sequence key and, alone, has no meaning.
    expect(resolveShortcut(key('d'), state({ pendingG: 10_000, now: 10_000 + sequenceTimeout + 1 }))).toEqual({ action: null, pendingG: null })
    // An unknown second key ends the sequence without an action.
    expect(resolveShortcut(key('x'), state({ pendingG: 10_000, now: 10_100 }))).toEqual({ action: null, pendingG: null })
    // j right after g is the sequence's second key, not the row cursor.
    expect(resolveShortcut(key('j'), state({ pendingG: 10_000, now: 10_100 })).action).toBeNull()
  })

  it('switches device tabs with Alt+1…9, not in inputs', () => {
    expect(resolveShortcut(key('3', { altKey: true }), state()).action).toEqual({ kind: 'tab', index: 3 })
    expect(resolveShortcut(key('0', { altKey: true }), state()).action).toBeNull()
    expect(resolveShortcut(key('3', { altKey: true, inInput: true }), state()).action).toBeNull()
  })

  it('turns every single-key and sequence shortcut off with the switch', () => {
    const off = state({ singleKey: false })
    for (const k of ['/', '?', '[', 'j', 'k', 'o', 'Enter', 'g']) {
      expect(resolveShortcut(key(k), off), k).toEqual({ action: null, pendingG: null })
    }
    expect(resolveShortcut(key('d'), state({ singleKey: false, pendingG: 10_000, now: 10_100 })).action).toBeNull()
    expect(resolveShortcut(key('1', { altKey: true }), off).action).toBeNull()
  })
})
