import { onBeforeUnmount, onMounted } from 'vue'

/**
 * Global keyboard shortcuts (plan M7c decision 17): the palette, the help dialog, the navigation toggle, the
 * g-sequences, the list cursor and the device tabs. No shortcut ever triggers a destructive or security-relevant
 * action. Single-key shortcuts are a viewer preference (WCAG 2.1.4) and are ignored in inputs and while an overlay
 * is open; Ctrl/⌘ K works everywhere except inside an open dialog.
 */
export interface ShortcutHandlers {
  openPalette(): void
  openHelp(): void
  toggleNav(): void
  go(to: string): void
  list(action: 'down' | 'up' | 'open'): void
  tab(index: number): void
}

export type ShortcutAction =
  | { kind: 'palette' }
  | { kind: 'help' }
  | { kind: 'nav' }
  | { kind: 'go'; key: string }
  | { kind: 'list'; action: 'down' | 'up' | 'open' }
  | { kind: 'tab'; index: number }

/** What the resolver needs to know about a keydown and the page. */
export interface KeyContext {
  key: string
  ctrlKey: boolean
  metaKey: boolean
  altKey: boolean
  shiftKey: boolean
  /** Focus is in an input, textarea, select or contenteditable. */
  inInput: boolean
  /** Focus is on a link, button or another control that handles Enter itself. */
  onControl: boolean
  /** A Vuetify overlay (dialog, menu) is open. */
  overlayOpen: boolean
  /** A dialog is open (the palette or the help dialog included). */
  dialogOpen: boolean
}

export interface ShortcutState {
  /** Time of the pending g, or null. */
  pendingG: number | null
  now: number
  singleKey: boolean
}

/** The g-sequence timeout. */
export const sequenceTimeout = 1000
const sequenceKeys = new Set(['o', 'a', 'd', 's', 'v', 'l'])

/** Maps a keydown to an action; pure, so the rules are unit-tested. Returns the next pending-g state. */
export function resolveShortcut(k: KeyContext, s: ShortcutState): { action: ShortcutAction | null; pendingG: number | null } {
  const modifier = k.ctrlKey || k.metaKey
  if (modifier && !k.altKey && !k.shiftKey && k.key.toLowerCase() === 'k') {
    return { action: k.dialogOpen ? null : { kind: 'palette' }, pendingG: null }
  }
  if (k.inInput || k.overlayOpen || !s.singleKey) return { action: null, pendingG: null }
  if (k.altKey && !modifier && /^[1-9]$/.test(k.key)) return { action: { kind: 'tab', index: Number(k.key) }, pendingG: null }
  if (modifier || k.altKey) return { action: null, pendingG: null }
  if (s.pendingG !== null && s.now - s.pendingG <= sequenceTimeout) {
    return { action: sequenceKeys.has(k.key) ? { kind: 'go', key: k.key } : null, pendingG: null }
  }
  switch (k.key) {
    case 'g':
      return { action: null, pendingG: s.now }
    case '/':
      return { action: { kind: 'palette' }, pendingG: null }
    case '?':
      return { action: { kind: 'help' }, pendingG: null }
    case '[':
      return { action: { kind: 'nav' }, pendingG: null }
    case 'j':
      return { action: { kind: 'list', action: 'down' }, pendingG: null }
    case 'k':
      return { action: { kind: 'list', action: 'up' }, pendingG: null }
    case 'o':
      return { action: { kind: 'list', action: 'open' }, pendingG: null }
    case 'Enter':
      return { action: k.onControl ? null : { kind: 'list', action: 'open' }, pendingG: null }
    default:
      return { action: null, pendingG: null }
  }
}

const singleKeyStorage = 'paddock.shortcuts.singleKey'

/** Whether single-key and sequence shortcuts are on (viewer preference, default on). */
export function singleKeyShortcutsEnabled(): boolean {
  try {
    return localStorage.getItem(singleKeyStorage) !== 'false'
  } catch {
    return true
  }
}

export function setSingleKeyShortcuts(enabled: boolean): void {
  try {
    localStorage.setItem(singleKeyStorage, String(enabled))
  } catch {
    // Not persisted; the choice holds until the page is reloaded.
  }
}

export function isMac(): boolean {
  const data = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData
  return navigator.platform.startsWith('Mac') || data?.platform === 'macOS'
}

/** The modifier of the palette shortcut as shown in hints. */
export function modifierLabel(): 'Ctrl' | '⌘' {
  return isMac() ? '⌘' : 'Ctrl'
}

const inputSelector = 'input, textarea, select, [contenteditable], [contenteditable=""], [contenteditable="true"]'
const controlSelector = 'a, button, [role="button"], [role="tab"], [role="menuitem"], [role="option"], summary'

/** Describes the page for the resolver. */
export function keyContext(e: KeyboardEvent): KeyContext {
  const target = e.target instanceof Element ? e.target : null
  const active = document.activeElement
  return {
    key: e.key,
    ctrlKey: e.ctrlKey,
    metaKey: e.metaKey,
    altKey: e.altKey,
    shiftKey: e.shiftKey,
    inInput: !!(target?.closest(inputSelector) || active?.closest(inputSelector)),
    onControl: !!active?.closest(controlSelector),
    overlayOpen: document.querySelector('.v-overlay--active') !== null,
    dialogOpen: document.querySelector('.v-dialog.v-overlay--active') !== null,
  }
}

/** Installs the keydown listener on window for the component's lifetime (App.vue installs it once). */
export function useShortcuts(handlers: ShortcutHandlers): void {
  let pendingG: number | null = null
  const listener = (e: KeyboardEvent): void => {
    if (e.defaultPrevented || e.isComposing) return
    const result = resolveShortcut(keyContext(e), { pendingG, now: Date.now(), singleKey: singleKeyShortcutsEnabled() })
    pendingG = result.pendingG
    const a = result.action
    if (!a) return
    e.preventDefault()
    switch (a.kind) {
      case 'palette':
        return handlers.openPalette()
      case 'help':
        return handlers.openHelp()
      case 'nav':
        return handlers.toggleNav()
      case 'go':
        return handlers.go(a.key)
      case 'list':
        return handlers.list(a.action)
      case 'tab':
        return handlers.tab(a.index)
    }
  }
  onMounted(() => window.addEventListener('keydown', listener))
  onBeforeUnmount(() => window.removeEventListener('keydown', listener))
}
