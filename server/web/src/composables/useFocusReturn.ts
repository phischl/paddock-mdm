import { nextTick } from 'vue'

/**
 * Remembers the control that opened a dialog and gives it focus again once the dialog is gone, so keyboard users
 * continue where they were. A dialog the page mounts only while it is open has no activator Vuetify could return to.
 */
export function useFocusReturn(): { remember: (event?: Event) => void; restore: (fallback?: () => HTMLElement | null | undefined) => void } {
  let origin: HTMLElement | null = null
  return {
    remember(event) {
      const target = event?.currentTarget ?? document.activeElement
      origin = target instanceof HTMLElement ? target : null
    },
    /** The fallback takes the focus when the opening control is gone, e.g. its row left the list after the step. */
    restore(fallback) {
      const el = origin
      origin = null
      void nextTick(() => {
        const target = el?.isConnected ? el : fallback?.()
        target?.focus()
      })
    },
  }
}
