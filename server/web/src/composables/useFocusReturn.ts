import { nextTick } from 'vue'

/** How long a focus return waits for the page behind a dialog to become interactive again. */
const inertWait = 1000

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
      const resolve = () => (el?.isConnected ? el : fallback?.())
      void nextTick(() => focusWhenInteractive(resolve))
    },
  }
}

/**
 * The page is inert while a dialog is open and the portal lifts that a render after the dialog closed; focus() on an
 * inert element is ignored, so the focus waits for the attribute to go. The same holds for a control that is still
 * disabled while its action runs (:disabled="pending"): focus() on it is dropped and the focus would fall to the body,
 * so it waits until the control is enabled again. A control that left the page meanwhile is replaced by the fallback on
 * the next attempt. After inertWait it is tried anyway.
 */
function isDisabled(el: HTMLElement): boolean {
  return 'disabled' in el && (el as HTMLButtonElement).disabled === true
}

function focusWhenInteractive(resolve: () => HTMLElement | null | undefined): void {
  const attempt = (): boolean => {
    const target = resolve()
    if (!target || target.closest('[inert]') || isDisabled(target)) return false
    target.focus()
    return true
  }
  if (attempt()) return
  const observer = new MutationObserver(() => {
    if (attempt()) finish()
  })
  const timer = setTimeout(() => {
    finish()
    resolve()?.focus()
  }, inertWait)
  function finish(): void {
    observer.disconnect()
    clearTimeout(timer)
  }
  observer.observe(document.body, { attributes: true, attributeFilter: ['inert', 'disabled'], subtree: true, childList: true })
}
