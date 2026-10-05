/**
 * Step-up authentication in the portal (plan M4a decisions 6 and 7): an action that the server refuses with
 * step_up_required sends the browser through /api/auth/stepup and is repeated once when the browser comes back. The
 * pending action (never a secret) waits in sessionStorage; the server adds stepup=failed to the return URL when the
 * step-up was refused.
 */

const storageKey = 'paddock.stepup'

/** A pending action older than this is dropped (the step-up itself is valid for 300 s). */
const maxAgeMs = 10 * 60 * 1000

/** The problem code of actions that need a step-up. */
export const stepUpRequired = 'step_up_required'

interface Pending {
  action: string
  target: string
  payload: unknown
  at: number
}

/** The current path and query without stepup. */
function currentPath(): string {
  const url = new URL(window.location.href)
  url.searchParams.delete('stepup')
  return url.pathname + url.search
}

/** Remembers the action and sends the browser to the step-up; it comes back to the current page. */
export function startStepUp(action: string, target: string, payload: unknown = null): void {
  const pending: Pending = { action, target, payload, at: Date.now() }
  sessionStorage.setItem(storageKey, JSON.stringify(pending))
  window.location.assign('/api/auth/stepup?return_to=' + encodeURIComponent(currentPath()))
}

/** The outcome of a step-up the page started for action on target. */
export type Resumed<T> = { failed: false; payload: T } | { failed: true }

/**
 * Takes the pending action for action and target once (it is removed): the payload to repeat it with, failed when
 * the server refused the step-up, null when there is none (or it is stale, or for another page).
 */
export function resumeStepUp<T>(action: string, target: string): Resumed<T> | null {
  const raw = sessionStorage.getItem(storageKey)
  if (!raw) return null
  let pending: Pending
  try {
    pending = JSON.parse(raw) as Pending
  } catch {
    sessionStorage.removeItem(storageKey)
    return null
  }
  if (pending.action !== action || pending.target !== target) return null
  sessionStorage.removeItem(storageKey)
  if (Date.now() - pending.at > maxAgeMs) return null
  if (new URLSearchParams(window.location.search).get('stepup') === 'failed') return { failed: true }
  return { failed: false, payload: pending.payload as T }
}

/** The current URL without the stepup parameter (for router.replace after resuming). */
export function withoutStepUpParam(): string {
  return currentPath()
}
