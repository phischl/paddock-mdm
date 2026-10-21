import { readonly, shallowRef } from 'vue'

/** A reason the dialog collects with the confirmation (revocations); kept with the request, never a secret. */
export interface ConfirmReason {
  label: string
  hint?: string
  required: boolean
  maxLength: 500
}

/** What a confirmation asks; texts are already translated. */
export interface ConfirmOptions {
  title: string
  /** The consequence in one sentence. */
  message: string
  confirmLabel: string
  /** Renders the confirm button in the error colour. */
  destructive?: boolean
  /** High-risk actions: the confirm button stays disabled until this text is typed exactly. */
  requireTypedText?: string
  reason?: ConfirmReason
  /** A warning shown above the fields (e.g. an in-place encryption in progress, plan M8e decision 39). */
  warning?: string
}

/** The answer of the dialog: cancelled, or confirmed with the reason typed (empty without a reason field). */
export type ConfirmAnswer = false | { reason: string }

interface PendingConfirm {
  /** Distinct per request; the host keys the dialog with it so each request starts from a fresh instance. */
  id: number
  options: ConfirmOptions
  resolve: (answer: ConfirmAnswer) => void
}

// One confirmation at a time for the whole portal; App.vue hosts the single ConfirmDialog that shows it.
const pending = shallowRef<PendingConfirm | null>(null)
let requests = 0

/** The confirmation being shown, for the host in App.vue. */
export const pendingConfirm = readonly(pending)

/** Answers the pending confirmation (host only). */
export function settleConfirm(answer: ConfirmAnswer): void {
  const current = pending.value
  pending.value = null
  current?.resolve(answer)
}

/** Asks and resolves with the raw answer. */
function ask(options: ConfirmOptions): Promise<ConfirmAnswer> {
  settleConfirm(false)
  return new Promise<ConfirmAnswer>((resolve) => {
    pending.value = { id: ++requests, options, resolve }
  })
}

export interface Confirm {
  /** With a reason field: false on cancel, else the reason (trimmed). */
  (options: ConfirmOptions & { reason: ConfirmReason }): Promise<false | { reason: string }>
  /** Without a reason field: true on confirm, false on cancel. */
  (options: Omit<ConfirmOptions, 'reason'>): Promise<boolean>
}

/**
 * Asks for confirmation in a modal (ADR 0018: never window.confirm). Resolves false on cancel, Esc or a click
 * outside. A new request cancels a pending one. The return type follows the options so callers cannot misread a
 * reason as a boolean.
 */
export function useConfirm(): Confirm {
  const confirm = async (options: ConfirmOptions): Promise<boolean | { reason: string }> => {
    const answer = await ask(options)
    if (options.reason) return answer
    return answer !== false
  }
  return confirm as Confirm
}
