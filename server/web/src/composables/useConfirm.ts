import { readonly, shallowRef } from 'vue'

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
}

interface PendingConfirm {
  options: ConfirmOptions
  resolve: (confirmed: boolean) => void
}

// One confirmation at a time for the whole portal; App.vue hosts the single ConfirmDialog that shows it.
const pending = shallowRef<PendingConfirm | null>(null)

/** The confirmation being shown, for the host in App.vue. */
export const pendingConfirm = readonly(pending)

/** Answers the pending confirmation (host only). */
export function settleConfirm(confirmed: boolean): void {
  const current = pending.value
  pending.value = null
  current?.resolve(confirmed)
}

/**
 * Asks for confirmation in a modal (ADR 0018: never window.confirm). Resolves true on confirm and false on cancel,
 * Esc or a click outside. A new request cancels a pending one.
 */
export function useConfirm(): (options: ConfirmOptions) => Promise<boolean> {
  return (options) => {
    settleConfirm(false)
    return new Promise<boolean>((resolve) => {
      pending.value = { options, resolve }
    })
  }
}
