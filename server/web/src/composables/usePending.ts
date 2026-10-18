import { computed, ref, type Ref } from 'vue'
import { pendingConfirm } from './useConfirm'

/** One in-flight request per caller: run ignores a second call while the first is pending. */
export function usePending(): { pending: Readonly<Ref<boolean>>; run<T>(fn: () => Promise<T>): Promise<T | undefined> } {
  const running = ref(false)
  // A run that waits for the answer of the confirmation dialog has no request in flight yet, so the button behind the
  // modal shows no loader (aria-busy) until the user confirms; a second click is still ignored.
  const pending = computed(() => running.value && pendingConfirm.value === null)
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    if (running.value) return undefined
    running.value = true
    try {
      return await fn()
    } finally {
      running.value = false
    }
  }
  return { pending, run }
}
