import { ref, type Ref } from 'vue'

/** One in-flight request per caller: run ignores a second call while the first is pending. */
export function usePending(): { pending: Ref<boolean>; run<T>(fn: () => Promise<T>): Promise<T | undefined> } {
  const pending = ref(false)
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    if (pending.value) return undefined
    pending.value = true
    try {
      return await fn()
    } finally {
      pending.value = false
    }
  }
  return { pending, run }
}
