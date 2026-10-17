import { describe, expect, it, vi } from 'vitest'
import { usePending } from '../composables/usePending'

describe('usePending (plan M8x decision 25)', () => {
  it('runs one request at a time and ignores a second call while pending', async () => {
    const { pending, run } = usePending()
    let resolve: (v: string) => void = () => {}
    const first = run(() => new Promise<string>((r) => { resolve = r }))
    expect(pending.value).toBe(true)
    const second = vi.fn(() => Promise.resolve('second'))
    await expect(run(second)).resolves.toBeUndefined()
    expect(second).not.toHaveBeenCalled()
    resolve('first')
    await expect(first).resolves.toBe('first')
    expect(pending.value).toBe(false)
    await expect(run(second)).resolves.toBe('second')
  })

  it('clears the pending state when the request fails', async () => {
    const { pending, run } = usePending()
    await expect(run(() => Promise.reject(new Error('down')))).rejects.toThrow('down')
    expect(pending.value).toBe(false)
  })
})
