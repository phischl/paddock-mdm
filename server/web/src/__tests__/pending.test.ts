import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { VBtn } from 'vuetify/components'
import { usePending } from '../composables/usePending'
import { settleConfirm, useConfirm } from '../composables/useConfirm'
import { vuetify } from '../plugins/vuetify'

afterEach(() => settleConfirm(false))

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

  it('shows no loader while the confirmation waits for the answer, only while the request runs (PR #82 e2e)', async () => {
    let finish: () => void = () => {}
    const Host = defineComponent({
      setup() {
        const { pending, run } = usePending()
        const confirm = useConfirm()
        const act = () =>
          run(async () => {
            if (!(await confirm({ title: 'Halt the rollout?', message: 'No more devices.', confirmLabel: 'Halt' }))) return
            await new Promise<void>((r) => { finish = r })
          })
        return () => h(VBtn, { loading: pending.value, disabled: pending.value, onClick: act }, () => 'Halt')
      },
    })
    const w = mount(Host, { global: { plugins: [vuetify] } })
    const busy = () => w.find('[aria-busy="true"]').exists()
    await w.find('button').trigger('click')
    await flushPromises()
    expect(busy()).toBe(false)
    expect(w.find('button').attributes('disabled')).toBeUndefined()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(busy()).toBe(true)
    finish()
    await flushPromises()
    expect(busy()).toBe(false)
    w.unmount()
  })
})

