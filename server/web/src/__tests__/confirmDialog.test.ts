import { afterEach, describe, expect, it } from 'vitest'
import { defineComponent, h, nextTick } from 'vue'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm, useConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

let wrapper: VueWrapper | null = null

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
})

function mountDialog(props: Record<string, unknown> = {}) {
  wrapper = mount(ConfirmDialog, {
    props: { modelValue: true, title: 'Delete device group', message: 'Delete Laptops?', confirmLabel: 'Delete', ...props },
    global: { plugins: [createPortalI18n(), vuetify] },
    attachTo: document.body,
  })
  return wrapper
}

// The dialog is teleported to the body.
const el = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)

describe('ConfirmDialog', () => {
  it('focuses Cancel when it opens', async () => {
    mountDialog()
    await flushPromises()
    await nextTick()
    expect(document.activeElement).toBe(el('confirm-cancel'))
    expect(el('confirm-dialog')?.textContent).toContain('Delete Laptops?')
  })

  it('emits confirm and cancel', async () => {
    const w = mountDialog({ destructive: true })
    await flushPromises()
    el('confirm-accept')?.click()
    el('confirm-cancel')?.click()
    expect(w.emitted('confirm')).toHaveLength(1)
    expect(w.emitted('cancel')).toHaveLength(1)
    expect(el('confirm-accept')?.className).toContain('bg-error')
  })

  it('cancels on Esc', async () => {
    const w = mountDialog()
    await flushPromises()
    el('confirm-dialog')?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(w.emitted('cancel')).toHaveLength(1)
    expect(w.emitted('confirm')).toBeUndefined()
  })

  it('requires the typed text exactly before confirming', async () => {
    const w = mountDialog({ requireTypedText: 'acme' })
    await flushPromises()
    const input = el('confirm-typed')?.querySelector('input') as HTMLInputElement
    const accept = () => el('confirm-accept') as HTMLButtonElement
    expect(accept().disabled).toBe(true)
    for (const wrong of ['acm', 'ACME', 'acme ']) {
      input.value = wrong
      input.dispatchEvent(new Event('input'))
      await nextTick()
      expect(accept().disabled, wrong).toBe(true)
      accept().click()
    }
    expect(w.emitted('confirm')).toBeUndefined()
    input.value = 'acme'
    input.dispatchEvent(new Event('input'))
    await nextTick()
    expect(accept().disabled).toBe(false)
    accept().click()
    expect(w.emitted('confirm')).toHaveLength(1)
  })
})

describe('ConfirmDialog reason field (plan M7c decision 23)', () => {
  const reason = { label: 'Reason', hint: 'Kept with the request.', required: true, maxLength: 500 as const }

  it('keeps the confirm button disabled until the typed text matches and a required reason is non-empty', async () => {
    const w = mountDialog({ requireTypedText: 'acme-lt-0142', reason, destructive: true })
    await flushPromises()
    const accept = () => el('confirm-accept') as HTMLButtonElement
    const typed = el('confirm-typed')?.querySelector('input') as HTMLInputElement
    const text = el('confirm-reason')?.querySelector('textarea') as HTMLTextAreaElement
    expect(el('confirm-reason')?.textContent).toContain('Reason')
    expect(accept().disabled).toBe(true)
    typed.value = 'acme-lt-0142'
    typed.dispatchEvent(new Event('input'))
    await nextTick()
    expect(accept().disabled).toBe(true)
    text.value = '   '
    text.dispatchEvent(new Event('input'))
    await nextTick()
    expect(accept().disabled).toBe(true)
    text.value = ' stolen laptop '
    text.dispatchEvent(new Event('input'))
    await nextTick()
    expect(accept().disabled).toBe(false)
    // Enter in either field does not submit.
    typed.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    text.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(w.emitted('confirm')).toBeUndefined()
    accept().click()
    expect(w.emitted('confirm')).toEqual([[{ reason: 'stolen laptop' }]])
  })

  it('lets an optional reason stay empty', async () => {
    const w = mountDialog({ reason: { ...reason, required: false } })
    await flushPromises()
    expect((el('confirm-accept') as HTMLButtonElement).disabled).toBe(false)
    el('confirm-accept')?.click()
    expect(w.emitted('confirm')).toEqual([[{ reason: '' }]])
  })

  it('starts every new confirmation with empty fields, also when it replaces an open one', async () => {
    const w = mountDialog({ title: 'Lock lt-1', requireTypedText: 'lt-1', reason, destructive: true })
    await flushPromises()
    const typed = () => el('confirm-typed')?.querySelector('input') as HTMLInputElement
    const text = () => el('confirm-reason')?.querySelector('textarea') as HTMLTextAreaElement
    typed().value = 'lt-1'
    typed().dispatchEvent(new Event('input'))
    text().value = 'stolen'
    text().dispatchEvent(new Event('input'))
    await nextTick()
    expect((el('confirm-accept') as HTMLButtonElement).disabled).toBe(false)
    // The next request reuses the open dialog (the host did not close it in between).
    await w.setProps({ title: 'Lock lt-2', requireTypedText: 'lt-2', reason: { ...reason } })
    await nextTick()
    expect(typed().value).toBe('')
    expect(text().value).toBe('')
    expect((el('confirm-accept') as HTMLButtonElement).disabled).toBe(true)
  })

  it('gives every request its own id, so the host renders a fresh dialog per request', async () => {
    const confirm = useConfirm()
    void confirm({ title: 'A', message: 'M', confirmLabel: 'OK' })
    const first = pendingConfirm.value?.id
    void confirm({ title: 'A', message: 'M', confirmLabel: 'OK' })
    expect(pendingConfirm.value?.id).not.toBe(first)
  })
})

describe('useConfirm', () => {
  it('resolves the reason when the options ask for one, a boolean otherwise', async () => {
    const confirm = useConfirm()
    const withReason = confirm({ title: 'Lock', message: 'Lock?', confirmLabel: 'Lock', reason: { label: 'Reason', required: true, maxLength: 500 } })
    expect(pendingConfirm.value?.options.reason?.label).toBe('Reason')
    settleConfirm({ reason: 'stolen' })
    expect(await withReason).toEqual({ reason: 'stolen' })
    const plain = confirm({ title: 'Delete', message: 'Delete?', confirmLabel: 'Delete' })
    settleConfirm({ reason: '' })
    expect(await plain).toBe(true)
    const cancelled = confirm({ title: 'Delete', message: 'Delete?', confirmLabel: 'Delete' })
    settleConfirm(false)
    expect(await cancelled).toBe(false)
  })

  const Host = defineComponent({
    setup() {
      return () =>
        pendingConfirm.value
          ? h(ConfirmDialog, {
              modelValue: true,
              ...pendingConfirm.value.options,
              onConfirm: () => settleConfirm({ reason: '' }),
              onCancel: () => settleConfirm(false),
            })
          : null
    },
  })

  it('resolves with the answer of the modal', async () => {
    wrapper = mount(Host, { global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body })
    const confirm = useConfirm()
    const accepted = confirm({ title: 'T', message: 'M', confirmLabel: 'Delete', destructive: true })
    await flushPromises()
    el('confirm-accept')?.click()
    expect(await accepted).toBe(true)
    expect(pendingConfirm.value).toBeNull()

    const cancelled = confirm({ title: 'T', message: 'M', confirmLabel: 'Delete' })
    await flushPromises()
    el('confirm-cancel')?.click()
    expect(await cancelled).toBe(false)
  })

  it('cancels a pending confirmation when a new one starts', async () => {
    const confirm = useConfirm()
    const first = confirm({ title: 'A', message: 'M', confirmLabel: 'OK' })
    const second = confirm({ title: 'B', message: 'M', confirmLabel: 'OK' })
    expect(await first).toBe(false)
    expect(pendingConfirm.value?.options.title).toBe('B')
    settleConfirm({ reason: '' })
    expect(await second).toBe(true)
  })
})
