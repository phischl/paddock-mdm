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

describe('useConfirm', () => {
  const Host = defineComponent({
    setup() {
      return () =>
        pendingConfirm.value
          ? h(ConfirmDialog, {
              modelValue: true,
              ...pendingConfirm.value.options,
              onConfirm: () => settleConfirm(true),
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
    settleConfirm(true)
    expect(await second).toBe(true)
  })
})
