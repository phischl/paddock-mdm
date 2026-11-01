import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, nextTick } from 'vue'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VDialog } from 'vuetify/components'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { pendingConfirm, settleConfirm, useConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import styles from '../styles.css?raw'
import confirmDialogSource from '../components/ConfirmDialog.vue?raw'

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

  it('keeps focus in a field the user moved to before the opening transition ended (PDK-047)', async () => {
    const w = mountDialog({ requireTypedText: 'acme' })
    await flushPromises()
    const input = el('confirm-typed')?.querySelector('input') as HTMLInputElement
    input.focus()
    w.findComponent(VDialog).vm.$emit('afterEnter')
    await nextTick()
    expect(document.activeElement).toBe(input)
    input.value = 'acme'
    input.dispatchEvent(new Event('input'))
    await nextTick()
    expect((el('confirm-accept') as HTMLButtonElement).disabled).toBe(false)
  })

  it('focuses Cancel again after the opening transition when focus left the dialog', async () => {
    const w = mountDialog()
    await flushPromises()
    ;(document.activeElement as HTMLElement | null)?.blur()
    w.findComponent(VDialog).vm.$emit('afterEnter')
    await nextTick()
    expect(document.activeElement).toBe(el('confirm-cancel'))
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

  it('puts its buttons into the shared action row, which wraps on a narrow screen (PDK-199 fix round 3)', async () => {
    mountDialog({ confirmLabel: 'Automatisches Entsiegeln aktivieren' })
    await flushPromises()
    const row = el('confirm-cancel')?.parentElement
    expect(row?.classList.contains('form-actions')).toBe(true)
    expect(el('confirm-accept')?.parentElement).toBe(row)
    expect(styles).toMatch(/\.form-actions\s*\{[^}]*flex-wrap:\s*wrap/)
  })

  it('shows a long unbreakable name in the title and the confirm label in full and lets both wrap (PDK-447)', async () => {
    const version = '0.9.1792783862-alpha.1792944510667'
    mountDialog({
      title: `Import agent release ${version}`,
      confirmLabel: `Import ${version}`,
      requireTypedText: version,
    })
    await flushPromises()
    const dialog = document.body.querySelector<HTMLElement>('[role="dialog"]')
    const heading = document.getElementById(dialog?.getAttribute('aria-labelledby') ?? '')
    expect(heading?.tagName).toBe('H2')
    expect(heading?.textContent?.trim()).toBe(`Import agent release ${version}`)
    const accept = el('confirm-accept')
    expect(accept?.tagName).toBe('BUTTON')
    expect(accept?.textContent?.trim()).toBe(`Import ${version}`)
    expect((accept as HTMLButtonElement).disabled).toBe(true)
    const input = el('confirm-typed')?.querySelector('input') as HTMLInputElement
    input.value = version
    input.dispatchEvent(new Event('input'))
    await nextTick()
    expect((accept as HTMLButtonElement).disabled).toBe(false)
    // jsdom does no layout, so the wrapping itself is pinned on the component's style rules; the browser check covers
    // the rendered result.
    expect(confirmDialogSource).toMatch(/\.confirm-title\s*\{[^}]*white-space:\s*normal[^}]*overflow-wrap:\s*anywhere/)
    expect(confirmDialogSource).toMatch(/\.confirm-accept\s*\{[^}]*height:\s*auto/)
    expect(confirmDialogSource).toMatch(
      /\.confirm-accept :deep\(\.v-btn__content\)\s*\{[^}]*white-space:\s*normal[^}]*overflow-wrap:\s*anywhere/,
    )
    expect(accept?.classList.contains('confirm-accept')).toBe(true)
    expect(heading?.classList.contains('confirm-title')).toBe(true)
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

describe('ConfirmDialog focus (PDK-155 fix round 2)', () => {
  function opener(): HTMLButtonElement {
    const button = document.createElement('button')
    button.textContent = 'Revert'
    document.body.appendChild(button)
    button.focus()
    return button
  }

  it('focuses Cancel without scrolling the card away from the title', async () => {
    const focus = vi.spyOn(HTMLElement.prototype, 'focus')
    mountDialog()
    await flushPromises()
    await nextTick()
    expect(focus).toHaveBeenCalledWith({ preventScroll: true })
    expect(document.activeElement).toBe(el('confirm-cancel'))
    expect(el('confirm-dialog')?.scrollTop).toBe(0)
    focus.mockRestore()
  })

  it('returns the focus to the opener after Cancel when the page closes the dialog', async () => {
    const button = opener()
    const w = mountDialog()
    await flushPromises()
    el('confirm-cancel')?.click()
    expect(w.emitted('cancel')).toHaveLength(1)
    await w.setProps({ modelValue: false })
    await flushPromises()
    await nextTick()
    expect(document.activeElement).toBe(button)
    button.remove()
  })

  it('returns the focus to the opener when a page unmounts the dialog after Escape', async () => {
    const button = opener()
    const w = mountDialog()
    await flushPromises()
    el('confirm-dialog')?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(w.emitted('cancel')).toHaveLength(1)
    w.unmount()
    wrapper = null
    await flushPromises()
    await nextTick()
    expect(document.activeElement).toBe(button)
    button.remove()
  })

  it('leaves the focus alone when the dialog goes without an answer', async () => {
    const button = opener()
    const w = mountDialog()
    await flushPromises()
    w.unmount()
    wrapper = null
    await flushPromises()
    expect(document.activeElement).not.toBe(button)
    button.remove()
  })
})

describe('ConfirmDialog detail slot (PDK-155)', () => {
  it('stays narrow without a slot and widens for the slot content', async () => {
    mountDialog()
    await flushPromises()
    expect(wrapper?.findComponent(VDialog).props('maxWidth')).toBe(480)
    wrapper?.unmount()
    wrapper = mount(ConfirmDialog, {
      props: { modelValue: true, title: 'Revert change set', message: 'Undo it?', confirmLabel: 'Revert' },
      slots: { default: () => h('p', { 'data-testid': 'slot-detail' }, 'the plan') },
      global: { plugins: [createPortalI18n(), vuetify] },
      attachTo: document.body,
    })
    await flushPromises()
    expect(wrapper.findComponent(VDialog).props('maxWidth')).toBe('64rem')
    expect(el('slot-detail')?.textContent).toBe('the plan')
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

describe('useConfirm focus return', () => {
  it.each([['cancelled', false], ['confirmed', { reason: '' }]] as const)('returns the focus to the asking control when %s', async (_, answer) => {
    const button = document.createElement('button')
    document.body.append(button)
    button.focus()
    const asked = useConfirm()({ title: 'T', message: 'M', confirmLabel: 'Go' })
    settleConfirm(answer)
    await asked
    await new Promise((r) => setTimeout(r, 20))
    expect(document.activeElement).toBe(button)
    button.remove()
  })

  it('does not take the focus from the dialog of a request that replaces the first', async () => {
    const button = document.createElement('button')
    document.body.append(button)
    button.focus()
    const confirm = useConfirm()
    void confirm({ title: 'A', message: 'M', confirmLabel: 'Go' })
    const inDialog = document.createElement('input')
    document.body.append(inDialog)
    inDialog.focus()
    void confirm({ title: 'B', message: 'M', confirmLabel: 'Go' })
    await new Promise((r) => setTimeout(r, 20))
    expect(document.activeElement).toBe(inDialog)
    button.remove()
    inDialog.remove()
  })
})
