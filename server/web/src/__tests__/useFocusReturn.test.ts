import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { useFocusReturn } from '../composables/useFocusReturn'

afterEach(() => {
  document.body.innerHTML = ''
  vi.useRealTimers()
})

function page(): { main: HTMLElement; button: HTMLButtonElement } {
  const main = document.createElement('main')
  const button = document.createElement('button')
  main.append(button)
  document.body.append(main)
  return { main, button }
}

describe('useFocusReturn', () => {
  it('focuses the opening control right away when the page is interactive', async () => {
    const { button } = page()
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    focus.restore()
    await nextTick()
    expect(document.activeElement).toBe(button)
  })

  it('waits while the page is still inert and focuses once the attribute is gone', async () => {
    const { main, button } = page()
    main.setAttribute('inert', '')
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    focus.restore()
    await nextTick()
    await new Promise((r) => setTimeout(r, 20))
    expect(document.activeElement).not.toBe(button)
    main.removeAttribute('inert')
    await new Promise((r) => setTimeout(r, 0))
    expect(document.activeElement).toBe(button)
  })

  it('uses the fallback when the opening control is gone', async () => {
    const { main, button } = page()
    const alert = document.createElement('div')
    alert.tabIndex = -1
    main.append(alert)
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    button.remove()
    focus.restore(() => alert)
    await nextTick()
    expect(document.activeElement).toBe(alert)
  })

  it('tries anyway after a second when the page stays inert', async () => {
    vi.useFakeTimers()
    const { main, button } = page()
    main.setAttribute('inert', '')
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    focus.restore()
    await nextTick()
    expect(document.activeElement).not.toBe(button)
    vi.advanceTimersByTime(1000)
    expect(document.activeElement).toBe(button)
  })

  it('waits while the opening control is disabled and focuses it once it is enabled again', async () => {
    const { button } = page()
    button.disabled = true
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    focus.restore()
    await nextTick()
    await new Promise((r) => setTimeout(r, 20))
    expect(document.activeElement).not.toBe(button)
    button.disabled = false
    await new Promise((r) => setTimeout(r, 0))
    expect(document.activeElement).toBe(button)
  })

  it('uses the fallback when the disabled control is removed while waiting', async () => {
    const { main, button } = page()
    const alert = document.createElement('div')
    alert.tabIndex = -1
    main.append(alert)
    button.disabled = true
    const focus = useFocusReturn()
    focus.remember({ currentTarget: button } as unknown as Event)
    focus.restore(() => alert)
    await nextTick()
    expect(document.activeElement).not.toBe(alert)
    button.remove()
    await new Promise((r) => setTimeout(r, 0))
    expect(document.activeElement).toBe(alert)
  })
})
