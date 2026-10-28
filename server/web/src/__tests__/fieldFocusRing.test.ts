import { afterEach, describe, expect, it } from 'vitest'
import styles from '../styles.css?raw'

// jsdom does not paint, so this checks the cascade only: which focus ring the stylesheet gives an element. Whether
// the Vuetify outline is visibly thicker on focus and that no ring crosses the label is checked in the browser.
function render(html: string): HTMLElement {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.appendChild(style)
  document.body.innerHTML = html
  return document.body
}

function ringOf(el: Element | null): string {
  if (!el) throw new Error('element missing')
  ;(el as HTMLElement).focus()
  return getComputedStyle(el).boxShadow
}

afterEach(() => {
  document.head.querySelectorAll('style').forEach((s) => s.remove())
  document.body.innerHTML = ''
})

describe('focus ring inside a Vuetify field', () => {
  it('draws no second ring on the native control of a number, text, time field or text area', () => {
    const root = render(`
      <div class="v-field v-field--variant-outlined">
        <input id="number" class="v-field__input" type="number">
        <input id="text" class="v-field__input" type="text">
        <input id="time" class="v-field__input" type="time">
        <textarea id="area" class="v-field__input"></textarea>
      </div>`)
    for (const id of ['number', 'text', 'time', 'area']) {
      expect(ringOf(root.querySelector(`#${id}`)), id).toBe('none')
    }
  })

  it('keeps the global ring on a focusable icon button inside the field and on controls outside a field', () => {
    const root = render(`
      <div class="v-field"><button id="reveal" type="button">eye</button></div>
      <input id="plain" type="number">
      <button id="button" type="button">Save</button>`)
    for (const id of ['reveal', 'plain', 'button']) {
      expect(ringOf(root.querySelector(`#${id}`)), id).toContain('var(--pd-focus-ring)')
    }
  })
})
