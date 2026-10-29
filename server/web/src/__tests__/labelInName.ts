/**
 * Visible text of an element as axe-core 4.14 computes it for label-content-name-mismatch (`visibleVirtual` with
 * screenReader=false): every text node visible on screen, concatenated without separators. aria-hidden subtrees
 * count because they are visible on screen; elements hidden from layout (hidden attribute, display:none,
 * visibility:hidden) do not.
 */
export function visibleText(el: Element): string {
  const hidden = (e: Element): boolean => {
    if (e.hasAttribute('hidden')) return true
    const style = getComputedStyle(e)
    return style.display === 'none' || style.visibility === 'hidden'
  }
  const walk = (node: Node): string => {
    if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? ''
    if (node.nodeName === 'BR') return ' '
    if (node instanceof Element && hidden(node)) return ''
    return Array.from(node.childNodes).map(walk).join('')
  }
  return walk(el).replace(/ /g, ' ').replace(/\s{2,}/g, ' ').trim()
}

/**
 * Words of a label as axe-core 4.14 `curateTokens` derives them: NFKD, nested parentheticals removed, every
 * character that is neither a letter nor a number becomes a space, then split into words.
 */
export function tokens(label: string): string[] {
  let text = label.toLowerCase().normalize('NFKD')
  let previous: string
  do {
    previous = text
    text = text.replace(/\([^()]*\)/g, '')
  } while (text !== previous)
  return text.replace(/[^\p{L}\p{N}]/gu, ' ').split(/\s+/).filter(Boolean)
}

function isContiguousSubsequence(haystack: string[], needle: string[]): boolean {
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    if (needle.every((word, j) => word === haystack[i + j])) return true
  }
  return false
}

/**
 * Whether axe-core 4.14's label-content-name-mismatch passes for el (WCAG 2.5.3 Label in Name): the words of the
 * visible text appear as a contiguous run in the words of the aria-label. A result axe reports as incomplete (visible
 * text or name not human-interpretable, e.g. a single letter) counts as not passing.
 */
export function nameContainsVisibleText(el: Element): boolean {
  const text = visibleText(el)
  const name = el.getAttribute('aria-label') ?? ''
  if (text === '') return true
  if (!interpretable(text) || !interpretable(name)) return false
  const visible = tokens(text)
  if (visible.length === 0) return true
  const named = tokens(name)
  return named.length > 0 && isContiguousSubsequence(named, visible)
}

function interpretable(str: string): boolean {
  const trimmed = str.trim()
  if (trimmed === '') return false
  if (trimmed.length === 1 && /\D/.test(trimmed)) return false
  if (['aa', 'abc'].includes(trimmed.toLowerCase())) return false
  return trimmed.replace(/[\p{P}\p{S}\p{Extended_Pictographic}]/gu, '').trim() !== ''
}
