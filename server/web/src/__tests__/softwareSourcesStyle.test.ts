import { compileStyle, parse } from '@vue/compiler-sfc'
import { describe, expect, it } from 'vitest'
import source from '../views/SoftwareSources.vue?raw'

describe('SoftwareSources scoped styles', () => {
  it('scope every selector, so no rule leaks to other tables or lists', () => {
    const filename = 'SoftwareSources.vue'
    const { descriptor } = parse(source, { filename })
    expect(descriptor.styles.length).toBeGreaterThan(0)
    for (const style of descriptor.styles) {
      expect(style.scoped).toBe(true)
      const { code, errors } = compileStyle({ source: style.content, filename, id: 'data-v-test', scoped: true })
      expect(errors).toEqual([])
      const selectors = [...code.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{/g)].flatMap((m) => m[1].split(',')).map((x) => x.trim()).filter((x) => x !== '')
      expect(selectors.length).toBeGreaterThan(0)
      for (const selector of selectors) expect(selector, selector).toContain('[data-v-test]')
    }
  })
})
