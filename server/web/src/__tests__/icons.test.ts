import { describe, expect, it } from 'vitest'
import { iconTags, parseIconSvg, renderIconsModule, type IconNode } from '../lib/iconGen'
import generated from '../lib/icons.gen.ts?raw'
import { icons } from '../lib/icons.gen'

const svgs = import.meta.glob<string>('../assets/icons/lucide/*.svg', { query: '?raw', import: 'default', eager: true })
const wrap = (inner: string, root = 'viewBox="0 0 24 24"') => `<svg xmlns="http://www.w3.org/2000/svg" ${root}>${inner}</svg>`

describe('parseIconSvg', () => {
  it('accepts the stroke primitives with geometry attributes', () => {
    expect(parseIconSvg('ok', wrap('<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3" />'))).toEqual([
      ['circle', { cx: '11', cy: '11', r: '8' }],
      ['path', { d: 'm21 21-4.3-4.3' }],
    ] satisfies IconNode[])
  })
  it.each([
    ['script', wrap('<script>alert(1)</script>')],
    ['style attribute', wrap('<path d="M0 0" style="fill:red"/>')],
    ['href', wrap('<path d="M0 0" href="x"/>')],
    ['nested element', wrap('<g><path d="M0 0"/></g>')],
    ['text', wrap('hello<path d="M0 0"/>')],
    ['foreign element', wrap('<image x="0"/>')],
    ['wrong viewBox', wrap('<path d="M0 0"/>', 'viewBox="0 0 48 48"')],
    ['root event handler', wrap('<path d="M0 0"/>', 'viewBox="0 0 24 24" onload="x()"')],
    ['empty', wrap('')],
    ['two roots', wrap('<path d="M0 0"/>') + wrap('<path d="M0 0"/>')],
  ])('rejects %s', (_, svg) => {
    expect(() => parseIconSvg('bad', svg)).toThrow(/bad/)
  })
  it('knows exactly the Lucide primitives', () => {
    expect([...iconTags]).toEqual(['path', 'circle', 'rect', 'line', 'polyline', 'polygon', 'ellipse'])
  })
})

describe('icons.gen.ts', () => {
  it('is what gen-icons.ts --check expects from the vendored files', () => {
    const parsed: Record<string, IconNode[]> = {}
    for (const [path, svg] of Object.entries(svgs)) {
      const name = path.replace(/^.*\//, '').replace(/\.svg$/, '')
      parsed[name] = parseIconSvg(name, svg)
    }
    expect(Object.keys(parsed).length).toBeGreaterThan(40)
    expect(renderIconsModule(parsed)).toBe(generated)
  })
  it('exports the chrome icons the shell uses', () => {
    for (const name of ['menu', 'panel-left', 'search', 'sun', 'moon', 'monitor', 'x', 'triangle-alert', 'keyboard']) {
      expect(icons, name).toHaveProperty(name)
    }
  })
})
