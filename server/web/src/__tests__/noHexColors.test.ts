import { describe, expect, it } from 'vitest'

// Every colour of the portal is a token (ADR 0023): a literal hex colour belongs only in plugins/theme.ts and
// styles/tokens.css. Vue files are checked in their style blocks, CSS files and TypeScript modules as a whole.
const sources = import.meta.glob<string>('../**/*.{vue,css,ts}', { query: '?raw', import: 'default', eager: true })
const exempt = ['/plugins/theme.ts', '/styles/tokens.css']
const hex = /#[0-9a-f]{3,8}\b/i

function styleBlocks(vue: string): string {
  return [...vue.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((m) => m[1]).join('\n')
}

describe('no literal colours outside the token files', () => {
  it('sees the source files with their content', () => {
    const byName = (name: string) => Object.entries(sources).find(([p]) => p.endsWith(name))?.[1] ?? ''
    expect(byName('/styles.css').length).toBeGreaterThan(100)
    expect(byName('/styles/tokens.css').length).toBeGreaterThan(100)
    expect(byName('/App.vue').length).toBeGreaterThan(100)
  })
  it('finds no hex colour', () => {
    const hits: string[] = []
    for (const [path, text] of Object.entries(sources)) {
      if (exempt.some((e) => path.endsWith(e)) || path.includes('/__tests__/') || path.includes('/api/')) continue
      const m = hex.exec(path.endsWith('.vue') ? styleBlocks(text) : text)
      if (m) hits.push(`${path}: ${m[0]}`)
    }
    expect(hits).toEqual([])
  })
  it('would catch a colour in a style block', () => {
    expect(hex.test(styleBlocks('<template/><style>.x { color: #abc; }</style>'))).toBe(true)
  })
})
