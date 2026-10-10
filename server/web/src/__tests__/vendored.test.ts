import { describe, expect, it } from 'vitest'
import { allowedAssetLicenses, entryProblems, vendoredProblems, walkVendored, type VendoredManifest } from '../lib/vendoredCheck'
import manifest from '../assets/vendored.json'

const font = 'a'.repeat(64)
const licence = 'b'.repeat(64)
const icon = 'c'.repeat(64)
const base: VendoredManifest = {
  sets: [
    {
      name: 'Font', license: 'OFL-1.1', source: 'https://example.test/font', release: 'v1.2', dir: 'fonts/font',
      license_file: 'OFL.txt', files: { 'Font-Regular.woff2': font, 'OFL.txt': licence },
    },
    {
      name: 'Icons', license: 'ISC', source: 'https://example.test/icons', release: '0.9.0', dir: 'icons/set',
      license_file: 'LICENSE', files: { 'laptop.svg': icon, LICENSE: licence },
    },
  ],
}
const disk = { 'fonts/font/Font-Regular.woff2': font, 'fonts/font/OFL.txt': licence, 'icons/set/laptop.svg': icon, 'icons/set/LICENSE': licence }
const notice = `Font v1.2 ${font}\nIcons 0.9.0`

describe('vendoredProblems', () => {
  it('passes a complete manifest', () => {
    expect(vendoredProblems(base, disk, notice)).toEqual([])
  })
  it('names an unlisted file', () => {
    expect(vendoredProblems(base, { ...disk, 'fonts/font/extra.woff2': font }, notice)).toEqual(['fonts/font/extra.woff2: not listed in vendored.json'])
  })
  it('names a missing and a changed file', () => {
    const changed = { ...disk, 'fonts/font/Font-Regular.woff2': 'd'.repeat(64) }
    delete (changed as Record<string, string>)['icons/set/laptop.svg']
    const problems = vendoredProblems(base, changed, notice)
    expect(problems).toContain('icons/set/laptop.svg: listed in vendored.json but missing')
    expect(problems.some((p) => p.startsWith('fonts/font/Font-Regular.woff2: SHA-256'))).toBe(true)
  })
  it('rejects a licence outside the allow list and a set without its licence file', () => {
    const bad: VendoredManifest = {
      sets: [{ ...base.sets[0], license: 'GPL-3.0', files: { 'Font-Regular.woff2': font } }],
    }
    const problems = vendoredProblems(bad, { 'fonts/font/Font-Regular.woff2': font }, notice)
    expect(problems).toContain(`Font: licence GPL-3.0 is not one of ${allowedAssetLicenses.join(', ')}`)
    expect(problems).toContain('Font: licence file OFL.txt is not listed')
  })
  it('requires the release tag and every font checksum in the notice', () => {
    const problems = vendoredProblems(base, disk, 'nothing recorded')
    expect(problems).toContain('Font: docs/compliance/third-party.md does not name the release v1.2')
    expect(problems).toContain('Icons: docs/compliance/third-party.md does not name the release 0.9.0')
    expect(problems).toContain('fonts/font/Font-Regular.woff2: docs/compliance/third-party.md does not record its SHA-256')
    expect(problems.some((p) => p.includes('OFL.txt') && p.includes('SHA-256'))).toBe(false)
  })
})

describe('vendored.json', () => {
  it('pins the three sets with their releases and licence files', () => {
    expect(manifest.sets.map((s) => [s.name, s.license, s.license_file])).toEqual([
      ['IBM Plex Sans', 'OFL-1.1', 'LICENSE.txt'],
      ['JetBrains Mono', 'OFL-1.1', 'OFL.txt'],
      ['Lucide', 'ISC', 'LICENSE'],
    ])
    for (const set of manifest.sets) {
      expect(set.release).not.toBe('')
      expect(Object.keys(set.files)).toContain(set.license_file)
      for (const sha of Object.values(set.files)) expect(sha).toMatch(/^[0-9a-f]{64}$/)
    }
  })
})

describe('entryProblems', () => {
  // A directory tree as readdirSync(dir, { withFileTypes: true }) lists it: lstat semantics, so a symlink is neither
  // a file nor a directory, also when it points at a directory.
  const entry = (name: string, kind: 'file' | 'dir' | 'link') => ({ name, isFile: () => kind === 'file', isDirectory: () => kind === 'dir' })
  const tree: Record<string, ReturnType<typeof entry>[]> = {
    '/a/icons': [entry('set', 'dir')],
    '/a/icons/set': [entry('laptop.svg', 'file'), entry('nested', 'dir'), entry('outside', 'link')],
    '/a/icons/set/nested': [entry('alias.svg', 'link')],
  }
  const list = (dir: string) => {
    if (!tree[dir]) throw new Error('walked into ' + dir)
    return tree[dir]
  }

  it('fails on a symlink anywhere under the vendored directories and never walks into one', () => {
    const entries = walkVendored('/a', 'icons', list)
    expect(entries.filter((e) => e.kind === 'file').map((e) => e.path)).toEqual(['icons/set/laptop.svg'])
    expect(entryProblems(entries).sort()).toEqual([
      'icons/set/nested/alias.svg: not a regular file (symlink or special file)',
      'icons/set/outside: not a regular file (symlink or special file)',
    ])
  })

  it('passes regular files and directories', () => {
    expect(entryProblems(walkVendored('/a', 'icons', (dir) => list(dir).filter((e) => e.isFile() || e.isDirectory())))).toEqual([])
  })
})
