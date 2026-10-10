import { describe, expect, it } from 'vitest'
import { allowedAssetLicenses, vendoredProblems, type VendoredManifest } from '../lib/vendoredCheck'
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
