import { describe, expect, it } from 'vitest'
import { groupFingerprint, iconFileProblem, normalizeFingerprint, validateAssignment, validateEntry, validateSource, type SourceInput } from '../lib/software'

const fp = 'ABCDEF0123456789ABCD'.repeat(2)
const source: SourceInput = {
  slug: 'vendor', name: 'Vendor', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'], architectures: [],
  signingKey: 'key', fingerprint: fp,
}

describe('fingerprints', () => {
  it('normalizes spaces and case and groups in blocks of four', () => {
    expect(normalizeFingerprint(' abcd ef01\n2345 ')).toBe('ABCDEF012345')
    expect(groupFingerprint(fp)).toBe('ABCD EF01 2345 6789 ABCD ABCD EF01 2345 6789 ABCD')
  })
})

describe('validateSource', () => {
  it('accepts a valid source and refuses http, user info, query and a bad slug', () => {
    expect(validateSource(source, true)).toEqual({})
    expect(validateSource({ ...source, uris: ['http://repo.example.com'] }, true).uris).toBe('software.sources.httpsOnly')
    expect(validateSource({ ...source, uris: ['https://u:p@repo.example.com'] }, true).uris).toBe('software.sources.urisInvalid')
    expect(validateSource({ ...source, uris: ['https://repo.example.com/a?x=1'] }, true).uris).toBe('software.sources.urisInvalid')
    expect(validateSource({ ...source, slug: 'A' }, true).slug).toBe('software.sources.slugInvalid')
    expect(validateSource({ ...source, slug: 'A' }, false).slug).toBeUndefined()
  })

  it('applies the flat repository rule', () => {
    expect(validateSource({ ...source, suites: ['./'], components: [] }, true)).toEqual({})
    expect(validateSource({ ...source, suites: ['./'] }, true).components).toBe('software.sources.flatComponents')
    expect(validateSource({ ...source, suites: ['stable', './'] }, true).suites).toBe('software.sources.flatMixed')
    expect(validateSource({ ...source, components: [] }, true).components).toBe('software.sources.componentsRequired')
  })
})

describe('validateEntry', () => {
  const entry = { name: 'Editor', description: '', category: '', sourceID: null, packages: [{ distribution: 'ubuntu', release: '24.04', architecture: 'amd64' as const, package: 'nano' }] }

  it('accepts a valid entry and reports duplicate tuples and bad rows', () => {
    expect(validateEntry(entry).packages).toBeUndefined()
    const dup = validateEntry({ ...entry, packages: [entry.packages[0], { ...entry.packages[0], package: 'vim' }] })
    expect(dup.packages).toBe('software.catalog.packagesDuplicate')
    expect(validateEntry({ ...entry, packages: [{ ...entry.packages[0], package: 'X' }] }).rows[0].package).toBe('software.catalog.packageInvalid')
    expect(validateEntry({ ...entry, packages: [] }).packages).toBe('software.catalog.packagesCount')
  })
})

describe('validateAssignment and the icon', () => {
  it('requires a version for required pinned only', () => {
    const a = { entryID: 'e', groupID: null, intent: 'required' as const, updateRule: 'pinned' as const, version: '', reason: '' }
    expect(validateAssignment(a).version).toBe('software.assignments.versionRequired')
    expect(validateAssignment({ ...a, updateRule: 'latest' })).toEqual({})
    expect(validateAssignment({ ...a, intent: 'forbid' })).toEqual({})
  })

  it('refuses anything but a PNG of at most 64 KiB', () => {
    expect(iconFileProblem({ type: 'image/png', size: 100 })).toBeNull()
    expect(iconFileProblem({ type: 'image/jpeg', size: 100 })).toBe('software.icon.notPng')
    expect(iconFileProblem({ type: 'image/png', size: 65537 })).toBe('software.icon.tooLarge')
  })
})
