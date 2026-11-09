import { describe, expect, it } from 'vitest'
import {
  assignmentTarget, compileWarningMessage, groupFingerprint, iconFileProblem, normalizeAssignment, normalizeFingerprint, packagesForSource,
  validateAssignment, validateEntry, validateSource, type SourceInput,
} from '../lib/software'

const fp = 'ABCDEF0123456789ABCD'.repeat(2)
const source: SourceInput = {
  kind: 'apt', slug: 'vendor', name: 'Vendor', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'], architectures: [],
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

  it('mirrors the server URI rules: case-sensitive scheme, characters, port, repeats', () => {
    const uris = (u: string[]) => validateSource({ ...source, uris: u }, true).uris
    expect(uris(['HTTPS://repo.example.com'])).toBe('software.sources.httpsOnly')
    expect(uris(['https://repo.example.com/a"b'])).toBe('software.sources.urisInvalid')
    expect(uris(['https://repo.example.com/<a>'])).toBe('software.sources.urisInvalid')
    expect(uris(['https://repo.example.com:0/apt'])).toBe('software.sources.urisInvalid')
    expect(uris(['https://repo.example.com:/apt'])).toBe('software.sources.urisInvalid')
    expect(uris(['https://repo.example.com:8443/apt'])).toBeUndefined()
    expect(uris(['https://repo.example.com\u200b/apt'])).toBe('software.sources.urisInvalid')
    expect(uris(['https://repo.example.com/apt', 'https://REPO.example.com:443/apt/'])).toBe('software.sources.repeated')
    expect(uris(['https://repo.example.com/apt', 'https://repo.example.com/other'])).toBeUndefined()
  })

  it('refuses repeated suites and components and a .. segment', () => {
    expect(validateSource({ ...source, suites: ['stable', 'stable'] }, true).suites).toBe('software.sources.repeated')
    expect(validateSource({ ...source, suites: ['../x/'], components: [] }, true).suites).toBe('software.sources.suitesInvalid')
    expect(validateSource({ ...source, components: ['main', 'main'] }, true).components).toBe('software.sources.repeated')
  })

  it('applies the flat repository rule', () => {
    expect(validateSource({ ...source, suites: ['./'], components: [] }, true)).toEqual({})
    expect(validateSource({ ...source, suites: ['./'] }, true).components).toBe('software.sources.flatComponents')
    expect(validateSource({ ...source, suites: ['stable', './'] }, true).suites).toBe('software.sources.flatMixed')
    expect(validateSource({ ...source, components: [] }, true).components).toBe('software.sources.componentsRequired')
  })
})

describe('a Flatpak remote (plan M13b decision 5)', () => {
  const remote: SourceInput = { ...source, kind: 'flatpak', uris: ['https://dl.flathub.org/repo/'], suites: [], components: [] }

  it('needs exactly one https URL and the key, and no suites or components', () => {
    expect(validateSource(remote, true)).toEqual({})
    expect(validateSource({ ...remote, uris: ['https://a.example.org/repo/', 'https://b.example.org/repo/'] }, true).uris).toBe('software.sources.flatpakUri')
    expect(validateSource({ ...remote, uris: [] }, true).uris).toBe('software.sources.flatpakUri')
    expect(validateSource({ ...remote, uris: ['http://dl.flathub.org/repo/'] }, true).uris).toBe('software.sources.httpsOnly')
    expect(validateSource({ ...remote, signingKey: ' ' }, true).signingKey).toBe('software.sources.keyInvalid')
    expect(validateSource({ ...remote, fingerprint: 'x' }, true).fingerprint).toBe('software.sources.fingerprintInvalid')
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

  it('checks Flatpak application IDs for a Flatpak source and keeps only the fields of the source kind', () => {
    const row = { distribution: 'ubuntu', release: '*', architecture: '*' as const, flatpak_ref: 'org.gimp.GIMP', scope: 'user' as const, package: 'gimp' }
    const flatpak = packagesForSource([row], true)
    expect(flatpak).toEqual([{ distribution: 'ubuntu', release: '*', architecture: '*', flatpak_ref: 'org.gimp.GIMP', scope: 'user' }])
    expect(packagesForSource([row], false)).toEqual([{ distribution: 'ubuntu', release: '*', architecture: '*', package: 'gimp' }])
    expect(validateEntry({ ...entry, packages: flatpak }, true).rows[0]).toEqual({})
    expect(validateEntry({ ...entry, packages: [{ ...flatpak[0], flatpak_ref: 'gimp' }] }, true).rows[0].flatpakRef).toBe('software.catalog.flatpakRefInvalid')
    expect(validateEntry({ ...entry, packages: [{ ...flatpak[0], flatpak_ref: 'org.' + 'a'.repeat(252) + '.x' }] }, true).rows[0].flatpakRef)
      .toBe('software.catalog.flatpakRefInvalid')
  })
})

describe('validateAssignment and the icon', () => {
  it('requires a version for required pinned only', () => {
    const a = { entryID: 'e', target: 'organization' as const, targetID: null, intent: 'required' as const, updateRule: 'pinned' as const, version: '', reason: '' }
    expect(validateAssignment(a).version).toBe('software.assignments.versionRequired')
    expect(validateAssignment({ ...a, updateRule: 'latest' })).toEqual({})
    expect(validateAssignment({ ...a, intent: 'forbid' })).toEqual({})
  })

  it('needs the target ID of a device group, user or user group target', () => {
    const a = { entryID: 'e', target: 'user' as const, targetID: null, intent: 'available' as const, updateRule: 'latest' as const, version: '', reason: '' }
    expect(validateAssignment(a).target).toBe('software.assignments.targetRequired')
    expect(validateAssignment({ ...a, targetID: 'u1' })).toEqual({})
    expect(validateAssignment({ ...a, target: 'organization' })).toEqual({})
  })

  it('sends available without a version and with the rule latest', () => {
    const a = { entryID: 'e', target: 'user_group' as const, targetID: 'g', intent: 'available' as const, updateRule: 'pinned' as const, version: '1.0', reason: '' }
    expect(normalizeAssignment(a)).toMatchObject({ updateRule: 'latest', version: '' })
  })

  it('reads the target kind of a stored assignment', () => {
    const none = { device_group_id: null, user_id: null, user_group_id: null }
    expect(assignmentTarget(none)).toEqual({ target: 'organization', targetID: null })
    expect(assignmentTarget({ ...none, device_group_id: 'd' })).toEqual({ target: 'device_group', targetID: 'd' })
    expect(assignmentTarget({ ...none, user_id: 'u' })).toEqual({ target: 'user', targetID: 'u' })
    expect(assignmentTarget({ ...none, user_group_id: 'g' })).toEqual({ target: 'user_group', targetID: 'g' })
  })

  it('names known compile warnings and keeps an unknown code visible', () => {
    expect(compileWarningMessage({ code: 'flatpak_forbidden', params: { flatpak_ref: 'org.gimp.GIMP' } }))
      .toEqual({ key: 'software.compileWarnings.text.flatpak_forbidden', args: { code: 'flatpak_forbidden', flatpak_ref: 'org.gimp.GIMP' } })
    expect(compileWarningMessage({ code: 'something_new', params: {} }).key).toBe('software.compileWarnings.text.unknown')
  })

  it('refuses anything but a PNG of at most 64 KiB', () => {
    expect(iconFileProblem({ type: 'image/png', size: 100 })).toBeNull()
    expect(iconFileProblem({ type: 'image/jpeg', size: 100 })).toBe('software.icon.notPng')
    expect(iconFileProblem({ type: 'image/png', size: 65537 })).toBe('software.icon.tooLarge')
  })
})
