/**
 * The vendored-asset gate (plan M7c decision 10, ADR 0023): every file under src/assets/fonts and src/assets/icons
 * is listed in src/assets/vendored.json with its SHA-256, every set ships its licence under an allowed licence,
 * and docs/compliance/third-party.md records every font file's checksum and every set's release tag.
 */
export interface VendoredSet {
  name: string
  license: string
  source: string
  release: string
  dir: string
  license_file: string
  aliases?: Record<string, string>
  files: Record<string, string>
}

export interface VendoredManifest {
  sets: VendoredSet[]
}

/** Licences accepted for vendored fonts and icons (product-owner rule; ISC for icons). */
export const allowedAssetLicenses = ['OFL-1.1', 'Apache-2.0', 'MIT', 'ISC'] as const

/**
 * Problems of the manifest against the files on disk (path relative to src/assets → SHA-256) and the third-party
 * notice; empty when the gate passes.
 */
export function vendoredProblems(manifest: VendoredManifest, actual: Record<string, string>, notice: string): string[] {
  const problems: string[] = []
  const listed = new Set<string>()
  for (const set of manifest.sets) {
    if (!(allowedAssetLicenses as readonly string[]).includes(set.license)) {
      problems.push(`${set.name}: licence ${set.license} is not one of ${allowedAssetLicenses.join(', ')}`)
    }
    if (!set.release) problems.push(`${set.name}: no release tag`)
    if (!(set.license_file in set.files)) problems.push(`${set.name}: licence file ${set.license_file} is not listed`)
    if (set.release && !notice.includes(set.release)) {
      problems.push(`${set.name}: docs/compliance/third-party.md does not name the release ${set.release}`)
    }
    for (const [file, sha] of Object.entries(set.files)) {
      const path = `${set.dir}/${file}`
      listed.add(path)
      if (!(path in actual)) {
        problems.push(`${path}: listed in vendored.json but missing`)
      } else if (actual[path] !== sha) {
        problems.push(`${path}: SHA-256 ${actual[path]} differs from vendored.json (${sha})`)
      }
      if (set.dir.startsWith('fonts/') && file !== set.license_file && !notice.includes(sha)) {
        problems.push(`${path}: docs/compliance/third-party.md does not record its SHA-256`)
      }
    }
  }
  for (const path of Object.keys(actual).sort()) {
    if ((path.startsWith('fonts/') || path.startsWith('icons/')) && !listed.has(path)) {
      problems.push(`${path}: not listed in vendored.json`)
    }
  }
  return problems
}
