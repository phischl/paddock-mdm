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

/** An entry under a vendored directory; path is relative to src/assets with forward slashes. */
export interface VendoredEntry {
  path: string
  kind: 'file' | 'directory' | 'other'
}

/** One directory listing entry as node:fs readdirSync(dir, { withFileTypes: true }) returns it (lstat semantics). */
interface DirectoryEntry {
  name: string
  isFile(): boolean
  isDirectory(): boolean
}

/**
 * Walks top (relative to root) without following symlinks: a recursive readdir would descend into a linked
 * directory and read files outside the vendored tree. list is node:fs readdirSync with file types (injected so this
 * module stays free of node imports).
 */
export function walkVendored(root: string, top: string, list: (dir: string) => DirectoryEntry[]): VendoredEntry[] {
  const out: VendoredEntry[] = []
  const visit = (rel: string): void => {
    for (const e of list(root + '/' + rel)) {
      const path = rel + '/' + e.name
      const kind = e.isDirectory() ? 'directory' : e.isFile() ? 'file' : 'other'
      out.push({ path, kind })
      if (kind === 'directory') visit(path)
    }
  }
  visit(top)
  return out
}

/**
 * Entries that are neither a directory nor a regular file. A symlink or a special file would bypass the checksum or
 * point outside the vendored tree, so it fails the check instead of being skipped.
 */
export function entryProblems(entries: VendoredEntry[]): string[] {
  return entries.filter((e) => e.kind === 'other').map((e) => `${e.path}: not a regular file (symlink or special file)`)
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
