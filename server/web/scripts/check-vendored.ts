// Lint check (plan M7c decision 10): the vendored fonts and icons match src/assets/vendored.json and the third-party
// notice. Run by `npm run lint`.
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { entryProblems, vendoredProblems, walkVendored, type VendoredManifest } from '../src/lib/vendoredCheck.ts'

const assets = fileURLToPath(new URL('../src/assets/', import.meta.url))
const notice = readFileSync(new URL('../../../docs/compliance/third-party.md', import.meta.url), 'utf8')
const manifest = JSON.parse(readFileSync(join(assets, 'vendored.json'), 'utf8')) as VendoredManifest

const actual: Record<string, string> = {}
const entries = ['fonts', 'icons'].flatMap((top) => walkVendored(assets.replace(/\/$/, ''), top, (dir) => readdirSync(dir, { withFileTypes: true })))
for (const e of entries) {
  if (e.kind === 'file') actual[e.path] = createHash('sha256').update(readFileSync(join(assets, e.path))).digest('hex')
}
const problems = [...entryProblems(entries), ...vendoredProblems(manifest, actual, notice)]
if (problems.length > 0) {
  console.error('vendored asset problems:\n  ' + problems.join('\n  '))
  process.exit(1)
}
