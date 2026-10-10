// Lint check (plan M7c decision 10): the vendored fonts and icons match src/assets/vendored.json and the third-party
// notice. Run by `npm run lint`.
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { vendoredProblems, type VendoredManifest } from '../src/lib/vendoredCheck.ts'

const assets = fileURLToPath(new URL('../src/assets/', import.meta.url))
const notice = readFileSync(new URL('../../../docs/compliance/third-party.md', import.meta.url), 'utf8')
const manifest = JSON.parse(readFileSync(join(assets, 'vendored.json'), 'utf8')) as VendoredManifest

const actual: Record<string, string> = {}
for (const top of ['fonts', 'icons']) {
  for (const entry of readdirSync(join(assets, top), { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const path = join(entry.parentPath, entry.name)
    actual[relative(assets, path).split('\\').join('/')] = createHash('sha256').update(readFileSync(path)).digest('hex')
  }
}
const problems = vendoredProblems(manifest, actual, notice)
if (problems.length > 0) {
  console.error('vendored asset problems:\n  ' + problems.join('\n  '))
  process.exit(1)
}
