// Generates src/lib/icons.gen.ts from the vendored Lucide SVG files (plan M7c decision 9); `--check` (part of
// `npm run lint`) fails when the generated file is out of date instead of writing it.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { parseIconSvg, renderIconsModule, type IconNode } from '../src/lib/iconGen.ts'

const dir = new URL('../src/assets/icons/lucide/', import.meta.url)
const target = new URL('../src/lib/icons.gen.ts', import.meta.url)

const icons: Record<string, IconNode[]> = {}
for (const file of readdirSync(dir).filter((f) => f.endsWith('.svg')).sort()) {
  icons[file.replace(/\.svg$/, '')] = parseIconSvg(file, readFileSync(new URL(file, dir), 'utf8'))
}
const text = renderIconsModule(icons)
if (process.argv.includes('--check')) {
  let current = ''
  try {
    current = readFileSync(target, 'utf8')
  } catch {
    // Missing counts as out of date.
  }
  if (current !== text) {
    console.error('src/lib/icons.gen.ts is out of date: run `npm run gen:icons`')
    process.exit(1)
  }
} else {
  writeFileSync(target, text)
}
