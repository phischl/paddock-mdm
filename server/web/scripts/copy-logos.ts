// Build step (plan M4c step 0b): copies the favicons and the app-bar symbol from docs/assets/logo/, the only source of
// the logos in the repository, into public/, from where Vite serves and emits them. Run by `npm run dev` and
// `npm run build`; the copies are git-ignored.
import { copyFileSync, mkdirSync } from 'node:fs'

const logos = [
  'paddock-favicon-light-tile-light.svg',
  'paddock-favicon-dark-tile-dark.svg',
  'paddock-favicon-small.svg',
  'paddock-symbol-light.svg',
  'paddock-symbol-dark.svg',
]

mkdirSync(new URL('../public/', import.meta.url), { recursive: true })
for (const name of logos) {
  copyFileSync(new URL('../../../docs/assets/logo/' + name, import.meta.url), new URL('../public/' + name, import.meta.url))
}
