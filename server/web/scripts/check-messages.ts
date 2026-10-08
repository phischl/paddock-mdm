// Lint check (plan M4a step 0b, plan M6b decision 2): every audit code has a display message audit.<code>, and every
// translated catalog has exactly the keys of src/locales/en.json, valid ICU messages and the English arguments. Run
// by `npm run lint`.
import { readFileSync } from 'node:fs'
import { auditCodes } from '../src/lib/auditCodes.gen.ts'
import { catalogProblems, type Catalog } from '../src/lib/catalogCheck.ts'

const catalog = (locale: string) =>
  JSON.parse(readFileSync(new URL(`../src/locales/${locale}.json`, import.meta.url), 'utf8')) as Catalog

const en = catalog('en')
const problems = ['de'].flatMap((locale) => catalogProblems(en, catalog(locale), locale, auditCodes))
if (problems.length > 0) {
  console.error('message catalog problems:\n  ' + problems.join('\n  '))
  process.exit(1)
}
