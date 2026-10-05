// Lint check (plan M4a step 0b): every code of the generated audit code list has an English display message
// audit.<code> in src/locales/en.json. Run by `npm run lint`.
import { readFileSync } from 'node:fs'
import { auditCodes } from '../src/lib/auditCodes.gen.ts'

type Messages = { [key: string]: string | Messages }

const en = JSON.parse(readFileSync(new URL('../src/locales/en.json', import.meta.url), 'utf8')) as Messages

function message(messages: Messages, key: string): string | undefined {
  let node: string | Messages | undefined = messages
  for (const part of key.split('.')) {
    node = typeof node === 'object' ? node[part] : undefined
  }
  return typeof node === 'string' ? node : undefined
}

const missing = auditCodes.filter((code) => !message(en, 'audit.' + code))
if (missing.length > 0) {
  console.error('audit codes without an English message in src/locales/en.json:\n  audit.' + missing.join('\n  audit.'))
  process.exit(1)
}
