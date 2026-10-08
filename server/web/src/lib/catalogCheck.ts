import IntlMessageFormat from 'intl-messageformat'

/** A message catalog as stored in src/locales/*.json. */
export type Catalog = { [key: string]: string | Catalog }

/** The message keys of a catalog with their messages, dotted. */
export function messages(catalog: Catalog, prefix = ''): Map<string, string> {
  const out = new Map<string, string>()
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === 'string') out.set(prefix + key, value)
    else for (const [k, v] of messages(value, prefix + key + '.')) out.set(k, v)
  }
  return out
}

// Argument, number, date, time, select and plural elements of the ICU AST (@formatjs/icu-messageformat-parser
// TYPE 1–6) name an argument; select and plural carry nested messages in their options.
type AstElement = { type: number; value?: unknown; options?: Record<string, { value: AstElement[] }> }

function argumentNames(elements: AstElement[], into = new Set<string>()): Set<string> {
  for (const el of elements) {
    if (el.type >= 1 && el.type <= 6 && typeof el.value === 'string') into.add(el.value)
    for (const option of Object.values(el.options ?? {})) argumentNames(option.value, into)
  }
  return into
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  return a.size === b.size && [...a].every((x) => b.has(x))
}

/**
 * The problems of a translated catalog against the English source (plan M6b decision 2): keys missing or extra,
 * messages that are not valid ICU MessageFormat, messages whose arguments differ from the English ones, and audit
 * codes without a display message audit.<code>. An empty list means the catalog is complete.
 */
export function catalogProblems(en: Catalog, translated: Catalog, locale: string, auditCodes: readonly string[]): string[] {
  const source = messages(en)
  const target = messages(translated)
  const problems: string[] = []
  for (const code of auditCodes) {
    if (!source.has('audit.' + code)) problems.push(`en: audit.${code}: no display message for the audit code`)
  }
  for (const [key, message] of source) {
    const other = target.get(key)
    if (other === undefined) {
      problems.push(`${locale}: ${key}: missing`)
      continue
    }
    let names: Set<string>
    try {
      names = argumentNames(new IntlMessageFormat(other, locale).getAst() as AstElement[])
    } catch (err) {
      problems.push(`${locale}: ${key}: not valid ICU MessageFormat (${(err as Error).message})`)
      continue
    }
    const expected = argumentNames(new IntlMessageFormat(message, 'en').getAst() as AstElement[])
    if (!sameSet(names, expected)) {
      problems.push(`${locale}: ${key}: arguments {${[...names].sort().join(', ')}} differ from en {${[...expected].sort().join(', ')}}`)
    }
  }
  for (const key of target.keys()) {
    if (!source.has(key)) problems.push(`${locale}: ${key}: not in en.json`)
  }
  return problems
}
