// License gate of the npm production dependencies (plan M6b decision 3, C8): every package's license must be an SPDX
// expression of licenses on the allow list. It fails closed: AND needs every operand allowed, OR at least one, and
// anything that is not such an expression (WITH, "SEE LICENSE IN …", UNKNOWN, a guessed "MIT*", no license) fails.

/** One entry of `license-checker-rseidelsohn --json`. */
export interface LicenseEntry {
  licenses?: string | string[]
}

const idPattern = /^[A-Za-z0-9][A-Za-z0-9.-]*$/

function tokenize(expr: string): string[] | null {
  const tokens = expr.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ').trim().split(/\s+/)
  return tokens.length === 1 && tokens[0] === '' ? null : tokens
}

/** licenseAllowed reports whether expr is an SPDX expression that the allowed licenses satisfy. */
export function licenseAllowed(expr: string, allowed: ReadonlySet<string>): boolean {
  const tokens = tokenize(expr)
  if (tokens === null) return false
  let pos = 0
  // Each parser returns the value of its subexpression, or null on a syntax error.
  const atom = (): boolean | null => {
    const t = tokens[pos++]
    if (t === '(') {
      const v = or()
      return tokens[pos++] === ')' ? v : null
    }
    if (t === undefined || t === 'AND' || t === 'OR' || t === 'WITH' || !idPattern.test(t)) return null
    return allowed.has(t)
  }
  const and = (): boolean | null => {
    let v = atom()
    while (v !== null && tokens[pos] === 'AND') {
      pos++
      const r = atom()
      v = r === null ? null : v && r
    }
    return v
  }
  const or = (): boolean | null => {
    let v = and()
    while (v !== null && tokens[pos] === 'OR') {
      pos++
      const r = and()
      v = r === null ? null : v || r
    }
    return v
  }
  const v = or()
  return v === true && pos === tokens.length
}

/** licenseProblems returns one line per package whose license the allow list does not satisfy. */
export function licenseProblems(packages: Record<string, LicenseEntry>, allowed: readonly string[]): string[] {
  const set = new Set(allowed)
  const problems: string[] = []
  for (const [name, entry] of Object.entries(packages).sort(([a], [b]) => a.localeCompare(b))) {
    const licenses = entry.licenses
    // An array lists several licenses without saying how they combine; every one of them must be allowed.
    const exprs = licenses === undefined ? [] : Array.isArray(licenses) ? licenses : [licenses]
    if (exprs.length === 0 || !exprs.every((e) => licenseAllowed(e, set))) {
      problems.push(`${name}: ${licenses === undefined ? 'no license' : JSON.stringify(licenses)}`)
    }
  }
  return problems
}
