/**
 * Client-side CIDR validation of the IP allow list (plan M7a decision 25): the same rules as the server's
 * ipallowlist.ParseCIDR — IPv4 dotted quad or IPv6 with a prefix of at least 1, host bits zero, no IPv4-mapped
 * IPv6 — so that a typo is caught before the request. The server stays authoritative.
 */

export type ParsedCIDR =
  | { ok: true; kind: 'v4' | 'v6'; canonical: string }
  | { ok: false; message: string; canonical?: string }

const invalid: ParsedCIDR = { ok: false, message: 'ipAllowlist.cidrInvalid' }

function isDigits(s: string): boolean {
  if (s.length === 0) return false
  for (const c of s) if (c < '0' || c > '9') return false
  return true
}

function isHex(s: string): boolean {
  if (s.length === 0 || s.length > 4) return false
  for (const c of s.toLowerCase()) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false
  return true
}

/** Parses "a.b.c.d" into its 32-bit value; null when it is not a dotted quad. */
function parseV4Addr(addr: string): number | null {
  const parts = addr.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const p of parts) {
    if (!isDigits(p) || p.length > 3 || (p.length > 1 && p.startsWith('0'))) return null
    const n = Number(p)
    if (n > 255) return null
    value = value * 256 + n
  }
  return value
}

function formatV4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.')
}

/** Parses an IPv6 address into eight 16-bit words; null when it is not one. */
function parseV6Addr(addr: string): number[] | null {
  if (addr.includes(':::')) return null
  const halves = addr.split('::')
  if (halves.length > 2) return null
  const groups = (s: string): string[] => (s === '' ? [] : s.split(':'))
  const head = groups(halves[0])
  const tail = halves.length === 2 ? groups(halves[1]) : []
  const toWords = (gs: string[], last: boolean): number[] | null => {
    const words: number[] = []
    for (const [i, g] of gs.entries()) {
      if (last && i === gs.length - 1 && g.includes('.')) {
        const v4 = parseV4Addr(g)
        if (v4 === null) return null
        words.push(v4 >>> 16, v4 & 0xffff)
        continue
      }
      if (!isHex(g)) return null
      words.push(parseInt(g, 16))
    }
    return words
  }
  const headWords = toWords(head, halves.length === 1)
  const tailWords = toWords(tail, true)
  if (headWords === null || tailWords === null) return null
  if (halves.length === 1) return headWords.length === 8 ? headWords : null
  const missing = 8 - headWords.length - tailWords.length
  if (missing < 1) return null
  return [...headWords, ...new Array<number>(missing).fill(0), ...tailWords]
}

/** RFC 5952 text of eight words: lowercase hex, the longest run of at least two zero words compressed once. */
function formatV6(words: number[]): string {
  let bestStart = -1
  let bestLength = 0
  for (let i = 0; i < 8; i++) {
    if (words[i] !== 0) continue
    let j = i
    while (j < 8 && words[j] === 0) j++
    if (j - i > bestLength) {
      bestStart = i
      bestLength = j - i
    }
    i = j
  }
  const hex = (ws: number[]) => ws.map((w) => w.toString(16)).join(':')
  if (bestLength < 2) return hex(words)
  return hex(words.slice(0, bestStart)) + '::' + hex(words.slice(bestStart + bestLength))
}

/** Validates text as a CIDR and returns its canonical form, or a message key (and the canonical form to use). */
export function parseCIDR(text: string): ParsedCIDR {
  const s = text.trim()
  const slash = s.indexOf('/')
  if (slash < 0 || s.indexOf('/', slash + 1) >= 0) return invalid
  const addr = s.slice(0, slash)
  const bitsText = s.slice(slash + 1)
  if (!isDigits(bitsText) || bitsText.length > 3) return invalid
  const bits = Number(bitsText)
  if (addr.includes(':')) {
    const words = parseV6Addr(addr)
    if (words === null || bits > 128) return invalid
    if (bits === 0) return { ok: false, message: 'ipAllowlist.cidrZero' }
    if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff) return { ok: false, message: 'ipAllowlist.cidrMapped' }
    const masked = words.map((w, i) => {
      const keep = Math.min(16, Math.max(0, bits - i * 16))
      return keep === 0 ? 0 : (w & ((0xffff << (16 - keep)) & 0xffff)) & 0xffff
    })
    const canonical = formatV6(masked) + '/' + bits
    if (masked.some((w, i) => w !== words[i])) return { ok: false, message: 'ipAllowlist.cidrHostBits', canonical }
    return { ok: true, kind: 'v6', canonical }
  }
  const value = parseV4Addr(addr)
  if (value === null || bits > 32) return invalid
  if (bits === 0) return { ok: false, message: 'ipAllowlist.cidrZero' }
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0
  const masked = (value & mask) >>> 0
  const canonical = formatV4(masked) + '/' + bits
  if (masked !== value) return { ok: false, message: 'ipAllowlist.cidrHostBits', canonical }
  return { ok: true, kind: 'v4', canonical }
}

/** The single-address range of ip: /32 or /128. */
export function singleAddressCIDR(ip: string): string {
  return ip + (ip.includes(':') ? '/128' : '/32')
}
