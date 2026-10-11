/**
 * Timestamps of tables (plan M7c decision 20): absolute values in the browser's time zone as YYYY-MM-DD HH:MM
 * (today: the time only), relative values with the largest unit of at least one. formatDateTime (lib/format.ts)
 * stays for prose.
 */
const pad = (n: number) => String(n).padStart(2, '0')

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
}

/** The full absolute value for tooltips: always with the date and seconds. */
export function formatAbsoluteFull(iso: string): string {
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function formatAbsolute(iso: string, now: Date, precision: 'minute' | 'second' = 'minute'): string {
  const d = new Date(iso)
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}` + (precision === 'second' ? `:${pad(d.getSeconds())}` : '')
  if (sameDay(d, now)) return time
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`
}

const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
]

/** "9 d ago" style: the largest unit that is at least one; the future reads "in …". */
export function formatRelative(iso: string, now: Date, locale: string): string {
  const seconds = Math.round((new Date(iso).getTime() - now.getTime()) / 1000)
  const format = new Intl.RelativeTimeFormat(locale, { numeric: 'always', style: 'narrow' })
  const magnitude = Math.abs(seconds)
  for (const [unit, size] of units) {
    if (magnitude >= size) return format.format(Math.trunc(seconds / size), unit)
  }
  // Negative zero reads "0s ago" (not "in 0s") for an instant within the last second.
  return format.format(seconds <= 0 ? -0 : 0, 'second')
}
