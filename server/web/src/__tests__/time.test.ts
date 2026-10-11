import { describe, expect, it } from 'vitest'
import { formatAbsolute, formatAbsoluteFull, formatRelative } from '../lib/time'

// Local times: the tests build the instants from local components so the browser's time zone does not matter.
const local = (y: number, m: number, d: number, h: number, min: number, s = 0) => new Date(y, m - 1, d, h, min, s)
const now = local(2026, 10, 10, 14, 32, 5)

describe('formatAbsolute (plan M7c decision 20)', () => {
  it('shows the time only for today, the date otherwise, seconds on request', () => {
    expect(formatAbsolute(local(2026, 10, 10, 9, 4, 7).toISOString(), now)).toBe('09:04')
    expect(formatAbsolute(local(2026, 10, 10, 9, 4, 7).toISOString(), now, 'second')).toBe('09:04:07')
    expect(formatAbsolute(local(2026, 9, 30, 17, 4, 59).toISOString(), now)).toBe('2026-09-30 17:04')
    expect(formatAbsolute(local(2026, 9, 30, 17, 4, 59).toISOString(), now, 'second')).toBe('2026-09-30 17:04:59')
    expect(formatAbsolute(local(2026, 10, 9, 23, 59).toISOString(), now)).toBe('2026-10-09 23:59')
  })
  it('keeps the full value for tooltips', () => {
    expect(formatAbsoluteFull(local(2026, 10, 10, 9, 4, 7).toISOString())).toBe('2026-10-10 09:04:07')
  })
})

describe('formatRelative', () => {
  const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000).toISOString()
  it('uses the largest unit of at least one', () => {
    expect(formatRelative(ago(0), now, 'en')).toBe('0s ago')
    expect(formatRelative(ago(45), now, 'en')).toBe('45s ago')
    expect(formatRelative(ago(4 * 60 + 20), now, 'en')).toBe('4m ago')
    expect(formatRelative(ago(3600 + 1), now, 'en')).toBe('1h ago')
    expect(formatRelative(ago(9 * 86400), now, 'en')).toBe('9d ago')
    expect(formatRelative(ago(35 * 86400), now, 'en')).toBe('1mo ago')
    expect(formatRelative(ago(400 * 86400), now, 'en')).toBe('1y ago')
  })
  it('reads the future and German', () => {
    expect(formatRelative(ago(-90), now, 'en')).toBe('in 1m')
    expect(formatRelative(ago(9 * 86400), now, 'de')).toBe('vor 9 Tagen')
  })
})
