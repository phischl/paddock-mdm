import { describe, expect, it } from 'vitest'
import { formatGB, formatGiB, formatTime } from '../lib/format'

describe('formatTime (plan M8x §6.6: identity confirmed until HH:MM)', () => {
  // Local times: the instant is built from local components so the browser's time zone does not matter.
  const iso = new Date(2026, 9, 18, 14, 7, 50).toISOString()

  it('shows hours and minutes on a 24-hour clock in German, without seconds', () => {
    expect(formatTime(iso, 'de')).toBe('14:07')
  })

  it('follows the English clock, without seconds', () => {
    expect(formatTime(iso, 'en')).toMatch(/^2:07\sPM$/)
  })
})

describe('hardware sizes (PDK-221)', () => {
  it('formats memory in GiB and disk size in GB with one decimal, nothing for 0', () => {
    expect(formatGiB(33328349184, 'en')).toBe('31.0 GiB')
    expect(formatGiB(33328349184, 'de')).toBe('31,0 GiB')
    expect(formatGB(510440000000, 'en')).toBe('510.4 GB')
    expect(formatGB(1_500_000_000_000, 'de')).toBe('1.500,0 GB')
    expect(formatGiB(0, 'en')).toBeNull()
    expect(formatGB(0, 'en')).toBeNull()
  })
})
