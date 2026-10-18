import { describe, expect, it } from 'vitest'
import { formatTime } from '../lib/format'

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
