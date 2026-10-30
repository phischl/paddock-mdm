import { afterEach, describe, expect, it, vi } from 'vitest'
import { resumeStepUp } from '../lib/stepUp'

describe('resumeStepUp', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('finds no pending step-up when the storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    expect(resumeStepUp('mcp-write', 'me')).toBeNull()
  })

  it('takes a pending step-up of the same action and target once', () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'mcp-write', target: 'me', payload: { a: 1 }, at: Date.now() }))
    expect(resumeStepUp('mcp-write', 'me')).toEqual({ failed: false, payload: { a: 1 } })
    expect(resumeStepUp('mcp-write', 'me')).toBeNull()
  })
})
