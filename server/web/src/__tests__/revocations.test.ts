import { describe, expect, it } from 'vitest'
import type { RevocationRequest } from '../api/client'
import { parseWarnDays, revocationActions, revocationStatuses, reviewVerbs, timeline } from '../lib/revocations'
import en from '../locales/en.json'

const alice = '0190f000-0000-7000-8000-00000000000a'
const bob = '0190f000-0000-7000-8000-00000000000b'

function request(over: Partial<RevocationRequest>): RevocationRequest {
  return {
    id: '0190f000-0000-7000-8000-000000000001', device_id: '0190f000-0000-7000-8000-000000000002', hostname: 'lt-1',
    action: 'destroy', status: 'requested', requested_at: '2026-10-07T10:00:00Z', reason: '', approvals: [],
    requested_by: alice, ...over,
  }
}

describe('revocations', () => {
  it('lets another administrator approve or reject a waiting destroy and its requester cancel it', () => {
    expect(reviewVerbs(request({}), bob)).toEqual(['approve', 'reject'])
    expect(reviewVerbs(request({}), alice)).toEqual(['cancel'])
    expect(reviewVerbs(request({ status: 'approved' }), bob)).toEqual([])
    expect(reviewVerbs(request({}), undefined)).toEqual([])
  })

  it('shows the steps a request went through, in order', () => {
    expect(timeline(request({
      action: 'lock', status: 'confirmed', approved_at: '2026-10-07T10:00:00Z', issued_at: '2026-10-07T10:00:05Z',
      delivered_at: '2026-10-07T10:01:00Z', confirmed_at: '2026-10-07T10:01:03Z', finished_at: '2026-10-07T10:01:03Z',
    })).map((s) => s.step)).toEqual(['requested', 'approved', 'issued', 'delivered', 'confirmed'])
    expect(timeline(request({ status: 'rejected', finished_at: '2026-10-07T11:00:00Z' })).map((s) => s.step))
      .toEqual(['requested', 'finished'])
  })

  it('parses the warning lead times', () => {
    expect(parseWarnDays('3, 1')).toEqual([3, 1])
    expect(parseWarnDays('')).toEqual([])
    expect(parseWarnDays('3, x')).toBeNull()
    expect(parseWarnDays('1.5')).toBeNull()
  })

  it('labels every action and status', () => {
    for (const a of revocationActions) expect(en.revocations.actions[a]).toBeTruthy()
    for (const s of revocationStatuses) expect(en.revocations.statuses[s]).toBeTruthy()
  })
})
