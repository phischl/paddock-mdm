import { beforeEach, describe, expect, it, vi } from 'vitest'
import { findingStatus } from '../lib/status'
import { findingFilters, liveFindingStatuses, listFindings, maxFindingReason, validateClose } from '../lib/findings'

const get = vi.hoisted(() => vi.fn())
vi.mock('../api/client', async (original) => ({
  ...(await original<typeof import('../api/client')>()),
  api: { GET: get },
}))

beforeEach(() => {
  get.mockReset()
  get.mockResolvedValue({ data: { items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-last_seen_at' } })
})

describe('listFindings', () => {
  it('asks for the live statuses and the uncleared findings by default', async () => {
    await listFindings({ page: 1, page_size: 25, sort: '-last_seen_at', status: [], kind: [], cleared: [] })
    expect(get).toHaveBeenCalledWith('/api/v1/findings', {
      params: { query: expect.objectContaining({ status: liveFindingStatuses, cleared: false, kind: undefined }) },
    })
  })

  it('passes the chosen statuses, kind and cleared filter', async () => {
    await listFindings({ page: 2, page_size: 10, sort: 'hostname', q: 'acme', status: ['false_positive', 'resolved'], kind: ['tamper'], cleared: ['true'] })
    expect(get.mock.calls[0][1].params.query).toEqual({
      page: 2, page_size: 10, sort: 'hostname', q: 'acme', status: ['false_positive', 'resolved'], kind: 'tamper', cleared: true,
    })
  })

  it('turns a problem into a list error', async () => {
    get.mockResolvedValue({ error: { code: 'forbidden' } })
    await expect(listFindings({ page: 1, page_size: 25, sort: '-last_seen_at' })).rejects.toMatchObject({ code: 'forbidden' })
  })
})

describe('finding rules', () => {
  it('requires a reason within the limit and bounds the external reference', () => {
    expect(validateClose({ resolution: 'resolved', reason: '  ', externalRef: '' })).toEqual({ reason: 'findings.close.reasonRequired' })
    expect(validateClose({ resolution: 'resolved', reason: 'x'.repeat(maxFindingReason + 1), externalRef: '' }).reason).toBe('findings.close.reasonTooLong')
    expect(validateClose({ resolution: 'resolved', reason: 'ok', externalRef: 'x'.repeat(201) }).externalRef).toBe('findings.close.externalRefTooLong')
    expect(validateClose({ resolution: 'accepted_risk', reason: 'ok', externalRef: 'CHG-1' })).toEqual({})
  })

  it('maps every status to a chip with a label and has a repeatable status filter', () => {
    expect(findingStatus('open')).toEqual({ status: 'warn', label: 'findings.status.open' })
    expect(findingStatus('in_progress').status).toBe('info')
    expect(findingStatus('false_positive').status).toBe('neutral')
    expect(findingFilters.map((f) => (f.kind === 'enum' ? f.key : ''))).toEqual(['status', 'kind', 'cleared'])
  })
})
