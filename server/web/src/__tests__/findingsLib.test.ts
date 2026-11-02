import { createPortalI18n } from '../i18n'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { findingStatus } from '../lib/status'
import { findingFilters, findingTitle, liveFindingStatuses, listAccounts, listFindings, maxFindingReason, validateClose } from '../lib/findings'

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

  it('restricts kind to a single choice and sends none for both', async () => {
    await listFindings({ page: 1, page_size: 25, sort: '-last_seen_at', kind: ['tamper', 'attention'] })
    expect(get.mock.calls[0][1].params.query.kind).toBeUndefined()
    await listFindings({ page: 1, page_size: 25, sort: '-last_seen_at', kind: ['attention'] })
    expect(get.mock.calls[1][1].params.query.kind).toBe('attention')
  })

  it('turns a problem into a list error', async () => {
    get.mockResolvedValue({ error: { code: 'forbidden' } })
    await expect(listFindings({ page: 1, page_size: 25, sort: '-last_seen_at' })).rejects.toMatchObject({ code: 'forbidden' })
  })
})

describe('listAccounts', () => {
  it('asks for administrators and operators only, never auditors', async () => {
    get.mockResolvedValue({ data: { items: [{ id: 'u1' }] } })
    expect(await listAccounts()).toEqual([{ id: 'u1' }])
    expect(get).toHaveBeenCalledWith('/api/v1/accounts', {
      params: { query: { page: 1, page_size: 100, sort: 'username', role: ['org_admin', 'org_operator'] } },
    })
  })

  it('returns the problem code when the accounts cannot be loaded', async () => {
    get.mockResolvedValue({ error: { code: 'forbidden' } })
    expect(await listAccounts()).toBe('forbidden')
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

describe('findingTitle', () => {
  const tamper = { kind: 'tamper' as const, code: 'device.tamper_sudoers_d_file', subject: '/etc/sudoers.d/x', hostname: 'lt-1' }
  const titleIn = (locale: 'en' | 'de', f: Parameters<typeof findingTitle>[0]) => {
    const { t, te } = createPortalI18n(locale).global
    return findingTitle(f, t as never, te as never)
  }

  it('shows a tamper code through its audit message with the device and the subject', () => {
    expect(titleIn('en', tamper)).toBe('The device lt-1 quarantined the unexpected sudoers file /etc/sudoers.d/x')
    expect(titleIn('de', tamper)).not.toContain('device.tamper')
    expect(titleIn('de', tamper)).toContain('lt-1')
    expect(titleIn('de', tamper)).toContain('/etc/sudoers.d/x')
  })

  it('has a label for every tamper code that opens a finding, in both languages', () => {
    const codes = [
      'device.tamper_sudo_group_member', 'device.tamper_sudoers_d_file', 'device.tamper_sudoers_changed',
      'device.tamper_protected_file_changed', 'device.tamper_local_admin_changed', 'device.tamper_keyslot_changed',
      'device.tamper_service_stopped', 'device.clone_suspected', 'device.tamper_agent_not_running',
    ]
    for (const locale of ['en', 'de'] as const) {
      for (const code of codes) {
        const title = titleIn(locale, { kind: 'tamper', code, subject: 's', hostname: 'lt-1' })
        expect(title, `${locale} ${code}`).not.toBe(code)
        expect(title, `${locale} ${code}`).toContain('lt-1')
      }
    }
  })

  it('appends the subject when the message has no slot for it', () => {
    const keyslot = { kind: 'tamper' as const, code: 'device.tamper_keyslot_changed', subject: '/dev/sda2', hostname: 'lt-1' }
    for (const locale of ['en', 'de'] as const) expect(titleIn(locale, keyslot)).toContain('(/dev/sda2)')
  })

  it('names an attention finding by its condition label and device, and falls back to an unknown code', () => {
    expect(titleIn('en', { kind: 'attention', code: 'stale_critical', subject: '', hostname: 'lt-1' })).toBe('Silent (critical) – lt-1')
    expect(titleIn('en', { ...tamper, code: 'device.unknown_thing' })).toBe('device.unknown_thing')
  })
})
