import { describe, expect, it, vi } from 'vitest'
import { loadSetupSteps, type SetupStep } from '../lib/setupChecklist'

let answers: Record<string, unknown> = {}
vi.mock('../api/client', () => ({
  api: {
    GET: (path: string) => Promise.resolve(path in answers ? { data: answers[path] } : { error: { code: 'internal' } }),
  },
}))

describe('loadSetupSteps', () => {
  function stubApi(a: Record<string, unknown>): void {
    answers = a
  }
  const page = (items: unknown[]) => ({ items, page: 1, page_size: 10, total: items.length, total_capped: false, sort: '' })
  const stateOf = (list: SetupStep[], k: string) => list.find((s) => s.key === k)?.state

  it('computes the organization steps from the existing endpoints', async () => {
    stubApi({
      '/api/v1/settings/login': { break_glass_accounts: [] },
      '/api/v1/users': page([{ id: 'u' }]),
      '/api/v1/enrollment-tokens': page([{ status: 'expired' }, { status: 'active' }]),
      '/api/v1/devices': page([]),
    })
    const list = await loadSetupSteps({ isPlatform: false, canWrite: true })
    expect(stateOf(list, 'breakGlass')).toBe('open')
    expect(stateOf(list, 'users')).toBe('done')
    expect(stateOf(list, 'token')).toBe('done')
    expect(stateOf(list, 'device')).toBe('open')
    expect(stateOf(list, 'agent')).toBe('manual')
  })

  it('hides the token step from a reader and marks failed reads unknown', async () => {
    stubApi({ '/api/v1/settings/login': { break_glass_accounts: ['root'] } })
    const list = await loadSetupSteps({ isPlatform: false, canWrite: false })
    expect(list.map((s) => s.key)).not.toContain('token')
    expect(stateOf(list, 'breakGlass')).toBe('done')
    expect(stateOf(list, 'users')).toBe('unknown')
    expect(stateOf(list, 'device')).toBe('unknown')
  })

  it('computes the platform steps from the platform endpoints', async () => {
    stubApi({
      '/api/platform/v1/organizations': page([{ id: 'o' }]),
      '/api/platform/v1/agent-releases': page([]),
      '/api/platform/v1/ip-allowlist': page([{ id: 'e' }]),
    })
    const list = await loadSetupSteps({ isPlatform: true, canWrite: false })
    expect(stateOf(list, 'organization')).toBe('done')
    expect(stateOf(list, 'release')).toBe('open')
    expect(stateOf(list, 'allowlist')).toBe('done')
    expect(stateOf(list, 'orgAdmin')).toBe('manual')
  })
})
