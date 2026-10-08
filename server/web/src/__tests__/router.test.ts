import { describe, expect, it, vi } from 'vitest'

let resolveCount: (n: number) => void = () => undefined
vi.mock('../lib/updates', () => ({ attentionCount: () => new Promise<number>((r) => { resolveCount = r }) }))
vi.mock('../stores/session', () => ({ useSessionStore: () => ({ load: () => Promise.resolve({ role: 'org_admin' }) }) }))

describe('router', () => {
  it('does not send an organization administrator to the attention list after they navigated elsewhere', async () => {
    const { router } = await import('../router')
    const start = router.push('/')
    await new Promise((r) => setTimeout(r))
    const elsewhere = router.push('/settings/dms')
    await elsewhere
    resolveCount(7)
    await start
    await new Promise((r) => setTimeout(r))
    expect(router.currentRoute.value.name).toBe('dms-settings')
  })
})
