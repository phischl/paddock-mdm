import { describe, expect, it, vi } from 'vitest'

let role = 'org_admin'
vi.mock('../stores/session', () => ({ useSessionStore: () => ({ load: () => Promise.resolve({ role }) }) }))

describe('router', () => {
  it('starts every role on its page (plan M7c decision 28)', async () => {
    const { homeFor } = await import('../router')
    expect(homeFor('org_admin')).toEqual({ name: 'home' })
    expect(homeFor('org_operator')).toEqual({ name: 'home' })
    expect(homeFor('org_auditor')).toEqual({ name: 'audit' })
    expect(homeFor('platform_admin')).toEqual({ name: 'organizations' })
  })

  it('keeps administrators on the overview and sends auditors to the audit log', async () => {
    const { router } = await import('../router')
    role = 'org_admin'
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('home')
    await router.push('/settings/dms')
    role = 'org_auditor'
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('audit')
  })
})
