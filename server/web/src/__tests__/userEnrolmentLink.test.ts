import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import UserDetail from '../views/UserDetail.vue'
import { api, type UserEnrolmentLink } from '../api/client'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const createEnrolmentLink = vi.fn<(id: string) => Promise<UserEnrolmentLink | string>>()
const locked = vi.hoisted(() => ({ value: false }))
vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  getUser: () => Promise.resolve({
    id: 'u1', username: 'erin@acme.test', display_name: 'Erin', email: '', source: 'local', locked: locked.value,
    lock_incomplete: false, locked_at: null, domain_match: true, groups: [], created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
  }),
  getEffectiveProfile: () => Promise.resolve('not_found'),
  listOwnedDevices: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'hostname' }),
  createEnrolmentLink: (id: string) => createEnrolmentLink(id),
}))
vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listUserSoftware: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'name' }),
}))
vi.mock('../lib/devices', async (original) => ({ ...(await original<typeof import('../lib/devices')>()), allDevices: () => Promise.resolve([]) }))
vi.mock('../lib/userGroups', async (original) => ({ ...(await original<typeof import('../lib/userGroups')>()), allUserGroups: () => Promise.resolve([]) }))

const link: UserEnrolmentLink = { link: 'https://auth.test/if/flow/paddock-recovery/?flow_token=one-time', expires_at: '2026-11-16T10:00:00Z' }
let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  createEnrolmentLink.mockReset()
  assign.mockReset()
  locked.value = false
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/users/u1', search: '' }, writable: true, configurable: true,
  })
})
afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
  vi.restoreAllMocks()
})

async function mountAt(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/users/:id', name: 'user', component: UserDetail },
      { path: '/users', name: 'users', component: { render: () => null } },
    ],
  })
  await router.push('/users/u1')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

function el(id: string): HTMLElement | null {
  return document.body.querySelector(`[data-testid="${id}"]`)
}

/** Clicks the action and answers its confirmation. */
async function requestLink(confirmed: boolean): Promise<void> {
  el('enrolment-link')?.click()
  await flushPromises()
  expect(pendingConfirm.value?.options.title).toBe('Sign-in setup link')
  expect(pendingConfirm.value?.options.message).toContain('erin@acme.test')
  settleConfirm(confirmed ? { reason: '' } : false)
  await flushPromises()
}

describe('the sign-in setup link of a user (ADR 0053 decision 1)', () => {
  it('shows the link once after the confirmation and drops it when the dialog closes', async () => {
    createEnrolmentLink.mockResolvedValueOnce(link)
    await mountAt('org_admin')
    expect(el('enrolment-link-help')?.textContent).toContain('A new link ends every older one')
    await requestLink(true)
    expect(createEnrolmentLink).toHaveBeenCalledWith('u1')
    const field = el('enrolment-link-value')?.querySelector('input') as HTMLInputElement
    expect(field.value).toBe(link.link)
    expect(field.readOnly).toBe(true)
    expect(document.body.textContent).toContain('It is valid until')
    el('close-enrolment-link')?.click()
    await flushPromises()
    expect(el('enrolment-link-value')).toBeNull()
    expect(document.body.innerHTML).not.toContain('flow_token=one-time')
  })

  it('copies the link', async () => {
    const writeText = vi.fn(() => Promise.resolve())
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    createEnrolmentLink.mockResolvedValueOnce(link)
    await mountAt('org_admin')
    await requestLink(true)
    el('copy-enrolment-link')?.click()
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(link.link)
    expect(document.body.textContent).toContain('Copied')
  })

  it('keeps the link in the field and says so inline when the clipboard refuses', async () => {
    const writeText = vi.fn(() => Promise.reject(new DOMException('denied', 'NotAllowedError')))
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    createEnrolmentLink.mockResolvedValueOnce(link)
    await mountAt('org_admin')
    await requestLink(true)
    el('copy-enrolment-link')?.click()
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(link.link)
    expect(document.body.textContent).toContain('The link could not be copied')
    expect(document.body.textContent).not.toContain('Copied')
    expect((el('enrolment-link-value')?.querySelector('input') as HTMLInputElement).value).toBe(link.link)
  })

  it('creates nothing when the confirmation is cancelled', async () => {
    await mountAt('org_admin')
    await requestLink(false)
    expect(createEnrolmentLink).not.toHaveBeenCalled()
  })

  it('starts the step-up and repeats the request once when the browser comes back', async () => {
    createEnrolmentLink.mockResolvedValueOnce('step_up_required')
    await mountAt('org_admin')
    await requestLink(true)
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fusers%2Fu1')
    wrapper?.unmount()
    createEnrolmentLink.mockResolvedValueOnce(link)
    await mountAt('org_admin')
    expect(createEnrolmentLink).toHaveBeenCalledTimes(2)
    expect((el('enrolment-link-value')?.querySelector('input') as HTMLInputElement).value).toBe(link.link)
  })

  it('does not start a second step-up when the resumed request still needs one', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'user-enrolment-link', target: 'u1', at: Date.now(), payload: null }))
    createEnrolmentLink.mockResolvedValueOnce('step_up_required')
    await mountAt('org_admin')
    expect(createEnrolmentLink).toHaveBeenCalledTimes(1)
    expect(assign).not.toHaveBeenCalled()
    expect(el('enrolment-link-value')).toBeNull()
    expect(document.body.querySelector('[role="alert"]')?.textContent).toContain('Confirm your identity')
  })

  it('shows the refusal of a locked or deactivated user inline', async () => {
    createEnrolmentLink.mockResolvedValueOnce('invalid_state')
    await mountAt('org_admin')
    await requestLink(true)
    expect(el('enrolment-link-value')).toBeNull()
    expect(document.body.querySelector('.form-error')).not.toBeNull()
  })

  it('tells the administrator that the host operator issues the link of a platform administrator', async () => {
    createEnrolmentLink.mockResolvedValueOnce('enrolment_link_platform_administrator')
    await mountAt('org_admin')
    await requestLink(true)
    expect(el('enrolment-link-value')).toBeNull()
    expect(document.body.querySelector('[role="alert"]')?.textContent)
      .toContain('Platform administrators receive their sign-in setup link from the host operator.')
  })

  it.each(['org_operator', 'org_auditor'])('is not offered to %s', async (role) => {
    await mountAt(role)
    expect(el('enrolment-link')).toBeNull()
    expect(el('enrolment-link-help')).toBeNull()
  })

  it('is not offered for a locked user', async () => {
    locked.value = true
    await mountAt('org_admin')
    expect(el('enrolment-link')).toBeNull()
  })
})

describe('createEnrolmentLink (plan M12h-2 amendment f)', () => {
  async function answer(error: { code: string; detail?: string }): Promise<UserEnrolmentLink | string> {
    vi.spyOn(api, 'POST').mockResolvedValue({ data: undefined, error, response: new Response(null, { status: 409 }) } as never)
    const actual = await vi.importActual<typeof import('../lib/users')>('../lib/users')
    return actual.createEnrolmentLink('u1')
  }

  it('names the platform administrator refusal by its detail', async () => {
    expect(await answer({ code: 'invalid_state', detail: 'platform administrators receive their setup link from the host operator' }))
      .toBe('enrolment_link_platform_administrator')
  })

  it('keeps invalid_state for a locked or deactivated user', async () => {
    expect(await answer({ code: 'invalid_state', detail: 'the user is locked' })).toBe('invalid_state')
    expect(await answer({ code: 'invalid_state' })).toBe('invalid_state')
  })
})
