import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import NotificationDestinationForm from '../components/NotificationDestinationForm.vue'
import NotificationDestinations from '../views/NotificationDestinations.vue'
import PlatformNotifications from '../views/PlatformNotifications.vue'
import { createPortalI18n } from '../i18n'
import en from '../locales/en.json'
import de from '../locales/de.json'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'
import {
  backlogOf, emptyInput, fieldOfProblem, lagParts, parseRecipients, pollUntil, stateStatus, validateNotification,
  type NotificationDestination, type NotificationInput,
} from '../lib/notifications'

function destination(over: Partial<NotificationDestination> = {}): NotificationDestination {
  return {
    id: 'd1', type: 'webhook', name: 'SIEM', enabled: true, filter_mode: 'security', codes: [], pseudonymize_users: false,
    include_params: false, url_display: 'https://siem.example/…', heartbeat_interval_s: 0, recipients: [],
    email_min_interval_s: 300, created_by: 'alice', created_at: '2026-10-30T10:00:00Z', updated_at: '2026-10-30T10:00:00Z',
    state: {
      status: 'active', cursor_commit_seq: 90, forward_seq: 90, last_success_at: '2026-10-31T09:00:00Z', last_attempt_at: null,
      next_attempt_at: null, stalled_since: null, last_error: null, lag_seconds: 0, last_test: null,
    },
    ...over,
  }
}

describe('notification rules', () => {
  const codes = ['finding.closed', 'device.retired']
  const valid: NotificationInput = { ...emptyInput(), name: 'SIEM', url: 'https://siem.example/hook' }

  it('accepts a valid webhook and requires the URL only on creation', () => {
    expect(validateNotification(valid, false, codes)).toEqual({})
    expect(validateNotification({ ...valid, url: '' }, false, codes).url).toBe('notifications.urlRequired')
    expect(validateNotification({ ...valid, url: '' }, true, codes)).toEqual({})
    expect(validateNotification({ ...valid, url: 'http://x.example' }, false, codes).url).toBe('notifications.urlHttps')
  })

  it('checks name, heartbeat, recipients, interval and custom codes', () => {
    expect(validateNotification({ ...valid, name: '-x' }, false, codes).name).toBe('notifications.nameInvalid')
    expect(validateNotification({ ...valid, heartbeatIntervalS: 30 }, false, codes).heartbeat).toBe('notifications.heartbeatInvalid')
    expect(validateNotification({ ...valid, heartbeatIntervalS: 60 }, false, codes)).toEqual({})
    const mail: NotificationInput = { ...valid, type: 'email', url: '' }
    expect(validateNotification(mail, false, codes).recipients).toBe('notifications.recipientsCount')
    expect(validateNotification({ ...mail, recipients: ['not-an-address'] }, false, codes).recipients).toBe('notifications.recipientsInvalid')
    expect(validateNotification({ ...mail, recipients: ['a@example.org'], emailMinIntervalS: 10 }, false, codes).interval).toBe('notifications.intervalInvalid')
    expect(validateNotification({ ...valid, filterMode: 'custom' }, false, codes).codes).toBe('notifications.codesCount')
    expect(validateNotification({ ...valid, filterMode: 'custom', codes: ['nope'] }, false, codes).codes).toBe('notifications.codesUnknown')
    expect(validateNotification({ ...valid, filterMode: 'custom', codes: ['finding.closed'] }, false, codes)).toEqual({})
  })

  it('maps server problems to fields', () => {
    expect(fieldOfProblem({ code: 'unknown_code' })).toBe('codes')
    expect(fieldOfProblem({ code: 'email_not_configured' })).toBe('type')
    expect(fieldOfProblem({ code: 'already_exists' })).toBe('name')
    expect(fieldOfProblem({ code: 'invalid_request', detail: 'invalid webhook URL: the scheme must be https' })).toBe('url')
    expect(fieldOfProblem({ code: 'invalid_request', detail: 'recipients must hold 1 to 20 plain e-mail addresses' })).toBe('recipients')
    expect(fieldOfProblem({ code: 'invalid_request', detail: 'something else' })).toBeNull()
    expect(fieldOfProblem({ code: 'forbidden' })).toBeNull()
  })

  it('derives state, backlog, lag and recipients', () => {
    expect(stateStatus(destination()).label).toBe('notifications.states.active')
    expect(stateStatus(destination({ enabled: false })).label).toBe('notifications.states.disabled')
    expect(stateStatus(destination({ state: { ...destination().state, status: 'stalled' } })).status).toBe('critical')
    expect(backlogOf(100, destination())).toBe(10)
    expect(backlogOf(50, destination())).toBe(0)
    expect(backlogOf(null, destination())).toBeNull()
    expect(lagParts(59)).toEqual({ unit: 's', value: 59 })
    expect(lagParts(3600)).toEqual({ unit: 'h', value: 1 })
    expect(parseRecipients('a@x.org, b@x.org;\nc@x.org')).toEqual(['a@x.org', 'b@x.org', 'c@x.org'])
  })

  it('polls until a value arrives, and gives up at the timeout', async () => {
    let calls = 0
    expect(await pollUntil(async () => (++calls === 3 ? 'ok' : null), () => false, 1, 1000)).toBe('ok')
    expect(await pollUntil(async () => null, () => false, 5, 20)).toBeNull()
    expect(await pollUntil(async () => 'x', () => true, 1, 1000)).toBeNull()
  })
})

describe('NotificationDestinationForm', () => {
  function mountForm(props: Record<string, unknown> = {}) {
    return mount(NotificationDestinationForm, {
      props: { scope: 'organization', emailAvailable: true, ...props }, global: { plugins: [createPortalI18n(), vuetify] },
      attachTo: document.body,
    })
  }

  it('submits a valid webhook', async () => {
    const w = mountForm()
    await w.find('#notification-name').setValue('SIEM')
    await w.find('#notification-url').setValue('https://siem.example/hook')
    await w.find('form').trigger('submit')
    const sent = w.emitted('submit')?.[0][0] as NotificationInput
    expect(sent).toMatchObject({ type: 'webhook', name: 'SIEM', url: 'https://siem.example/hook', enabled: true, filterMode: 'security' })
    w.unmount()
  })

  it('shows validation errors inline and does not submit', async () => {
    const w = mountForm()
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeUndefined()
    expect(w.text()).toContain('The name must start with a letter or digit')
    expect(w.text()).toContain('Enter the webhook URL.')
    w.unmount()
  })

  it('keeps the URL write-only when editing: empty field, placeholder and the masked address', () => {
    const w = mountForm({ initial: destination() })
    const url = w.find('#notification-url')
    expect((url.element as HTMLInputElement).value).toBe('')
    expect(url.attributes('placeholder')).toBe('unchanged')
    expect(w.text()).toContain('https://siem.example/…')
    w.unmount()
  })

  it('shows the localized message at the field and the server detail on a separate line', () => {
    const w = mountForm({ problem: { code: 'invalid_request', detail: 'invalid webhook URL: the scheme must be https' } })
    expect(w.text()).toContain('The server refused the URL')
    expect(w.find('[data-testid="notification-problem-detail"]').text()).toBe('invalid webhook URL: the scheme must be https')
    w.unmount()
  })

  it('shows a server problem at its field', () => {
    const w = mountForm({ problem: { code: 'invalid_request', detail: 'invalid webhook URL: the port must be 443 or 1024–65535' } })
    expect(w.text()).toContain('invalid webhook URL: the port must be 443')
    expect(w.find('[data-testid="notification-problem"]').exists()).toBe(false)
    w.unmount()
  })

  it('hides the e-mail type without a relay and the pseudonym switch on the platform', () => {
    const none = mountForm({ emailAvailable: false })
    expect(none.find('[data-testid="notification-type-email"]').exists()).toBe(false)
    none.unmount()
    const platform = mountForm({ scope: 'platform' })
    expect(platform.find('[data-testid="notification-pseudonymize"]').exists()).toBe(false)
    platform.unmount()
    const org = mountForm()
    expect(org.find('[data-testid="notification-pseudonymize"]').exists()).toBe(true)
    org.unmount()
  })
})

const created = vi.fn()
const update = vi.fn()
const remove = vi.fn()
const rotate = vi.fn()
const test = vi.fn()
const getOne = vi.fn()
const requestPseudo = vi.fn()
const lookup = vi.fn()
let pseudonymizing: NotificationDestination[] = []
let items: NotificationDestination[] = []
let email = true
vi.mock('../lib/notifications', async (importOriginal) => {
  const original = await importOriginal<typeof import('../lib/notifications')>()
  return {
  ...original,
  destinationLister: () => () => Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort: 'name' }),
  loadEmailCapability: () => Promise.resolve(email),
  loadLatestSeq: () => Promise.resolve(100),
  listPseudonymizing: () => Promise.resolve(pseudonymizing),
  requestPseudonym: (...a: unknown[]) => requestPseudo(...a),
  getPseudonymLookup: (...a: unknown[]) => lookup(...a),
  createDestination: (...a: unknown[]) => created(...a),
  updateDestination: (...a: unknown[]) => update(...a),
  deleteDestination: (...a: unknown[]) => remove(...a),
  rotateSecret: (...a: unknown[]) => rotate(...a),
  requestTest: (...a: unknown[]) => test(...a),
  getDestination: (...a: unknown[]) => getOne(...a),
  pollUntil: (check: () => Promise<unknown>, cancelled: () => boolean) => original.pollUntil(check, cancelled, 1, 1000),
  }
})

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  for (const f of [created, update, remove, rotate, test, getOne, requestPseudo, lookup, assign]) f.mockReset()
  pseudonymizing = []
  items = [destination()]
  email = true
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/settings/notifications', search: '' }, writable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(role: string, platform = false): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'u', username: 'u', display_name: 'U', role, locale: 'en', organization: null } as never
  const path = platform ? '/platform/notifications' : '/settings/notifications'
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path, component: platform ? PlatformNotifications : NotificationDestinations }] })
  await router.push(path)
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

async function click(selector: string): Promise<void> {
  ;(document.querySelector(selector) as HTMLElement).click()
  await flushPromises()
}

describe('notification pages', () => {
  it('lists destinations with state and the masked URL, and offers every action to an administrator', async () => {
    const w = await mountPage('org_admin')
    expect(w.find('h1').text()).toBe('Notifications')
    const list = w.find('[data-testid="notification-list"]')
    expect(list.text()).toContain('SIEM')
    expect(list.text()).toContain('https://siem.example/…')
    expect(w.find('[data-testid="notification-state-SIEM"]').text()).toContain('Active')
    expect(w.find('[data-testid="create-notification"]').exists()).toBe(true)
    expect(w.find('[data-testid="resolve-pseudonym"]').exists()).toBe(true)
    expect(list.text()).toContain('Replace secret')
  })

  it('shows the list to an auditor without any action', async () => {
    const w = await mountPage('org_auditor')
    expect(w.find('[data-testid="notification-list"]').text()).toContain('SIEM')
    expect(w.find('[data-testid="create-notification"]').exists()).toBe(false)
    expect(w.find('[data-testid="resolve-pseudonym"]').exists()).toBe(false)
    expect(w.text()).not.toContain('Send test')
  })

  it('shows the stalled state with its failure class', async () => {
    items = [destination({ state: { ...destination().state, status: 'stalled', last_error: 'http_5xx', lag_seconds: 7200 } })]
    const w = await mountPage('org_admin')
    expect(w.find('[data-testid="notification-state-SIEM"]').text()).toContain('Stalled')
    expect(w.find('[data-testid="notification-last-error"]').text()).toBe('http_5xx')
    expect(w.text()).toContain('2 h')
  })

  it('uses the platform title and no pseudonym dialog on the platform page', async () => {
    const w = await mountPage('platform_admin', true)
    expect(w.find('h1').text()).toBe('Platform notifications')
    expect(w.find('[data-testid="resolve-pseudonym"]').exists()).toBe(false)
    expect(w.find('[data-testid="create-notification"]').exists()).toBe(true)
  })

  it('creates a webhook, shows the secret once and drops it on close', async () => {
    created.mockResolvedValue({ destination: destination({ name: 'New' }), secret: 'whsec_once' })
    await mountPage('org_admin')
    await click('[data-testid="create-notification"]')
    const set = async (sel: string, v: string) => {
      const el = document.querySelector(sel) as HTMLInputElement
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    await set('#notification-name', 'New')
    await set('#notification-url', 'https://siem.example/hook')
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(created).toHaveBeenCalledTimes(1)
    expect((document.querySelector('[data-testid="notification-secret"] input') as HTMLInputElement).value).toBe('whsec_once')
    expect(document.body.textContent).toContain('only time the signing secret of New is shown')
    await click('[data-testid="close-notification-secret"]')
    expect(document.querySelector('[data-testid="notification-secret"]')).toBeNull()
    expect(document.body.textContent).not.toContain('whsec_once')
  })

  it('starts the step-up when the creation is refused and keeps the URL out of the storage', async () => {
    created.mockResolvedValue({ code: 'step_up_required' })
    await mountPage('org_admin')
    await click('[data-testid="create-notification"]')
    const name = document.querySelector('#notification-name') as HTMLInputElement
    name.value = 'New'
    name.dispatchEvent(new Event('input'))
    const url = document.querySelector('#notification-url') as HTMLInputElement
    url.value = 'https://siem.example/token-in-path'
    url.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fnotifications')
    const stored = sessionStorage.getItem('paddock.stepup') ?? ''
    expect(stored).toContain('"hadUrl":true')
    expect(stored).not.toContain('token-in-path')
  })

  it('reopens the form after the step-up and asks for the URL again', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({
      action: 'notification-destination', target: 'organization', at: Date.now(),
      payload: { op: 'create', hadUrl: true, input: { ...emptyInput(), name: 'New' } },
    }))
    await mountPage('org_admin')
    expect(document.querySelector('[data-testid="notification-reenter-url"]')).not.toBeNull()
    expect((document.querySelector('#notification-name') as HTMLInputElement).value).toBe('New')
    expect(created).not.toHaveBeenCalled()
  })

  it('repeats a refused rotation after the step-up and shows the new secret once', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({
      action: 'notification-destination', target: 'organization', at: Date.now(), payload: { op: 'rotate', id: 'd1', name: 'SIEM' },
    }))
    rotate.mockResolvedValue('whsec_new')
    await mountPage('org_admin')
    expect(rotate).toHaveBeenCalledWith('organization', 'd1')
    expect((document.querySelector('[data-testid="notification-secret"] input') as HTMLInputElement).value).toBe('whsec_new')
  })

  it('reports a refused step-up', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({
      action: 'notification-destination', target: 'organization', at: Date.now(), payload: { op: 'rotate', id: 'd1', name: 'SIEM' },
    }))
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign, href: 'https://admin.test/settings/notifications?stepup=failed', search: '?stepup=failed' }, writable: true,
    })
    const w = await mountPage('org_admin')
    expect(rotate).not.toHaveBeenCalled()
    expect(w.find('[data-testid="notification-page-problem"]').text()).toContain('identity confirmation failed')
  })

  it('deletes only after the name is typed in the confirmation', async () => {
    remove.mockResolvedValue(null)
    await mountPage('org_admin')
    await click('[aria-label="Delete: SIEM"]')
    expect(pendingConfirm.value?.options.requireTypedText).toBe('SIEM')
    settleConfirm(false)
    await flushPromises()
    expect(remove).not.toHaveBeenCalled()
    await click('[aria-label="Delete: SIEM"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(remove).toHaveBeenCalledWith('organization', 'd1')
    expect(document.body.textContent).toContain('Notification destination SIEM deleted.')
  })

  it('asks continue or skip with the backlog when enabling a disabled destination', async () => {
    items = [destination({ enabled: false })]
    update.mockResolvedValue(destination())
    await mountPage('org_admin')
    await click('[aria-label="Edit: SIEM"]')
    await click('[data-testid="notification-enabled"] input')
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(update).not.toHaveBeenCalled()
    expect(document.querySelector('[data-testid="notification-cursor-dialog"]')?.textContent).toContain('Deliver the 10 events since it was disabled')
    await click('[data-testid="cursor-skip"] input')
    await click('[data-testid="cursor-accept"]')
    expect(update).toHaveBeenCalledWith('organization', 'd1', expect.objectContaining({ enabled: true }), 'skip')
  })

  it('shows the test result once the notifier recorded it', async () => {
    test.mockResolvedValue(null)
    getOne
      .mockResolvedValueOnce(destination())
      .mockResolvedValueOnce(destination())
      .mockResolvedValue(destination({ state: { ...destination().state, last_test: { at: '2026-10-31T10:00:00Z', ok: false, error: 'http_5xx' } } }))
    await mountPage('org_admin')
    await click('[aria-label="Send test: SIEM"]')
    expect(pendingConfirm.value?.options.title).toBe('Send a test notification')
    settleConfirm({ reason: '' })
    await vi.waitFor(() => {
      expect(test).toHaveBeenCalledWith('organization', 'd1')
      expect(document.querySelector('[data-testid="notification-test-result"]')?.textContent).toContain('failed: http_5xx')
    }, { timeout: 5000 })
  })

  it('shows a specific message when a test is still pending', async () => {
    test.mockResolvedValue({ code: 'invalid_state' })
    getOne.mockResolvedValue(destination())
    const w = await mountPage('org_admin')
    await click('[aria-label="Send test: SIEM"]')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[data-testid="notification-page-problem"]').text()).toContain('earlier test of this destination is still waiting')
  })
})

describe('pseudonym dialog', () => {
  const pseudonym = 'u_0123456789abcdef01234567'

  async function openDialog(): Promise<void> {
    pseudonymizing = [destination({ pseudonymize_users: true })]
    await mountPage('org_admin')
    await click('[data-testid="resolve-pseudonym"]')
  }

  async function submitPseudonym(value: string): Promise<void> {
    const el = document.querySelector('#notification-pseudonym') as HTMLInputElement
    el.value = value
    el.dispatchEvent(new Event('input'))
    await flushPromises()
    await click('[data-testid="pseudonym-submit"]')
    await new Promise((r) => setTimeout(r, 30))
    await flushPromises()
  }

  it('says there is nothing to resolve without a pseudonymizing destination', async () => {
    await mountPage('org_admin')
    await click('[data-testid="resolve-pseudonym"]')
    expect(document.querySelector('[data-testid="pseudonym-none"]')).not.toBeNull()
  })

  it('refuses a malformed pseudonym without a request', async () => {
    await openDialog()
    await submitPseudonym('u_nothex')
    expect(requestPseudo).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter u_ followed by 24 lowercase hexadecimal characters.')
  })

  it('shows the user name once the notifier resolved the lookup', async () => {
    requestPseudo.mockResolvedValue('l1')
    lookup.mockResolvedValueOnce({ resolved: false, username: '' }).mockResolvedValue({ resolved: true, username: 'bob' })
    await openDialog()
    await submitPseudonym(pseudonym)
    expect(requestPseudo).toHaveBeenCalledWith('d1', pseudonym)
    expect(document.querySelector('[data-testid="pseudonym-result"]')?.textContent).toContain('stands for bob')
  })

  it('shows that no user matches', async () => {
    requestPseudo.mockResolvedValue('l1')
    lookup.mockResolvedValue({ resolved: true, username: '' })
    await openDialog()
    await submitPseudonym(pseudonym)
    expect(document.querySelector('[data-testid="pseudonym-result"]')?.textContent).toContain('No user matches')
  })

  it('names a pending lookup when the server answers invalid_state', async () => {
    requestPseudo.mockResolvedValue({ code: 'invalid_state' })
    await openDialog()
    await submitPseudonym(pseudonym)
    expect(document.body.textContent).toContain('Another pseudonym lookup of this organization is still pending')
  })

  it('starts the step-up without keeping anything secret and resumes it on return', async () => {
    requestPseudo.mockResolvedValue({ code: 'step_up_required' })
    await openDialog()
    await submitPseudonym(pseudonym)
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fnotifications')
    const stored = JSON.parse(sessionStorage.getItem('paddock.stepup') ?? '{}') as { action: string; target: string }
    expect(stored).toMatchObject({ action: 'notification-resolve', target: 'organization' })
    wrapper?.unmount()
    wrapper = null
    document.body.innerHTML = ''

    requestPseudo.mockReset()
    requestPseudo.mockResolvedValue('l1')
    lookup.mockResolvedValue({ resolved: true, username: 'bob' })
    pseudonymizing = [destination({ pseudonymize_users: true })]
    await mountPage('org_admin')
    await new Promise((r) => setTimeout(r, 30))
    await flushPromises()
    expect(requestPseudo).toHaveBeenCalledTimes(1)
    expect(requestPseudo).toHaveBeenCalledWith('d1', pseudonym)
    expect(document.querySelector('[data-testid="pseudonym-result"]')?.textContent).toContain('stands for bob')
    expect(sessionStorage.getItem('paddock.stepup')).toBeNull()
  })

  it('does not fire a stored lookup when the dialog is opened later', async () => {
    requestPseudo.mockResolvedValue('l1')
    sessionStorage.setItem('paddock.stepup', JSON.stringify({
      action: 'notification-resolve', target: 'organization', at: Date.now(), payload: { id: 'd1', pseudonym },
    }))
    pseudonymizing = [destination({ pseudonymize_users: true })]
    lookup.mockResolvedValue({ resolved: true, username: 'bob' })
    await mountPage('org_admin')
    await new Promise((r) => setTimeout(r, 30))
    await flushPromises()
    expect(requestPseudo).toHaveBeenCalledTimes(1)
    expect(sessionStorage.getItem('paddock.stepup')).toBeNull()
  })

  it('reports a refused step-up in the dialog', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({
      action: 'notification-resolve', target: 'organization', at: Date.now(), payload: { id: 'd1', pseudonym },
    }))
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign, href: 'https://admin.test/settings/notifications?stepup=failed', search: '?stepup=failed' }, writable: true,
    })
    pseudonymizing = [destination({ pseudonymize_users: true })]
    await mountPage('org_admin')
    expect(requestPseudo).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('identity confirmation failed')
  })
})

describe('notification page accessibility and keyboard', () => {
  it('names every row button starting with its visible text (WCAG 2.5.3)', async () => {
    const w = await mountPage('org_admin')
    const buttons = w.findAll('[data-testid="notification-list"] td button, [data-testid="notification-list"] .form-actions button')
    expect(buttons.length).toBeGreaterThanOrEqual(4)
    for (const b of buttons) {
      expect(b.attributes('aria-label')?.startsWith(b.text()), b.text()).toBe(true)
    }
  })

  it('keeps the row button labels led by the visible text in both catalogs', () => {
    for (const c of [de, en]) {
      const n = c.notifications
      expect(n.editLabel.startsWith(c.common.edit)).toBe(true)
      expect(n.deleteLabel.startsWith(c.common.delete)).toBe(true)
      expect(n.testLabel.startsWith(n.test)).toBe(true)
      expect(n.rotateLabel.startsWith(n.rotate)).toBe(true)
    }
  })

  it('closes the form dialog and the secret dialog with Escape while focus is on the overlay content', async () => {
    created.mockResolvedValue({ destination: destination({ name: 'New' }), secret: 'whsec_once' })
    await mountPage('org_admin')
    await click('[data-testid="create-notification"]')
    const esc = async () => {
      const content = [...document.querySelectorAll('.v-overlay__content')].at(-1) as HTMLElement
      content.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
      await flushPromises()
    }
    expect(document.querySelector('[data-testid="notification-form"]')).not.toBeNull()
    await esc()
    expect(document.querySelector('[data-testid="notification-form"]')).toBeNull()

    await click('[data-testid="create-notification"]')
    for (const [sel, v] of [['#notification-name', 'New'], ['#notification-url', 'https://siem.example/hook']]) {
      const el = document.querySelector(sel) as HTMLInputElement
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    await flushPromises()
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(document.querySelector('[data-testid="notification-secret"]')).not.toBeNull()
    await esc()
    expect(document.querySelector('[data-testid="notification-secret"]')).toBeNull()
  })

  it('gives the list a focusable fallback target', async () => {
    const w = await mountPage('org_admin')
    expect(w.find('[data-testid="notification-list"]').attributes('tabindex')).toBe('-1')
  })
})
