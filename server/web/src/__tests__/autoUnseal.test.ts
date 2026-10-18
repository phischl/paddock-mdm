import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h, nextTick } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { VApp } from 'vuetify/components'
import AutoUnsealDisclaimerDialog from '../components/AutoUnsealDisclaimerDialog.vue'
import PlatformOpenBao from '../views/PlatformOpenBao.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import type { AutoUnsealAcknowledgement, AutoUnsealStatus } from '../lib/autoUnseal'
import { vuetify } from '../plugins/vuetify'
import en from '../locales/en.json'
import de from '../locales/de.json'

function statusOf(over: Partial<AutoUnsealStatus> = {}, unsealer: Partial<AutoUnsealStatus['unsealer']> = {}): AutoUnsealStatus {
  return {
    state: 'disabled',
    disclaimer_version: '2026-10-17',
    acknowledgement_version: null,
    acknowledgement: null,
    acknowledged_by: null,
    acknowledged_at: null,
    disabled_by: null,
    disabled_at: null,
    seal: { reachable: true, initialized: true, sealed: false, type: 'shamir', threshold: 3, shares: 5 },
    ...over,
    unsealer: {
      running: false,
      seen_at: null,
      shares_present: false,
      unseal_count: 0,
      last_unseal_at: null,
      failure_count: 0,
      last_failure_at: null,
      last_failure_reason: null,
      ...unsealer,
    },
  }
}

let current: AutoUnsealStatus = statusOf()
let enableAnswer: AutoUnsealStatus | string = statusOf()
let disableAnswer: AutoUnsealStatus | string = statusOf()
const enabled: AutoUnsealAcknowledgement[] = []
let disables = 0
let loads = 0
vi.mock('../lib/autoUnseal', async (original) => ({
  ...(await original<typeof import('../lib/autoUnseal')>()),
  getAutoUnseal: () => {
    loads++
    return Promise.resolve(current)
  },
  enableAutoUnseal: (input: AutoUnsealAcknowledgement) => {
    enabled.push(input)
    return Promise.resolve(enableAnswer)
  },
  disableAutoUnseal: () => {
    disables++
    return Promise.resolve(disableAnswer)
  },
}))

const started: { action: string; target: string; payload: unknown }[] = []
let resumed: { action: string; result: unknown } | null = null
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string, target: string, payload: unknown = null) => started.push({ action, target, payload }),
  resumeStepUp: (action: string) => {
    if (!resumed || resumed.action !== action) return null
    const r = resumed.result
    resumed = null
    return r
  },
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  current = statusOf()
  enableAnswer = statusOf()
  disableAnswer = statusOf()
  enabled.length = 0
  started.length = 0
  disables = 0
  loads = 0
  resumed = null
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
})

// Dialogs are teleported to the body.
const el = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)

async function type(text: string): Promise<void> {
  const input = el('auto-unseal-typed')?.querySelector('input') as HTMLInputElement
  input.value = text
  input.dispatchEvent(new Event('input'))
  await nextTick()
}

const accept = () => el('auto-unseal-accept') as HTMLButtonElement

describe('AutoUnsealDisclaimerDialog (plan M8u decision 23)', () => {
  function mountDialog(locale: 'en' | 'de' = 'en') {
    const i18n = createPortalI18n()
    i18n.global.locale.value = locale
    wrapper = mount(AutoUnsealDisclaimerDialog, {
      props: { modelValue: true, version: '2026-10-17' },
      global: { plugins: [i18n, vuetify] },
      attachTo: document.body,
    })
    return wrapper
  }

  it('renders the disclaimer with the four risks as a numbered list and the version', async () => {
    mountDialog()
    await flushPromises()
    const text = el('auto-unseal-disclaimer')?.textContent ?? ''
    for (const key of ['title', 'intro', 'lead'] as const) expect(text).toContain(en.openbao.disclaimer[key])
    const risks = el('auto-unseal-risks')
    expect(risks?.tagName).toBe('OL')
    expect([...(risks?.querySelectorAll('li') ?? [])].map((li) => li.textContent?.trim())).toEqual([
      en.openbao.disclaimer.risk1,
      en.openbao.disclaimer.risk2,
      en.openbao.disclaimer.risk3,
      en.openbao.disclaimer.risk4,
    ])
    expect(text).toContain(en.openbao.disclaimer.outro.replace('{version}', '2026-10-17'))
    expect(text).toContain('Type the sentence to confirm: I understand and accept the risk')
    expect(document.activeElement).toBe(el('auto-unseal-cancel'))
  })

  it('enables the button only for the exact English sentence', async () => {
    const w = mountDialog()
    await flushPromises()
    expect(accept().disabled).toBe(true)
    for (const wrong of ['I understand and accept the risk ', 'i understand and accept the risk', 'Ich verstehe und akzeptiere das Risiko']) {
      await type(wrong)
      expect(accept().disabled).toBe(true)
    }
    await type('I understand and accept the risk')
    expect(accept().disabled).toBe(false)
    const input = el('auto-unseal-typed')?.querySelector('input') as HTMLInputElement
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(w.emitted('confirm')).toBeUndefined()
    accept().click()
    expect(w.emitted('confirm')).toEqual([[{ disclaimer_version: '2026-10-17', acknowledgement: 'I understand and accept the risk' }]])
  })

  it('accepts only the German sentence in German and renders the German risks', async () => {
    const w = mountDialog('de')
    await flushPromises()
    const text = el('auto-unseal-disclaimer')?.textContent ?? ''
    for (const key of ['risk1', 'risk2', 'risk3', 'risk4'] as const) expect(text).toContain(de.openbao.disclaimer[key])
    await type('I understand and accept the risk')
    expect(accept().disabled).toBe(true)
    await type('Ich verstehe und akzeptiere das Risiko')
    expect(accept().disabled).toBe(false)
    accept().click()
    expect(w.emitted('confirm')).toEqual([[{ disclaimer_version: '2026-10-17', acknowledgement: 'Ich verstehe und akzeptiere das Risiko' }]])
  })

  it('cancels on Esc', async () => {
    const w = mountDialog()
    await flushPromises()
    el('auto-unseal-disclaimer')?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(w.emitted('cancel')).toHaveLength(1)
    expect(w.emitted('confirm')).toBeUndefined()
  })
})

describe('PlatformOpenBao (plan M8u decisions 21–23)', () => {
  async function mountView(): Promise<VueWrapper> {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/platform/openbao', component: { render: () => null } }] })
    await router.push('/platform/openbao')
    wrapper = mount(() => h(VApp, null, { default: () => h(PlatformOpenBao) }),
      { global: { plugins: [createPortalI18n(), vuetify, router] }, attachTo: document.body })
    await flushPromises()
    return wrapper
  }

  it('shows the seal, the setting off and the unsealer without an alert', async () => {
    const w = await mountView()
    expect(w.find('[data-testid="openbao-seal"]').text()).toContain('Unsealed')
    expect(w.find('[data-testid="openbao-seal"]').text()).toContain('3 of 5 shares unseal it (shamir)')
    expect(w.find('[data-testid="openbao-setting"]').text()).toContain('Off')
    expect(w.find('[data-testid="openbao-unsealer"]').text()).toContain('Not running')
    expect(w.find('[data-testid="openbao-unsealer"]').text()).toContain('No automatic unseal yet')
    expect(w.find('[data-testid^="openbao-alert"]').exists()).toBe(false)
  })

  it('shows sealed and unreachable', async () => {
    current = statusOf({ seal: { reachable: true, initialized: true, sealed: true, type: 'shamir', threshold: 3, shares: 5 } })
    let w = await mountView()
    expect(w.find('[data-testid="openbao-seal"]').text()).toContain('Sealed')
    wrapper?.unmount()
    current = statusOf({ seal: { reachable: false, initialized: false, sealed: false, type: '', threshold: 0, shares: 0 } })
    w = await mountView()
    expect(w.find('[data-testid="openbao-seal"]').text()).toContain('OpenBao is not reachable')
  })

  it('warns when the shares are left on the host after disabling', async () => {
    current = statusOf({ state: 'disabled' }, { running: true, shares_present: true, seen_at: '2026-10-17T10:00:00Z' })
    const w = await mountView()
    expect(w.find('[data-testid="openbao-alert-sharesLeft"]').text()).toBe(en.openbao.alerts.sharesLeft)
    expect(w.find('[data-testid="openbao-unsealer"]').text()).toContain('Running, shares present')
  })

  it('tells the host step while the unsealer does not run, and the outdated acknowledgement', async () => {
    current = statusOf({
      state: 'enabled', acknowledgement_version: '2026-01-01', acknowledgement: 'I understand and accept the risk',
      acknowledged_by: 'Root Admin', acknowledged_at: '2026-10-17T09:30:00Z',
    }, {
      last_unseal_at: '2026-10-17T09:40:00Z', unseal_count: 4, last_failure_at: '2026-10-17T09:35:00Z',
      last_failure_reason: 'invalid_share', failure_count: 1,
    })
    const w = await mountView()
    expect(w.find('[data-testid="openbao-alert-hostStep"]').text()).toBe(en.openbao.alerts.hostStep)
    const setting = w.find('[data-testid="openbao-setting"]').text()
    expect(setting).toContain('On — acknowledged by Root Admin on ')
    expect(setting).toContain('disclaimer 2026-01-01')
    expect(w.find('[data-testid="openbao-outdated"]').text()).toBe(en.openbao.setting.outdated)
    const unsealer = w.find('[data-testid="openbao-unsealer"]').text()
    expect(unsealer).toContain('(4 in total)')
    expect(unsealer).toContain(': a share was refused')
  })

  it('shows no alert while enabled and the unsealer runs with shares', async () => {
    current = statusOf({ state: 'enabled', acknowledgement_version: '2026-10-17', acknowledged_by: 'Root', acknowledged_at: '2026-10-17T09:30:00Z' },
      { running: true, shares_present: true })
    const w = await mountView()
    expect(w.find('[data-testid^="openbao-alert"]').exists()).toBe(false)
    expect(w.find('[data-testid="openbao-outdated"]').exists()).toBe(false)
  })

  it('enables through the disclaimer and keeps the input across the step-up', async () => {
    enableAnswer = 'step_up_required'
    const w = await mountView()
    await w.find('[data-testid="openbao-enable"]').trigger('click')
    await flushPromises()
    await type('I understand and accept the risk')
    accept().click()
    await flushPromises()
    const input = { disclaimer_version: '2026-10-17', acknowledgement: 'I understand and accept the risk' }
    expect(enabled).toEqual([input])
    expect(started).toEqual([{ action: 'auto-unseal-enable', target: 'setting', payload: input }])
  })

  it('resends the stored input after the step-up without asking again', async () => {
    const input = { disclaimer_version: '2026-10-17', acknowledgement: 'Ich verstehe und akzeptiere das Risiko' }
    resumed = { action: 'auto-unseal-enable', result: { failed: false, payload: input } }
    enableAnswer = statusOf({ state: 'enabled', acknowledgement_version: '2026-10-17', acknowledged_by: 'Root Admin', acknowledged_at: '2026-10-17T09:30:00Z' },
      { running: false })
    const w = await mountView()
    await vi.waitFor(() => expect(enabled).toEqual([input]))
    await flushPromises()
    expect(started).toEqual([])
    expect(el('auto-unseal-disclaimer')).toBeNull()
    expect(w.find('[data-testid="openbao-setting"]').text()).toContain('On — acknowledged by Root Admin')
  })

  it('shows a failed step-up inline', async () => {
    resumed = { action: 'auto-unseal-disable', result: { failed: true } }
    const w = await mountView()
    await vi.waitFor(() => expect(w.find('[data-testid="openbao-problem"]').text()).toBe(en.problems.step_up_failed))
    expect(disables).toBe(0)
  })

  it('shows a stale disclaimer inline and reloads the status', async () => {
    enableAnswer = 'disclaimer_outdated'
    const w = await mountView()
    expect(loads).toBe(1)
    await w.find('[data-testid="openbao-enable"]').trigger('click')
    await flushPromises()
    await type('I understand and accept the risk')
    accept().click()
    await flushPromises()
    expect(w.find('[data-testid="openbao-problem"]').text()).toBe(en.problems.disclaimer_outdated)
    expect(loads).toBe(2)
    expect(started).toEqual([])
  })

  it('disables after a plain confirmation and handles the step-up', async () => {
    current = statusOf({ state: 'enabled', acknowledgement_version: '2026-10-17', acknowledged_by: 'Root', acknowledged_at: '2026-10-17T09:30:00Z' },
      { running: true, shares_present: true })
    disableAnswer = 'step_up_required'
    const w = await mountView()
    await w.find('[data-testid="openbao-disable"]').trigger('click')
    expect(pendingConfirm.value?.options).toMatchObject({
      title: en.openbao.disableConfirmTitle,
      message: en.openbao.disableConfirmMessage,
      confirmLabel: en.openbao.disable,
      destructive: false,
    })
    expect(pendingConfirm.value?.options.requireTypedText).toBeUndefined()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(disables).toBe(1)
    expect(started).toEqual([{ action: 'auto-unseal-disable', target: 'setting', payload: null }])

    disableAnswer = statusOf({ state: 'disabled', disabled_by: 'Root', disabled_at: '2026-10-17T10:00:00Z' }, { running: true, shares_present: true })
    await w.find('[data-testid="openbao-disable"]').trigger('click')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[data-testid="openbao-setting"]').text()).toContain('Off')
    expect(w.find('[data-testid="openbao-alert-sharesLeft"]').exists()).toBe(true)
  })
})
