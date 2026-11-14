import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import RecoveryExport from '../components/RecoveryExport.vue'
import type { RecoveryExportRequest } from '../api/client'
import type { HeaderFile } from '../lib/disk'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { exportFileName, passphraseStrength, validateExport } from '../lib/recoveryExport'

const exportRecoveryKeys = vi.fn<(org: string | null, body: RecoveryExportRequest) => Promise<HeaderFile | string>>()
const saveFile = vi.fn()
vi.mock('../lib/recoveryExport', async (original) => ({
  ...(await original<typeof import('../lib/recoveryExport')>()),
  exportRecoveryKeys: (org: string | null, body: RecoveryExportRequest) => exportRecoveryKeys(org, body),
}))
vi.mock('../lib/disk', async (original) => ({
  ...(await original<typeof import('../lib/disk')>()),
  saveFile: (f: HeaderFile) => saveFile(f),
}))

const passphrase = 'Correct-Horse-Battery-42'
let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  exportRecoveryKeys.mockReset()
  saveFile.mockReset()
  assign.mockReset()
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/overview', search: '' }, writable: true, configurable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountExport(organizationId: string | null): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/overview', component: () => h(RecoveryExport, { organizationId, slug: 'acme' }) }],
  })
  await router.push('/overview')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
}

function resumed(target: string): void {
  sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'recovery-export', target, at: Date.now(), payload: null }))
}

function input(id: string, value: string): void {
  const el = document.getElementById(id) as HTMLInputElement
  el.value = value
  el.dispatchEvent(new Event('input'))
}

/** Switches the dialog from the preselected public key to a passphrase. */
async function choosePassphrase(): Promise<void> {
  document.querySelector<HTMLInputElement>('[data-testid="recovery-export-passphrase-option"] input')!.click()
  await flushPromises()
}

async function submit(): Promise<void> {
  document.querySelector<HTMLElement>('[data-testid="recovery-export-submit"]')!.click()
  await flushPromises()
}

describe('recovery export rules', () => {
  it('rates passphrases and refuses those under 20 characters', () => {
    expect(passphraseStrength('x'.repeat(19))).toBe('short')
    expect(passphraseStrength('ä'.repeat(20))).toBe('fair')
    expect(passphraseStrength(passphrase)).toBe('strong')
    expect(validateExport({ recipient: 'passphrase', passphrase: 'x'.repeat(19) }, 'x'.repeat(19))).toBe('recoveryExport.errors.length')
    expect(validateExport({ recipient: 'passphrase', passphrase: 'x'.repeat(20) }, 'x'.repeat(20))).toBe('')
    expect(validateExport({ recipient: 'passphrase', passphrase }, passphrase + 'x')).toBe('recoveryExport.errors.mismatch')
    expect(validateExport({ recipient: 'passphrase', passphrase }, passphrase)).toBe('')
    expect(validateExport({ recipient: 'public_key', public_key: 'ssh-ed25519 AAAA' }, '')).toBe('recoveryExport.errors.publicKey')
    expect(validateExport({ recipient: 'public_key', public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n...' }, '')).toBe('')
  })

  it('takes the file name from the Content-Disposition header', () => {
    expect(exportFileName('attachment; filename=paddock-recovery-acme-20261114T120000Z.asc')).toBe('paddock-recovery-acme-20261114T120000Z.asc')
    expect(exportFileName(null)).toBe('paddock-recovery.asc')
  })
})

describe('RecoveryExport', () => {
  it('starts with a step-up and never stores a passphrase', async () => {
    await mountExport(null)
    document.querySelector<HTMLElement>('[data-testid="recovery-export-acme"]')!.click()
    expect(assign).toHaveBeenCalledWith(expect.stringContaining('/api/auth/stepup'))
    expect(JSON.parse(sessionStorage.getItem('paddock.stepup')!)).toMatchObject({ action: 'recovery-export', target: 'own', payload: null })
  })

  it('opens after the step-up, warns about the last copy and downloads with a matching passphrase', async () => {
    resumed('own')
    await mountExport(null)
    expect(document.body.textContent).toContain('only remaining copy')
    expect(document.querySelector<HTMLInputElement>('[data-testid="recovery-export-public-key"] input')!.checked).toBe(true)
    expect(document.getElementById('recovery-export-key')).not.toBeNull()
    await choosePassphrase()
    expect(document.querySelector('[data-testid="recovery-export-passphrase-note"]')?.textContent).toContain('at least 20 characters')
    input('recovery-export-passphrase', passphrase)
    input('recovery-export-repeat', 'something else entirely')
    await submit()
    expect(exportRecoveryKeys).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('The passphrases do not match.')

    exportRecoveryKeys.mockResolvedValueOnce({ blob: new Blob(['x']), filename: 'paddock-recovery-acme.asc' })
    input('recovery-export-repeat', passphrase)
    await submit()
    expect(exportRecoveryKeys).toHaveBeenCalledWith(null, { recipient: 'passphrase', passphrase })
    expect(saveFile).toHaveBeenCalledTimes(1)
    expect(document.body.textContent).toContain('The encrypted file was downloaded.')
    expect(JSON.stringify(sessionStorage)).not.toContain(passphrase)
  })

  it('exports another organization for a platform administrator and shows the export limit', async () => {
    resumed('o1')
    await mountExport('o1')
    await choosePassphrase()
    input('recovery-export-passphrase', passphrase)
    input('recovery-export-repeat', passphrase)
    exportRecoveryKeys.mockResolvedValueOnce('export_limit')
    await submit()
    expect(exportRecoveryKeys).toHaveBeenCalledWith('o1', { recipient: 'passphrase', passphrase })
    expect(saveFile).not.toHaveBeenCalled()
    const alerts = [...document.querySelectorAll('[role="alert"]')].map((a) => a.textContent)
    expect(alerts.some((a) => a?.includes('five times'))).toBe(true)
  })

  it('shows a failed step-up', async () => {
    resumed('own')
    window.location.search = '?stepup=failed'
    await mountExport(null)
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('identity confirmation failed')
  })
})
