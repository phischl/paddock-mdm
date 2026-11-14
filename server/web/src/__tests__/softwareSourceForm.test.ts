import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import SoftwareSourceForm from '../components/SoftwareSourceForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import type { SourceInput } from '../lib/software'

const save = vi.fn<(id: string | null, input: SourceInput, keyChanged?: boolean) => Promise<string | null>>()
vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  saveSoftwareSource: (id: string | null, input: SourceInput, keyChanged?: boolean) => save(id, input, keyChanged),
}))

const key = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBF\n-----END PGP PUBLIC KEY BLOCK-----'
const fingerprint = 'ABCD'.repeat(10)

beforeEach(() => save.mockReset())

function mountForm(props: Record<string, unknown> = {}) {
  return mount(SoftwareSourceForm, { props, global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body })
}

async function fill(w: ReturnType<typeof mountForm>, uri = 'https://repo.example.com/apt'): Promise<void> {
  await w.find('#source-name').setValue('Vendor')
  await w.find('#source-slug').setValue('vendor')
  await w.find('#source-uris').setValue(uri)
  await w.find('#source-suites').setValue('stable')
  await w.find('#source-components').setValue('main')
  await w.find('#source-key').setValue(key)
  await w.find('#source-fingerprint').setValue(fingerprint)
}

describe('SoftwareSourceForm', () => {
  it('refuses http before any request and says why', async () => {
    const w = mountForm()
    await fill(w, 'http://repo.example.com/apt')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('Sources must use https.')
    expect(save).not.toHaveBeenCalled()
  })

  it('normalizes the typed fingerprint to uppercase blocks of four when the field is left', async () => {
    const w = mountForm()
    await w.find('#source-fingerprint').setValue('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')
    await w.find('#source-fingerprint').trigger('blur')
    expect((w.find('#source-fingerprint').element as HTMLInputElement).value).toBe('ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD ABCD')
  })

  it('sends a valid source and reports it saved', async () => {
    save.mockResolvedValue(null)
    const w = mountForm()
    await fill(w)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(save).toHaveBeenCalledTimes(1)
    expect(save.mock.calls[0][1]).toMatchObject({ uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'] })
    expect(w.emitted('saved')).toHaveLength(1)
  })

  it('rejects a fingerprint that is not 40 hexadecimal characters', async () => {
    const w = mountForm()
    await fill(w)
    await w.find('#source-fingerprint').setValue('1234')
    await w.find('form').trigger('submit')
    expect(w.text()).toContain('Enter the 40 hexadecimal characters')
    expect(save).not.toHaveBeenCalled()
  })

  it('hands a step_up_required refusal to the page to resume instead of showing an error', async () => {
    save.mockResolvedValue('step_up_required')
    const w = mountForm()
    await fill(w)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.emitted('step-up')).toHaveLength(1)
    expect((w.emitted('step-up') as [SourceInput][])[0][0]).toMatchObject({ slug: 'vendor', name: 'Vendor' })
    expect(w.emitted('saved')).toBeUndefined()
    expect(w.find('.form-error').exists()).toBe(false)
  })

  it('shows fingerprint_mismatch under the fingerprint field', async () => {
    save.mockResolvedValue('fingerprint_mismatch')
    const w = mountForm()
    await fill(w)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain("The key's fingerprint does not match the one you entered.")
  })

  it('sends a changed source without the key unless the key or fingerprint changed', async () => {
    save.mockResolvedValue(null)
    const initial = {
      id: 's1', slug: 'vendor', name: 'Vendor', uris: ['https://repo.example.com/apt'], suites: ['stable'], components: ['main'],
      architectures: [], fingerprint, weak_key: false, entry_count: 0, signing_key: key, created_at: '', updated_at: '',
    }
    const w = mountForm({ initial })
    await w.find('#source-name').setValue('Vendor 2')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(save).toHaveBeenCalledWith('s1', expect.objectContaining({ name: 'Vendor 2' }), false)
  })
})

describe('SoftwareSourceForm, Flatpak remote (plan M13b decision 5)', () => {
  async function fillRemote(w: ReturnType<typeof mountForm>, uris: string): Promise<void> {
    await w.findComponent({ name: 'VSelect' }).setValue('flatpak')
    await w.find('#source-name').setValue('Flathub')
    await w.find('#source-slug').setValue('flathub')
    await w.find('#source-uris').setValue(uris)
    await w.find('#source-key').setValue(key)
    await w.find('#source-fingerprint').setValue(fingerprint)
  }

  it('shows suites, components and architectures for an APT repository only', async () => {
    const w = mountForm()
    expect(w.find('#source-suites').exists()).toBe(true)
    expect(w.text()).toContain('Architectures')
    await w.findComponent({ name: 'VSelect' }).setValue('flatpak')
    expect(w.find('#source-suites').exists()).toBe(false)
    expect(w.find('#source-components').exists()).toBe(false)
    expect(w.text()).not.toContain('Architectures')
    expect(w.text()).toContain('The https URL of the Flatpak remote')
  })

  it('requires exactly one https URL and the key before it sends anything', async () => {
    const w = mountForm()
    await fillRemote(w, 'https://a.example.org/repo/\nhttps://b.example.org/repo/')
    await w.find('#source-key').setValue('')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(save).not.toHaveBeenCalled()
    expect(w.text()).toContain('Enter exactly one https address, the URL of the Flatpak remote.')
    expect(w.text()).toContain('Paste one OpenPGP public key of at most 64 KiB.')
  })

  it('sends a valid remote as kind flatpak', async () => {
    save.mockResolvedValue(null)
    const w = mountForm()
    await fillRemote(w, 'https://dl.flathub.org/repo/')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(save).toHaveBeenCalledTimes(1)
    expect(save.mock.calls[0][1]).toMatchObject({ kind: 'flatpak', slug: 'flathub', uris: ['https://dl.flathub.org/repo/'] })
    expect(w.emitted('saved')).toHaveLength(1)
  })

  it('keeps the kind of a stored source fixed', () => {
    const w = mountForm({
      initial: {
        id: 's1', kind: 'flatpak', slug: 'flathub', name: 'Flathub', uris: ['https://dl.flathub.org/repo/'], suites: [], components: [],
        architectures: [], fingerprint, weak_key: false, entry_count: 0, signing_key: key, created_at: '', updated_at: '',
      },
    })
    expect((w.find('#source-kind').element as HTMLInputElement).disabled).toBe(true)
    expect(w.find('#source-suites').exists()).toBe(false)
  })
})
