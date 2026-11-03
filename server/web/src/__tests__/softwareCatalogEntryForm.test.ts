import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SoftwareCatalogEntryForm from '../components/SoftwareCatalogEntryForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

function mountForm() {
  return mount(SoftwareCatalogEntryForm, {
    props: { sources: [{ id: 's1', name: 'Vendor' }] },
    global: { plugins: [createPortalI18n(), vuetify] },
    attachTo: document.body,
  })
}

describe('SoftwareCatalogEntryForm', () => {
  it('creates an entry with two package rows', async () => {
    const w = mountForm()
    await w.find('#entry-name').setValue('Editor')
    await w.find('[data-testid="package-name-0"] input').setValue('nano')
    await w.find('[data-testid="add-package-row"]').trigger('click')
    expect(w.findAll('[data-testid="package-row"]')).toHaveLength(2)
    await w.find('[data-testid="package-release-1"] input').setValue('24.04')
    await w.find('[data-testid="package-name-1"] input').setValue('vim')
    await w.find('form').trigger('submit')
    const input = (w.emitted('submit') as unknown[][])[0][0] as { name: string; packages: { release: string; package: string }[] }
    expect(input.name).toBe('Editor')
    expect(input.packages.map((p) => [p.release, p.package])).toEqual([['*', 'nano'], ['24.04', 'vim']])
  })

  it('refuses two rows with the same distribution, release and architecture', async () => {
    const w = mountForm()
    await w.find('#entry-name').setValue('Editor')
    await w.find('[data-testid="package-name-0"] input').setValue('nano')
    await w.find('[data-testid="add-package-row"]').trigger('click')
    await w.find('[data-testid="package-name-1"] input').setValue('vim')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeUndefined()
    expect(w.text()).toContain('Each combination of distribution, release and architecture may appear once.')
  })

  it('refuses an invalid package name before any request', async () => {
    const w = mountForm()
    await w.find('#entry-name').setValue('Editor')
    await w.find('[data-testid="package-name-0"] input').setValue('Not A Package')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeUndefined()
    expect(w.text()).toContain('Enter a Debian package name')
  })
})
