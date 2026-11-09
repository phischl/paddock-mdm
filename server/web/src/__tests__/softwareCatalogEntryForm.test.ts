import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SoftwareCatalogEntryForm from '../components/SoftwareCatalogEntryForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

function mountForm(initial: Record<string, unknown> | null = null) {
  return mount(SoftwareCatalogEntryForm, {
    props: { sources: [{ id: 's1', name: 'Vendor', kind: 'apt' }, { id: 's2', name: 'Flathub', kind: 'flatpak' }], initial: initial as never },
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

  it('edits Flatpak application IDs and their scope for a Flatpak source (plan M13b decision 3)', async () => {
    const w = mountForm({
      id: 'e1', name: 'GIMP', description: '', category: '', source_id: 's2', source_slug: 'flathub', has_icon: false, assignment_count: 0,
      created_at: '', updated_at: '', packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', flatpak_ref: 'org.gimp.GIMP', scope: 'user' }],
    })
    expect(w.find('[data-testid="package-name-0"]').exists()).toBe(false)
    expect(w.find('[data-testid="package-flatpak-ref-0"]').text()).toContain('Flatpak application ID')
    expect(w.find('[data-testid="package-scope-0"]').text()).toContain('User')
    await w.find('form').trigger('submit')
    const input = (w.emitted('submit') as unknown[][])[0][0] as { packages: unknown[] }
    expect(input.packages).toEqual([{ distribution: 'ubuntu', release: '*', architecture: '*', flatpak_ref: 'org.gimp.GIMP', scope: 'user' }])

    await w.find('[data-testid="package-flatpak-ref-0"] input').setValue('gimp')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toHaveLength(1)
    expect(w.text()).toContain('Enter a Flatpak application ID of at least three parts')
  })

  it('adds a Flatpak row in system scope for a Flatpak source', async () => {
    const w = mountForm({
      id: 'e1', name: 'GIMP', description: '', category: '', source_id: 's2', source_slug: 'flathub', has_icon: false, assignment_count: 0,
      created_at: '', updated_at: '', packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', flatpak_ref: 'org.gimp.GIMP', scope: 'user' }],
    })
    await w.find('[data-testid="add-package-row"]').trigger('click')
    await w.find('[data-testid="package-release-1"] input').setValue('24.04')
    await w.find('[data-testid="package-flatpak-ref-1"] input').setValue('org.inkscape.Inkscape')
    await w.find('form').trigger('submit')
    const input = (w.emitted('submit') as unknown[][])[0][0] as { packages: { flatpak_ref?: string; scope?: string }[] }
    expect(input.packages[1]).toMatchObject({ flatpak_ref: 'org.inkscape.Inkscape', scope: 'system' })
  })
})
