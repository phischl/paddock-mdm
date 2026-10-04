import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import DeviceGroupForm from '../components/DeviceGroupForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { validateDeviceGroup } from '../lib/validation'

function mountForm(props: Record<string, unknown> = {}) {
  return mount(DeviceGroupForm, {
    props: { submitLabel: 'Create', ...props },
    global: { plugins: [createPortalI18n(), vuetify] },
  })
}

describe('device group validation', () => {
  it('requires a name of at most 100 characters', () => {
    expect(validateDeviceGroup('', '')).toEqual({ name: 'validation.nameRequired' })
    expect(validateDeviceGroup('   ', '')).toEqual({ name: 'validation.nameRequired' })
    expect(validateDeviceGroup('x'.repeat(100), '')).toEqual({})
    expect(validateDeviceGroup('x'.repeat(101), '')).toEqual({ name: 'validation.nameTooLong' })
    expect(validateDeviceGroup('ä'.repeat(100), '')).toEqual({})
  })

  it('limits the description to 1000 characters', () => {
    expect(validateDeviceGroup('a', 'd'.repeat(1000))).toEqual({})
    expect(validateDeviceGroup('a', 'd'.repeat(1001))).toEqual({ description: 'validation.descriptionTooLong' })
  })
})

describe('DeviceGroupForm', () => {
  it('shows an error and does not submit an empty name', async () => {
    const wrapper = mountForm()
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    expect(wrapper.text()).toContain('Enter a name.')
    expect(wrapper.find('#device-group-name').attributes('aria-invalid')).toBe('true')
  })

  it('submits valid input', async () => {
    const wrapper = mountForm()
    await wrapper.find('#device-group-name').setValue('Laptops')
    await wrapper.find('#device-group-description').setValue('All laptops')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toEqual([[{ name: 'Laptops', description: 'All laptops' }]])
  })

  it('prefills values and shows server problems', () => {
    const wrapper = mountForm({ initialName: 'Servers', problem: 'name_taken' })
    expect((wrapper.find('#device-group-name').element as HTMLInputElement).value).toBe('Servers')
    // Vuetify's field message containers are role="alert" too; the server problem is the form-level paragraph.
    expect(wrapper.find('p[role="alert"]').text()).toBe('An item with this name already exists.')
  })
})
