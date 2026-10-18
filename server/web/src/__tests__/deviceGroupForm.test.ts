import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import DeviceGroupForm from '../components/DeviceGroupForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { validateDeviceGroup } from '../lib/validation'
import { effectiveStaleness } from '../lib/deviceGroups'

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
    expect(wrapper.emitted('submit')).toEqual([[{ name: 'Laptops', description: 'All laptops', staleness: null, agent_update_policy: null }]])
  })

  it('fills the laptop preset and submits the override (PDK-222)', async () => {
    const wrapper = mountForm()
    await wrapper.find('#device-group-name').setValue('Laptops')
    expect(wrapper.find('[data-testid="group-staleness"] legend').text()).toBe('Contact thresholds')
    await wrapper.find('[data-testid="group-staleness-laptop"]').trigger('click')
    expect((wrapper.find('#device-group-staleness-warning').element as HTMLInputElement).value).toBe('120')
    expect((wrapper.find('#device-group-staleness-critical').element as HTMLInputElement).value).toBe('840')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toEqual([[{ name: 'Laptops', description: '', staleness: { warning_h: 120, critical_h: 840 }, agent_update_policy: null }]])
  })

  it('prefills an existing override and clears it when switched off', async () => {
    const wrapper = mountForm({ initialName: 'Servers', initialStaleness: { warning_h: 2, critical_h: 4 } })
    expect((wrapper.find('#device-group-staleness-warning').element as HTMLInputElement).value).toBe('2')
    await wrapper.find('#device-group-staleness-override').setValue(false)
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toEqual([[{ name: 'Servers', description: '', staleness: null, agent_update_policy: null }]])
  })

  it('keeps the agent update policy override of a group (PDK-225)', async () => {
    const wrapper = mountForm({ initialName: 'Kiosks', initialAgentUpdatePolicy: 'manual' })
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toMatchObject({ agent_update_policy: 'manual' })
  })

  it('prefills values and shows server problems', () => {
    const wrapper = mountForm({ initialName: 'Servers', problem: 'name_taken' })
    expect((wrapper.find('#device-group-name').element as HTMLInputElement).value).toBe('Servers')
    // Vuetify's field message containers are role="alert" too; the server problem is the form-level paragraph.
    expect(wrapper.find('p[role="alert"]').text()).toBe('An item with this name already exists.')
  })
})

describe('effective contact thresholds (PDK-222)', () => {
  const org = { staleness_warning_h: 24, staleness_critical_h: 168 }
  it('takes the group override, else the organization', () => {
    expect(effectiveStaleness({ staleness: { warning_h: 120, critical_h: 840 } }, org))
      .toEqual({ warning: 120, critical: 840, source: 'device_group' })
    expect(effectiveStaleness({ staleness: null }, org)).toEqual({ warning: 24, critical: 168, source: 'organization' })
    expect(effectiveStaleness({ staleness: null }, null)).toBeNull()
  })
})
