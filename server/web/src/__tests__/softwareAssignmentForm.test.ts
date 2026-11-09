import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SoftwareAssignmentForm from '../components/SoftwareAssignmentForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { updateRuleEnabled, versionEnabled } from '../lib/software'

function mountForm(initial: Record<string, unknown> | null = null) {
  return mount(SoftwareAssignmentForm, {
    props: {
      entryId: 'e1', groups: [{ id: 'g1', name: 'Laptops' }], users: [{ id: 'u1', username: 'alice@acme.test' }],
      userGroups: [{ id: 'ug1', name: 'Designers' }], initial: initial as never,
    },
    global: { plugins: [createPortalI18n(), vuetify] },
    attachTo: document.body,
  })
}

const base = {
  id: 'a1', catalog_entry_id: 'e1', app_name: 'Editor', device_group_id: 'g1', user_id: null, user_group_id: null, reason: '', urgent: false,
  created_at: '', updated_at: '',
}

function disabled(w: ReturnType<typeof mountForm>, id: string): boolean {
  return (w.find('#' + id).element as HTMLInputElement).disabled
}

describe('version and rule enablement (plan M13a decision 9)', () => {
  it.each([
    ['required', 'latest', false, true],
    ['required', 'pinned', true, true],
    ['hold', 'latest', true, false],
    ['uninstall', 'latest', false, false],
    ['forbid', 'latest', false, false],
  ] as const)('%s %s: version %s, rule %s', (intent, rule, version, ruleOn) => {
    expect(versionEnabled(intent, rule)).toBe(version)
    expect(updateRuleEnabled(intent)).toBe(ruleOn)
  })
})

describe('SoftwareAssignmentForm', () => {
  it('disables the version for required latest and enables it for required pinned', async () => {
    const w = mountForm({ ...base, intent: 'required', update_rule: 'latest', version: null })
    expect(disabled(w, 'assignment-version')).toBe(true)
    const pinned = mountForm({ ...base, intent: 'required', update_rule: 'pinned', version: '1.2.3' })
    expect(disabled(pinned, 'assignment-version')).toBe(false)
  })

  it('enables the version for hold and disables rule and version for uninstall and forbid', () => {
    const hold = mountForm({ ...base, intent: 'hold', update_rule: 'latest', version: null })
    expect(disabled(hold, 'assignment-version')).toBe(false)
    expect(disabled(hold, 'assignment-rule')).toBe(true)
    for (const intent of ['uninstall', 'forbid']) {
      const w = mountForm({ ...base, intent, update_rule: 'latest', version: null })
      expect(disabled(w, 'assignment-version')).toBe(true)
      expect(disabled(w, 'assignment-rule')).toBe(true)
    }
  })

  it('asks for the version of a pinned requirement and submits the normalized input', async () => {
    const w = mountForm({ ...base, intent: 'required', update_rule: 'pinned', version: '' })
    await w.find('form').trigger('submit')
    expect(w.text()).toContain('Enter the version to pin.')
    expect(w.emitted('submit')).toBeUndefined()
    await w.find('#assignment-version').setValue('2.0-1')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([[{ entryID: 'e1', target: 'device_group', targetID: 'g1', intent: 'required', updateRule: 'pinned', version: '2.0-1', reason: '', urgent: false }]])
  })

  it('shows the fixed user group target of a stored assignment and offers the intent available', async () => {
    const w = mountForm({ ...base, device_group_id: null, user_group_id: 'ug1', intent: 'available', update_rule: 'latest', version: null })
    expect(w.find('[data-testid="assignment-target"]').text()).toContain('User group')
    expect(w.find('[data-testid="assignment-target-id"]').text()).toContain('Designers')
    expect(disabled(w, 'assignment-target')).toBe(true)
    expect(w.find('[data-testid="assignment-intent"]').text()).toContain('Available')
    expect(disabled(w, 'assignment-rule')).toBe(true)
    expect(disabled(w, 'assignment-version')).toBe(true)
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([[{
      entryID: 'e1', target: 'user_group', targetID: 'ug1', intent: 'available', updateRule: 'latest', version: '', reason: '', urgent: false,
    }]])
  })

  it('asks for the user of a new user target and then submits exactly that one target', async () => {
    const w = mountForm()
    expect(w.find('[data-testid="assignment-target-id"]').exists()).toBe(false)
    const target = w.findComponent({ name: 'VSelect' })
    await target.setValue('user')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeUndefined()
    expect(w.text()).toContain('Choose the target.')
    const picker = w.findComponent({ name: 'VAutocomplete' })
    expect(picker.props('items')).toEqual([{ value: 'u1', title: 'alice@acme.test' }])
    await picker.setValue('u1')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([[{
      entryID: 'e1', target: 'user', targetID: 'u1', intent: 'required', updateRule: 'latest', version: '', reason: '', urgent: false,
    }]])
  })

  it('drops the picked target when the kind of target changes', async () => {
    const w = mountForm()
    const target = w.findComponent({ name: 'VSelect' })
    await target.setValue('device_group')
    await w.findComponent({ name: 'VAutocomplete' }).setValue('g1')
    await target.setValue('user_group')
    expect(w.findComponent({ name: 'VAutocomplete' }).props('modelValue')).toBeNull()
  })
  it('asks for a reason of an urgent assignment and submits urgent with it (plan M13c decision 7)', async () => {
    const w = mountForm({ ...base, intent: 'required', update_rule: 'latest', version: null })
    await w.find('[data-testid="assignment-urgent"] input').setValue(true)
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeUndefined()
    expect(w.text()).toContain('Enter a reason of 2 to 500 characters for an urgent assignment.')
    await w.find('#assignment-reason').setValue('CVE fix')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([[{
      entryID: 'e1', target: 'device_group', targetID: 'g1', intent: 'required', updateRule: 'latest', version: '', reason: 'CVE fix', urgent: true,
    }]])
  })

  it('keeps the urgent flag of a stored urgent assignment checked', () => {
    const w = mountForm({ ...base, intent: 'required', update_rule: 'latest', version: null, reason: 'CVE fix', urgent: true })
    expect((w.find('[data-testid="assignment-urgent"] input').element as HTMLInputElement).checked).toBe(true)
  })
})
