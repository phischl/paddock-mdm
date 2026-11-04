import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SoftwareAssignmentForm from '../components/SoftwareAssignmentForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { updateRuleEnabled, versionEnabled } from '../lib/software'

function mountForm(initial: Record<string, unknown> | null = null) {
  return mount(SoftwareAssignmentForm, {
    props: { entryId: 'e1', groups: [{ id: 'g1', name: 'Laptops' }], initial: initial as never },
    global: { plugins: [createPortalI18n(), vuetify] },
    attachTo: document.body,
  })
}

const base = {
  id: 'a1', catalog_entry_id: 'e1', app_name: 'Editor', device_group_id: 'g1', reason: '', created_at: '', updated_at: '',
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
    expect(w.emitted('submit')).toEqual([[{ entryID: 'e1', groupID: 'g1', intent: 'required', updateRule: 'pinned', version: '2.0-1', reason: '' }]])
  })
})
