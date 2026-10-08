import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import ApiTokenForm from '../components/ApiTokenForm.vue'
import ChangeSetPlan from '../components/ChangeSetPlan.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { expiresAt, expiryBounds, rolesFor, validateApiToken } from '../lib/apiTokens'
import { planRows } from '../lib/changeSets'

const now = new Date(2026, 9, 8, 12, 0, 0)

describe('API token rules', () => {
  it('limits the role to the creator\'s ceiling', () => {
    expect(rolesFor('org_admin')).toEqual(['org_admin', 'org_operator', 'org_auditor'])
    expect(rolesFor('org_operator')).toEqual(['org_operator', 'org_auditor'])
    expect(rolesFor('org_auditor')).toEqual([])
    expect(rolesFor('platform_admin')).toEqual([])
    expect(validateApiToken({ name: 'ci', role: 'org_admin', expires: '2026-12-01' }, 'org_operator', now).role).toBe('apiTokens.roleAboveCeiling')
  })

  it('validates name and expiry like the server', () => {
    expect(validateApiToken({ name: 'ci deploy', role: 'org_auditor', expires: '2026-10-09' }, 'org_admin', now)).toEqual({})
    for (const name of ['', ' ci', '-ci', 'ci/deploy', 'a'.repeat(65)]) {
      expect(validateApiToken({ name, role: 'org_auditor', expires: '2026-10-09' }, 'org_admin', now).name).toBe('apiTokens.nameInvalid')
    }
    expect(validateApiToken({ name: 'ci', role: 'org_auditor', expires: '2026-10-08' }, 'org_admin', now).expires).toBe('apiTokens.expiryTooSoon')
    expect(validateApiToken({ name: 'ci', role: 'org_auditor', expires: '' }, 'org_admin', now).expires).toBe('apiTokens.expiryTooSoon')
    const b = expiryBounds(now)
    expect(validateApiToken({ name: 'ci', role: 'org_auditor', expires: b.maxDay }, 'org_admin', now)).toEqual({})
    expect(validateApiToken({ name: 'ci', role: 'org_auditor', expires: '2027-10-09' }, 'org_admin', now).expires).toBe('apiTokens.expiryTooLate')
    expect(b.defaultDay).toBe('2027-01-06')
    expect(expiresAt('2026-10-09', now).getTime() - now.getTime()).toBe(24 * 60 * 60 * 1000)
  })
})

describe('ApiTokenForm', () => {
  function mountForm(creatorRole: string) {
    return mount(ApiTokenForm, { props: { creatorRole, now }, global: { plugins: [createPortalI18n(), vuetify] } })
  }

  it('submits a valid token with the default expiry of 90 days', async () => {
    const wrapper = mountForm('org_operator')
    await wrapper.find('#api-token-name').setValue('ci')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toEqual([[{ name: 'ci', role: 'org_auditor', expires: '2027-01-06' }]])
  })

  it('refuses an invalid name and a date beyond 365 days', async () => {
    const wrapper = mountForm('org_admin')
    await wrapper.find('#api-token-name').setValue('-bad')
    await wrapper.find('#api-token-expires').setValue('2028-01-01')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    expect(wrapper.text()).toContain('The token can be valid for at most 365 days.')
    expect(wrapper.text()).toContain('The name must start with a letter or digit')
  })
})

describe('change set plan', () => {
  const plan = {
    changes: [
      { section: 'package_holds', key: 'firefox', action: 'delete' as const, fields: [{ name: 'package', before: 'firefox', after: null }] },
      { section: 'settings.login', key: '', action: 'update' as const, fields: [{ name: 'hello_enabled', before: false, after: true },
        { name: 'break_glass_accounts', before: [], after: ['root'] }] },
      { section: 'device_groups', key: 'laptops', action: 'create' as const, fields: [] },
    ],
    created: 1, updated: 1, deleted: 1,
  }

  it('lists one row per changed field in the plan order', () => {
    expect(planRows(plan)).toEqual([
      { section: 'package_holds', key: 'firefox', action: 'delete', field: 'package', before: 'firefox', after: '' },
      { section: 'settings.login', key: '', action: 'update', field: 'hello_enabled', before: 'false', after: 'true' },
      { section: 'settings.login', key: '', action: 'update', field: 'break_glass_accounts', before: '[]', after: '["root"]' },
      { section: 'device_groups', key: 'laptops', action: 'create', field: '', before: '', after: '' },
    ])
  })

  it('renders the table with translated actions', () => {
    const wrapper = mount(ChangeSetPlan, { props: { plan }, global: { plugins: [createPortalI18n(), vuetify] } })
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(4)
    expect(rows[0].text()).toContain('Deleted')
    expect(rows[2].text()).toContain('["root"]')
    expect(wrapper.findAll('th').map((h) => h.text())).toEqual(['Section', 'Item', 'Change', 'Field', 'Before', 'After'])
  })
})
