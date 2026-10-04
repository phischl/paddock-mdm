import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import ProfileForm from '../components/ProfileForm.vue'
import EffectiveProfileView from '../components/EffectiveProfileView.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { auditText } from '../lib/format'
import { lines } from '../lib/loginSettings'
import { commandLines } from '../lib/profiles'
import { groupSlugPattern, slugFrom } from '../lib/userGroups'
import type { AuditEvent, UserEffectiveProfile } from '../api/client'

const global = { plugins: [createPortalI18n(), vuetify], stubs: { RouterLink: { template: '<a><slot /></a>' } } }

describe('text area lists', () => {
  it('take one entry per line and drop blank lines', () => {
    expect(commandLines(' /usr/bin/systemctl restart nginx.service \n\n/usr/bin/journalctl\n')).toEqual([
      '/usr/bin/systemctl restart nginx.service', '/usr/bin/journalctl',
    ])
    expect(lines('README\n 90-paddock \n')).toEqual(['README', '90-paddock'])
  })
})

describe('group slugs', () => {
  it('are suggested from upstream names and match the API rule', () => {
    expect(slugFrom('Engineering: Linux')).toBe('engineering-linux')
    expect(slugFrom('  Team #1 (DE) ')).toBe('team-1-de')
    expect(groupSlugPattern.test(slugFrom('Engineering: Linux'))).toBe(true)
    expect(groupSlugPattern.test('Ops')).toBe(false)
  })
})

describe('ProfileForm', () => {
  it('requires commands for a restricted profile and sends none for full rights', async () => {
    const wrapper = mount(ProfileForm, { props: { submitLabel: 'Create' }, global })
    await wrapper.find('#profile-name').setValue('nginx')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    expect(wrapper.text()).toContain('Enter at least one command.')
    await wrapper.find('#profile-commands').setValue('/usr/bin/systemctl restart nginx.service\n')
    await wrapper.find('#profile-timeout').setValue('61')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.text()).toContain('Enter 0 to 60 minutes.')
    await wrapper.find('#profile-timeout').setValue('5')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toMatchObject({
      name: 'nginx', class: 'restricted', commands: ['/usr/bin/systemctl restart nginx.service'], requirePassword: true,
      timestampTimeoutMin: 5, lecture: 'once',
    })
  })
})

describe('EffectiveProfileView', () => {
  const profile = {
    user: { id: 'u', username: 'dave@acme.test', display_name: 'Dave' }, device_id: null,
    class: 'restricted', reported_class: 'full', root_equivalent: true, root_equivalent_commands: ['/opt/x', '/usr/bin/cp /a /opt/x'],
    catalog_version: 1, commands: ['/opt/x', '/usr/bin/cp /a /opt/x'], require_password: true, timestamp_timeout_min: 5,
    lecture: 'always',
    derivation: [{
      kind: 'command', item: '/opt/x', value: '/opt/x', assignment_id: 'a1', profile_id: 'p1', profile_name: 'run',
      subject: { type: 'group', id: 'g1' },
    }],
  } as UserEffectiveProfile

  it('warns about root-equivalent combinations and shows where each right comes from', () => {
    const wrapper = mount(EffectiveProfileView, { props: { profile, subjectName: () => 'Operations' }, global })
    expect(wrapper.find('[data-testid="root-equivalent-warning"]').text()).toContain('/usr/bin/cp /a /opt/x')
    expect(wrapper.find('[data-testid="effective-class"]').text()).toBe('Restricted (reported as Full)')
    expect(wrapper.find('[data-testid="derivation"]').text()).toContain('Command /opt/x')
    expect(wrapper.find('[data-testid="derivation"]').text()).toContain('Operations')
  })
})

describe('audit texts of identity events', () => {
  const { t, te } = createPortalI18n().global
  it('render the privilege change of a membership', () => {
    const ev = {
      code: 'user_group.member_added', actor: { type: 'admin', display: 'alice@acme.test' },
      params: { user: 'dave@acme.test', group: 'ops', effective_class_before: 'none', effective_class_after: 'full' },
      target: { type: 'user_group', id: 'g', display: 'Operations' },
    } as unknown as AuditEvent
    expect(auditText(t, te, ev)).toBe('alice@acme.test added dave@acme.test to the group ops (highest rights none → full)')
    const locked = { ...ev, code: 'user.locked', params: { username: 'dave@acme.test', source: 'local' } } as unknown as AuditEvent
    expect(auditText(t, te, locked)).toBe('alice@acme.test locked the user dave@acme.test')
  })
})
