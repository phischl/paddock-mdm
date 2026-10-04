import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import ManagedFileForm from '../components/ManagedFileForm.vue'
import EnrollmentTokenForm from '../components/EnrollmentTokenForm.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { actionsFor, reportText } from '../lib/devices'
import { configText } from '../lib/enrollmentTokens'
import { validateFile, validateUnit, type FileInput } from '../lib/managedConfig'
import { auditText } from '../lib/format'
import type { AuditEvent, EnrollmentTokenCreated } from '../api/client'

const global = { plugins: [createPortalI18n(), vuetify] }
const file = (patch: Partial<FileInput> = {}): FileInput => ({
  groupID: null, path: '/etc/motd', mode: '0644', owner: 'root', group: 'root', content: 'hi', ...patch,
})

describe('device lifecycle actions', () => {
  it('offers only the transitions of the state', () => {
    expect(actionsFor('pending')).toEqual(['approve', 'reject'])
    expect(actionsFor('active')).toEqual(['retire'])
    expect(actionsFor('quarantined')).toEqual(['release-quarantine', 'retire'])
    expect(actionsFor('retired')).toEqual([])
    expect(actionsFor('rejected')).toEqual([])
  })
})

describe('device reports', () => {
  const { t } = createPortalI18n().global
  const at = '2026-10-04T08:00:00Z'

  it('renders the latest login and sudo report', () => {
    expect(reportText(t, { type: 'login.applied', occurred_at: at, params: { changed: ['package', 'config'] } }))
      .toBe('Login configuration applied: package, config')
    expect(reportText(t, { type: 'login.apply_failed', occurred_at: at, params: { stage: 'apt', message: 'dpkg lock' } }))
      .toBe('Login configuration failed at stage apt: dpkg lock')
    expect(reportText(t, { type: 'sudo.apply_failed', occurred_at: at, params: { username: 'dave@acme.test', message: 'visudo' } }))
      .toBe('The sudo rights of dave@acme.test could not be applied: visudo')
    expect(reportText(t, { type: 'sudo.apply_failed', occurred_at: at, params: { message: 'no includedir' } }))
      .toBe('The sudo configuration failed its check: no includedir')
    expect(reportText(t, { type: 'sudo.user_unresolved', occurred_at: at, params: { username: 'erin@acme.test' } }))
      .toBe('erin@acme.test has sudo rights but is not known on the device yet')
    expect(reportText(t, { type: 'login.future', occurred_at: at, params: {} })).toBe('login.future')
  })
})

describe('managed configuration validation', () => {
  it('mirrors the path, mode, owner and size rules', () => {
    expect(validateFile(file())).toEqual({})
    expect(validateFile(file({ path: '/usr/local/etc/a.conf' }))).toEqual({})
    expect(validateFile(file({ path: '/var/x' })).path).toBe('validation.pathInvalid')
    expect(validateFile(file({ path: '/etc/../root/x' })).path).toBe('validation.pathInvalid')
    expect(validateFile(file({ mode: '4755' })).mode).toBe('validation.modeInvalid')
    expect(validateFile(file({ owner: 'Root' })).owner).toBe('validation.ownerInvalid')
    expect(validateFile(file({ content: 'x'.repeat(64 * 1024 + 1) })).content).toBe('validation.contentTooLarge')
    expect(validateUnit({ groupID: null, unit: 'chrony.service', enabled: true, active: true })).toEqual({})
    expect(validateUnit({ groupID: null, unit: 'chrony', enabled: true, active: true }).unit).toBe('validation.unitInvalid')
  })

  it('ManagedFileForm does not submit an invalid path', async () => {
    const wrapper = mount(ManagedFileForm, { props: { groups: [] }, global })
    await wrapper.find('#file-path').setValue('/var/lib/x')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    expect(wrapper.text()).toContain('Enter an absolute path below /etc/, /usr/local/etc/ or /opt/.')
    await wrapper.find('#file-path').setValue('/etc/motd')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toMatchObject({ path: '/etc/motd', mode: '0644', owner: 'root' })
  })
})

describe('enrollment tokens', () => {
  it('EnrollmentTokenForm requires a name and 1 to 1000 uses', async () => {
    const wrapper = mount(EnrollmentTokenForm, { props: { groups: [] }, global })
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    await wrapper.find('#token-name').setValue('Laptops')
    await wrapper.find('#token-max-uses').setValue('1001')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.text()).toContain('Enter a number from 1 to 1000.')
    await wrapper.find('#token-max-uses').setValue('5')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toMatchObject({ name: 'Laptops', maxUses: 5, validDays: 7, autoApprove: false, groupID: null })
  })

  it('renders the enrollment configuration as the device reads it', () => {
    const created = {
      token: {}, secret: 's3cret',
      enrollment_config: { server_url: 'https://device.test', organization_id: 'o', token: 's3cret', bundle_keys: [] },
    } as unknown as EnrollmentTokenCreated
    expect(JSON.parse(configText(created))).toEqual(created.enrollment_config)
  })
})

describe('audit texts of device events', () => {
  const { t, te } = createPortalI18n().global
  it('render the hostname from params or the target', () => {
    const ev = {
      code: 'device.retired', params: { hostname: 'lt-1' }, actor: { type: 'admin', display: 'alice@acme.test' },
      target: { type: 'device', id: 'x', display: 'lt-1' },
    } as unknown as AuditEvent
    expect(auditText(t, te, ev)).toBe('alice@acme.test retired the device lt-1')
    const applied = { ...ev, code: 'device.bundle_applied', params: { bundle_version: 3 }, actor: { type: 'device' } } as unknown as AuditEvent
    expect(auditText(t, te, applied)).toBe('The device lt-1 applied bundle 3')
  })
})
