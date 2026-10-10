import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import IpAllowlistEntryForm from '../components/IpAllowlistEntryForm.vue'
import IpAllowlistStatus from '../components/IpAllowlistStatus.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { parseCIDR, singleAddressCIDR } from '../lib/cidr'
import { confirmationOf, validateIpAllowlistEntry } from '../lib/ipAllowlist'

describe('parseCIDR', () => {
  it('accepts IPv4 and IPv6 ranges in their canonical form', () => {
    const valid: Record<string, string> = {
      '10.0.0.0/8': '10.0.0.0/8',
      ' 198.51.100.7/32 ': '198.51.100.7/32',
      '192.0.2.128/25': '192.0.2.128/25',
      '2001:db8::/32': '2001:db8::/32',
      '2001:DB8:0:0:0:0:0:0/32': '2001:db8::/32',
      '2001:db8::9/128': '2001:db8::9/128',
      'fe80::/10': 'fe80::/10',
      '::1/128': '::1/128',
      '2001:db8:0:0:1:0:0:1/128': '2001:db8::1:0:0:1/128',
      '2001:db8:0:1:1:1:1:1/128': '2001:db8:0:1:1:1:1:1/128',
      '64:ff9b::192.0.2.0/120': '64:ff9b::c000:200/120',
    }
    for (const [input, canonical] of Object.entries(valid)) {
      const kind = canonical.includes(':') ? 'v6' : 'v4'
      expect(parseCIDR(input), input).toEqual({ ok: true, kind, canonical })
    }
  })

  it('refuses what the server refuses, naming the canonical form for host bits', () => {
    const invalid: Record<string, string> = {
      '': 'ipAllowlist.cidrInvalid',
      '10.0.0.1': 'ipAllowlist.cidrInvalid',
      '2001:db8::9': 'ipAllowlist.cidrInvalid',
      '10.0.0.256/8': 'ipAllowlist.cidrInvalid',
      '10.0.0/8': 'ipAllowlist.cidrInvalid',
      '010.0.0.0/8': 'ipAllowlist.cidrInvalid',
      '10.0.0.0/33': 'ipAllowlist.cidrInvalid',
      '10.0.0.0/8/1': 'ipAllowlist.cidrInvalid',
      'example.com/24': 'ipAllowlist.cidrInvalid',
      '2001:db8::/129': 'ipAllowlist.cidrInvalid',
      '2001:db8:::1/64': 'ipAllowlist.cidrInvalid',
      '2001::db8::1/64': 'ipAllowlist.cidrInvalid',
      '2001:db8:0:0:0:0:0:0:1/64': 'ipAllowlist.cidrInvalid',
      '2001:db8:12345::/64': 'ipAllowlist.cidrInvalid',
      '2001:dbg::/64': 'ipAllowlist.cidrInvalid',
      'fe80::1%eth0/64': 'ipAllowlist.cidrInvalid',
      '0.0.0.0/0': 'ipAllowlist.cidrZero',
      '::/0': 'ipAllowlist.cidrZero',
      '::ffff:10.0.0.0/104': 'ipAllowlist.cidrMapped',
      '10.0.0.1/8': 'ipAllowlist.cidrHostBits',
      '2001:db8::9/32': 'ipAllowlist.cidrHostBits',
    }
    for (const [input, message] of Object.entries(invalid)) {
      const res = parseCIDR(input)
      expect(res.ok, input).toBe(false)
      if (!res.ok) expect(res.message, input).toBe(message)
    }
    expect(parseCIDR('10.0.0.1/8')).toEqual({ ok: false, message: 'ipAllowlist.cidrHostBits', canonical: '10.0.0.0/8' })
    expect(parseCIDR('2001:db8::9/32')).toEqual({ ok: false, message: 'ipAllowlist.cidrHostBits', canonical: '2001:db8::/32' })
    expect(parseCIDR('192.0.2.9/24')).toEqual({ ok: false, message: 'ipAllowlist.cidrHostBits', canonical: '192.0.2.0/24' })
  })

  it('derives the single-address range and validates the label', () => {
    expect(singleAddressCIDR('198.51.100.7')).toBe('198.51.100.7/32')
    expect(singleAddressCIDR('2001:db8::9')).toBe('2001:db8::9/128')
    expect(validateIpAllowlistEntry({ cidr: '10.0.0.0/8', label: ' office ' })).toEqual({})
    expect(validateIpAllowlistEntry({ cidr: '10.0.0.1/8', label: '' })).toEqual({
      cidr: 'ipAllowlist.cidrHostBits', label: 'ipAllowlist.labelInvalid',
    })
    expect(validateIpAllowlistEntry({ cidr: '10.0.0.0/8', label: 'x'.repeat(65) }).label).toBe('ipAllowlist.labelInvalid')
    expect(validateIpAllowlistEntry({ cidr: '10.0.0.0/8', label: 'a\tb' }).label).toBe('ipAllowlist.labelInvalid')
    expect(confirmationOf('lockout_confirmation_required')).toBe('lockout')
    expect(confirmationOf('disable_confirmation_required')).toBe('disable')
    expect(confirmationOf('already_exists')).toBeNull()
  })
})

const plugins = [createPortalI18n(), vuetify]

describe('IpAllowlistEntryForm', () => {
  it('fills the own address and submits the trimmed input', async () => {
    const wrapper = mount(IpAllowlistEntryForm, { props: { clientIp: '198.51.100.7' }, global: { plugins } })
    await wrapper.find('[data-testid="use-my-address"]').trigger('click')
    expect((wrapper.find('#ip-allowlist-cidr').element as HTMLInputElement).value).toBe('198.51.100.7/32')
    await wrapper.find('#ip-allowlist-label').setValue('  gate host ')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toEqual([[{ cidr: '198.51.100.7/32', label: 'gate host' }]])
  })

  it('refuses host bits and an empty label before the request', async () => {
    const wrapper = mount(IpAllowlistEntryForm, { props: { clientIp: '2001:db8::9' }, global: { plugins } })
    await wrapper.find('#ip-allowlist-cidr').setValue('10.0.0.1/8')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
    expect(wrapper.text()).toContain('The host bits must be zero.')
    expect(wrapper.text()).toContain('The label must have 1 to 64 characters')
    expect(wrapper.text()).toContain('Use my address (2001:db8::9)')
  })

  it('edits an existing entry and shows the server problem', () => {
    const wrapper = mount(IpAllowlistEntryForm, {
      props: { clientIp: '198.51.100.7', initial: { cidr: '10.0.0.0/8', label: 'office' }, problem: 'already_exists' },
      global: { plugins },
    })
    expect((wrapper.find('#ip-allowlist-cidr').element as HTMLInputElement).value).toBe('10.0.0.0/8')
    expect(wrapper.find('button[type="submit"]').text()).toBe('Save')
    expect(wrapper.find('p.form-error').text()).toContain('already')
  })
})

describe('IpAllowlistStatus', () => {
  const mountStatus = (entries: number, covering: string[]) =>
    mount(IpAllowlistStatus, { props: { clientIp: '198.51.100.7', entries, covering }, global: { plugins } })

  it('reports the list as off', () => {
    const w = mountStatus(0, [])
    expect(w.text()).toContain('Your current address: 198.51.100.7')
    expect(w.text()).toContain('The allow list is off: no entries.')
    expect(w.find('[data-testid="ip-allowlist-status"]').attributes('data-state')).toBe('off')
  })

  it('names the covering ranges', () => {
    const w = mountStatus(3, ['198.51.100.0/24', '198.51.100.7/32'])
    expect(w.text()).toContain('Enabled with 3 entries; your address is covered by 198.51.100.0/24, 198.51.100.7/32.')
    expect(w.find('[data-testid="ip-allowlist-status"]').attributes('data-state')).toBe('covered')
  })

  it('warns when the caller is not covered', () => {
    const w = mountStatus(2, [])
    expect(w.text()).toContain('your address is not covered')
    expect(w.find('[data-testid="ip-allowlist-status"]').attributes('data-state')).toBe('notCovered')
  })
})
