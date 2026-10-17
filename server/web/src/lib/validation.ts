/** Client-side validation mirroring the API rules; values are message keys. */
export interface DeviceGroupErrors {
  name?: 'validation.nameRequired' | 'validation.nameTooLong'
  description?: 'validation.descriptionTooLong'
}

export function validateDeviceGroup(name: string, description: string): DeviceGroupErrors {
  const errors: DeviceGroupErrors = {}
  const trimmed = name.trim()
  if (trimmed.length === 0) errors.name = 'validation.nameRequired'
  else if ([...trimmed].length > 100) errors.name = 'validation.nameTooLong'
  if ([...description.trim()].length > 1000) errors.description = 'validation.descriptionTooLong'
  return errors
}

export const slugPattern = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/

export interface OrganizationErrors {
  slug?: 'validation.slugInvalid'
  name?: 'validation.orgNameRequired'
}

export function validateOrganization(slug: string, name: string): OrganizationErrors {
  const errors: OrganizationErrors = {}
  if (!slugPattern.test(slug) || slug === 'platform') errors.slug = 'validation.slugInvalid'
  const n = [...name.trim()].length
  if (n < 1 || n > 200) errors.name = 'validation.orgNameRequired'
  return errors
}

/** The server's domain rule (organization.ValidateDomains), repeated for the form; the server stays authoritative. */
const domainPattern = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/

/** The domains of a text area: one per line, trimmed and lower-cased, blank lines dropped. */
export function parseDomains(text: string): string[] {
  return text.split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l !== '')
}

/** Validates the domains of a text area; returns '' or the message key. */
export function validateDomains(text: string): '' | 'validation.domainsInvalid' {
  const domains = parseDomains(text)
  const valid = domains.length <= 20 && new Set(domains).size === domains.length &&
    domains.every((d) => d.length <= 253 && domainPattern.test(d))
  return valid ? '' : 'validation.domainsInvalid'
}

export function hasErrors(errors: object): boolean {
  return Object.values(errors).some(Boolean)
}
