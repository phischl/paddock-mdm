import { describe, expect, it } from 'vitest'
import { visibleNavigation, type NavigationAccess } from '../lib/navigation'

const access = (role: 'org_admin' | 'org_operator' | 'org_auditor'): NavigationAccess => ({
  isPlatform: false,
  canWrite: role !== 'org_auditor',
  canDelete: role === 'org_admin',
  canReadAudit: role !== 'org_operator',
  canReadGroups: true,
})

function paths(role: Parameters<typeof access>[0]): string[] {
  return visibleNavigation(access(role)).flatMap((g) => g.items.map((i) => i.to))
}

describe('software navigation (plan M13a decision 31)', () => {
  it('shows the package sources to administrators only and the catalog to every reader, before the package holds', () => {
    expect(paths('org_admin')).toContain('/software-sources')
    expect(paths('org_operator')).not.toContain('/software-sources')
    expect(paths('org_auditor')).not.toContain('/software-sources')
    for (const role of ['org_admin', 'org_operator', 'org_auditor'] as const) {
      const p = paths(role)
      expect(p).toContain('/software-catalog')
      expect(p.indexOf('/software-catalog')).toBeLessThan(p.indexOf('/package-holds'))
    }
  })

  it('shows the software requests to every reader of the organization (plan M13c decision 10)', () => {
    for (const role of ['org_admin', 'org_operator', 'org_auditor'] as const) expect(paths(role)).toContain('/software-requests')
  })
})
