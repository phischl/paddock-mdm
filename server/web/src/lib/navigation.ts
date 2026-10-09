/** What the signed-in administrator may see; the session store provides these flags. */
export interface NavigationAccess {
  isPlatform: boolean
  canWrite: boolean
  canDelete: boolean
  canReadAudit: boolean
  canReadGroups: boolean
}

/** One entry of the navigation drawer; label is a message key. */
export interface NavigationItem {
  to: string
  label: string
  visible: (access: NavigationAccess) => boolean
  testid?: string
}

/** A titled group of the navigation drawer; label is a message key. */
export interface NavigationGroup {
  key: string
  label: string
  items: NavigationItem[]
}

const orgReader = (a: NavigationAccess) => a.canReadGroups

/**
 * The drawer groups in their order (PDK-017 architect decision). Each item keeps the role rule its app bar link had
 * before the drawer; the pages themselves enforce the same rules through the API.
 */
export const navigationGroups: readonly NavigationGroup[] = [
  {
    key: 'overview',
    label: 'nav.groups.overview',
    items: [
      { to: '/', label: 'nav.start', visible: () => true },
      { to: '/attention', label: 'nav.attention', visible: orgReader, testid: 'nav-attention' },
    ],
  },
  {
    key: 'devices',
    label: 'nav.groups.devices',
    items: [
      { to: '/devices', label: 'nav.devices', visible: orgReader },
      { to: '/device-groups', label: 'nav.deviceGroups', visible: orgReader },
      { to: '/enrollment-tokens', label: 'nav.enrollmentTokens', visible: (a) => a.canWrite },
    ],
  },
  {
    key: 'configuration',
    label: 'nav.groups.configuration',
    items: [
      { to: '/permission-profiles', label: 'nav.permissionProfiles', visible: orgReader },
      { to: '/managed-files', label: 'nav.managedFiles', visible: orgReader },
      { to: '/managed-units', label: 'nav.managedUnits', visible: orgReader },
      { to: '/package-holds', label: 'nav.packageHolds', visible: orgReader },
      { to: '/change-sets', label: 'nav.changeSets', visible: orgReader },
    ],
  },
  {
    key: 'security',
    label: 'nav.groups.security',
    items: [
      { to: '/revocations', label: 'nav.revocations', visible: (a) => a.canDelete },
      { to: '/settings/dms', label: 'nav.dms', visible: orgReader },
      { to: '/settings/login', label: 'nav.loginSettings', visible: orgReader },
    ],
  },
  {
    key: 'inventory',
    label: 'nav.groups.inventory',
    items: [
      { to: '/software', label: 'nav.software', visible: orgReader },
      { to: '/vulnerabilities', label: 'nav.vulnerabilities', visible: orgReader },
    ],
  },
  {
    key: 'organization',
    label: 'nav.groups.organization',
    items: [
      { to: '/users', label: 'nav.users', visible: orgReader },
      { to: '/user-groups', label: 'nav.userGroups', visible: orgReader },
      { to: '/api-tokens', label: 'nav.apiTokens', visible: orgReader },
      { to: '/settings/updates', label: 'nav.updateSettings', visible: orgReader },
      { to: '/audit', label: 'nav.audit', visible: (a) => a.canReadAudit },
    ],
  },
  {
    key: 'platform',
    label: 'nav.groups.platform',
    items: [
      { to: '/platform/organizations', label: 'nav.organizations', visible: (a) => a.isPlatform },
      { to: '/platform/agent-releases', label: 'nav.agentReleases', visible: (a) => a.isPlatform },
    ],
  },
]

/** The groups with the items the administrator may see; a group without any is left out. */
export function visibleNavigation(access: NavigationAccess): NavigationGroup[] {
  return navigationGroups
    .map((g) => ({ ...g, items: g.items.filter((i) => i.visible(access)) }))
    .filter((g) => g.items.length > 0)
}
