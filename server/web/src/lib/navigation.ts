import type { IconName } from './icons.gen'

/** What the signed-in administrator may see; the session store provides these flags. */
export interface NavigationAccess {
  isPlatform: boolean
  canWrite: boolean
  canDelete: boolean
  canReadAudit: boolean
  canReadGroups: boolean
}

/** One entry of the navigation drawer; label is a message key, shortcut the g-sequence that opens it (plan M7c). */
export interface NavigationItem {
  to: string
  label: string
  icon: IconName
  shortcut?: string
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
      { to: '/', label: 'nav.overview', icon: 'layout-dashboard', shortcut: 'g o', visible: () => true },
      { to: '/attention', label: 'nav.attention', icon: 'bell', shortcut: 'g a', visible: orgReader, testid: 'nav-attention' },
    ],
  },
  {
    key: 'devices',
    label: 'nav.groups.devices',
    items: [
      { to: '/devices', label: 'nav.devices', icon: 'laptop', shortcut: 'g d', visible: orgReader },
      { to: '/device-groups', label: 'nav.deviceGroups', icon: 'folder', visible: orgReader },
      { to: '/enrollment-tokens', label: 'nav.enrollmentTokens', icon: 'ticket', visible: (a) => a.canWrite },
    ],
  },
  {
    key: 'configuration',
    label: 'nav.groups.configuration',
    items: [
      { to: '/permission-profiles', label: 'nav.permissionProfiles', icon: 'shield-check', visible: orgReader },
      { to: '/managed-files', label: 'nav.managedFiles', icon: 'file-text', visible: orgReader },
      { to: '/managed-units', label: 'nav.managedUnits', icon: 'cog', visible: orgReader },
      { to: '/settings/managed-files', label: 'nav.operatorRoots', icon: 'folder', visible: orgReader },
      { to: '/package-holds', label: 'nav.packageHolds', icon: 'package', visible: orgReader },
      { to: '/change-sets', label: 'nav.changeSets', icon: 'diff', visible: orgReader },
    ],
  },
  {
    key: 'security',
    label: 'nav.groups.security',
    items: [
      { to: '/security-review', label: 'nav.securityReview', icon: 'triangle-alert', visible: orgReader },
      { to: '/revocations', label: 'nav.revocations', icon: 'lock', visible: (a) => a.canDelete },
      { to: '/settings/dms', label: 'nav.dms', icon: 'timer', visible: orgReader },
      { to: '/settings/login', label: 'nav.loginSettings', icon: 'log-in', visible: orgReader },
    ],
  },
  {
    key: 'inventory',
    label: 'nav.groups.inventory',
    items: [
      { to: '/software', label: 'nav.software', icon: 'package-search', shortcut: 'g s', visible: orgReader },
      { to: '/vulnerabilities', label: 'nav.vulnerabilities', icon: 'bug', shortcut: 'g v', visible: orgReader },
    ],
  },
  {
    key: 'organization',
    label: 'nav.groups.organization',
    items: [
      { to: '/users', label: 'nav.users', icon: 'user', visible: orgReader },
      { to: '/user-groups', label: 'nav.userGroups', icon: 'users', visible: orgReader },
      { to: '/api-tokens', label: 'nav.apiTokens', icon: 'key', visible: orgReader },
      { to: '/settings/mcp', label: 'nav.mcpSettings', icon: 'cog', visible: orgReader },
      { to: '/settings/updates', label: 'nav.updateSettings', icon: 'refresh-cw', visible: orgReader },
      { to: '/settings/rollout', label: 'nav.rolloutSettings', icon: 'rocket', visible: orgReader },
      { to: '/settings/privacy', label: 'nav.privacySettings', icon: 'shield', visible: orgReader },
      { to: '/audit', label: 'nav.audit', icon: 'scroll-text', shortcut: 'g l', visible: (a) => a.canReadAudit },
      { to: '/audit/integrity', label: 'nav.auditIntegrity', icon: 'shield-check', visible: (a) => a.canReadAudit, testid: 'nav-audit-integrity' },
      { to: '/audit/exports', label: 'nav.auditExports', icon: 'file-check', visible: (a) => a.canReadAudit, testid: 'nav-audit-exports' },
    ],
  },
  {
    key: 'platform',
    label: 'nav.groups.platform',
    items: [
      { to: '/platform/organizations', label: 'nav.organizations', icon: 'building-complex', visible: (a) => a.isPlatform },
      { to: '/platform/agent-releases', label: 'nav.agentReleases', icon: 'rocket', visible: (a) => a.isPlatform },
      { to: '/platform/ip-allowlist', label: 'nav.ipAllowlist', icon: 'globe-lock', visible: (a) => a.isPlatform },
      { to: '/platform/sessions', label: 'nav.sessions', icon: 'log-in', visible: (a) => a.isPlatform },
      { to: '/platform/openbao', label: 'nav.openbao', icon: 'shield-check', visible: (a) => a.isPlatform },
      { to: '/platform/mcp', label: 'nav.platformMcp', icon: 'cog', visible: (a) => a.isPlatform },
    ],
  },
]

/** The shortcut of the navigation item of a path, for hints next to links to it; '' when it has none. */
export function shortcutOf(to: string): string {
  return navigationGroups.flatMap((g) => g.items).find((i) => i.to === to)?.shortcut ?? ''
}

/** The sequence shortcuts (g + key) of the visible items: key → route. */
export function shortcutRoutes(groups: NavigationGroup[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const g of groups) {
    for (const i of g.items) {
      if (i.shortcut?.startsWith('g ')) out[i.shortcut.slice(2)] = i.to
    }
  }
  return out
}

/** The groups with the items the administrator may see; a group without any is left out. */
export function visibleNavigation(access: NavigationAccess): NavigationGroup[] {
  return navigationGroups
    .map((g) => ({ ...g, items: g.items.filter((i) => i.visible(access)) }))
    .filter((g) => g.items.length > 0)
}
