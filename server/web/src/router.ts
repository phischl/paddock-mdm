import { createRouter, createWebHistory, type RouteLocationRaw } from 'vue-router'
import { useSessionStore } from './stores/session'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: () => import('./views/Overview.vue') },
    { path: '/attention', name: 'attention', component: () => import('./views/Attention.vue') },
    { path: '/security-review', name: 'security-review', component: () => import('./views/SecurityReview.vue') },
    { path: '/login-denied', name: 'login-denied', component: () => import('./views/LoginDenied.vue'), meta: { public: true } },
    { path: '/device-groups', name: 'device-groups', component: () => import('./views/DeviceGroups.vue') },
    { path: '/device-groups/:id', name: 'device-group', component: () => import('./views/DeviceGroupDetail.vue') },
    { path: '/devices', name: 'devices', component: () => import('./views/Devices.vue') },
    {
      // The device frame (pane, header band, tabs) loads the device once; the tabs are its children (plan M7c decision 29).
      path: '/devices/:id', component: () => import('./views/DeviceDetail.vue'),
      children: [
        { path: '', name: 'device', component: () => import('./views/DeviceOverview.vue') },
        { path: 'software', name: 'device-software', component: () => import('./views/DeviceSoftware.vue') },
        { path: 'vulnerabilities', name: 'device-vulnerabilities', component: () => import('./views/DeviceVulnerabilities.vue') },
        { path: 'access', name: 'device-access', component: () => import('./views/DeviceAccess.vue') },
        { path: 'logins', name: 'device-logins', component: () => import('./views/DeviceLogins.vue') },
        { path: 'configuration', name: 'device-configuration', component: () => import('./views/DeviceConfiguration.vue') },
        { path: 'commands', name: 'device-commands', component: () => import('./views/DeviceCommands.vue') },
        { path: 'audit', name: 'device-audit', component: () => import('./views/DeviceAudit.vue') },
      ],
    },
    { path: '/software', name: 'software', component: () => import('./views/Software.vue') },
    { path: '/vulnerabilities', name: 'vulnerabilities', component: () => import('./views/Vulnerabilities.vue') },
    { path: '/vulnerabilities/:cve', name: 'vulnerability', component: () => import('./views/VulnerabilityDevices.vue') },
    { path: '/enrollment-tokens', name: 'enrollment-tokens', component: () => import('./views/EnrollmentTokens.vue') },
    { path: '/api-tokens', name: 'api-tokens', component: () => import('./views/ApiTokens.vue') },
    { path: '/change-sets', name: 'change-sets', component: () => import('./views/ChangeSets.vue') },
    { path: '/managed-files', name: 'managed-files', component: () => import('./views/ManagedFiles.vue') },
    { path: '/managed-units', name: 'managed-units', component: () => import('./views/ManagedUnits.vue') },
    { path: '/users', name: 'users', component: () => import('./views/Users.vue') },
    { path: '/users/:id', name: 'user', component: () => import('./views/UserDetail.vue') },
    { path: '/user-groups', name: 'user-groups', component: () => import('./views/UserGroups.vue') },
    { path: '/user-groups/:id', name: 'user-group', component: () => import('./views/UserGroupDetail.vue') },
    { path: '/permission-profiles', name: 'permission-profiles', component: () => import('./views/PermissionProfiles.vue') },
    {
      path: '/permission-profiles/:id', name: 'permission-profile',
      component: () => import('./views/PermissionProfileDetail.vue'),
    },
    { path: '/settings/login', name: 'login-settings', component: () => import('./views/LoginSettings.vue') },
    { path: '/settings/dms', name: 'dms-settings', component: () => import('./views/DMSSettings.vue') },
    { path: '/settings/managed-files', name: 'managed-file-settings', component: () => import('./views/ManagedFileSettings.vue') },
    { path: '/settings/updates', name: 'update-settings', component: () => import('./views/UpdateSettings.vue') },
    { path: '/settings/rollout', name: 'rollout-settings', component: () => import('./views/RolloutSettings.vue') },
    { path: '/settings/privacy', name: 'privacy-settings', component: () => import('./views/PrivacySettings.vue') },
    { path: '/settings/mcp', name: 'mcp-settings', component: () => import('./views/McpSettings.vue') },
    { path: '/package-holds', name: 'package-holds', component: () => import('./views/PackageHolds.vue') },
    { path: '/revocations', name: 'revocations', component: () => import('./views/RevocationRequests.vue') },
    { path: '/audit', name: 'audit', component: () => import('./views/Audit.vue') },
    { path: '/audit/integrity', name: 'audit-integrity', component: () => import('./views/AuditIntegrity.vue') },
    { path: '/audit/exports', name: 'audit-exports', component: () => import('./views/AuditExports.vue') },
    { path: '/platform/organizations', name: 'organizations', component: () => import('./views/Organizations.vue') },
    { path: '/platform/agent-releases', name: 'agent-releases', component: () => import('./views/AgentReleases.vue') },
    { path: '/platform/agent-releases/:version', name: 'agent-release', component: () => import('./views/AgentReleaseDetail.vue') },
    { path: '/platform/ip-allowlist', name: 'ip-allowlist', component: () => import('./views/IpAllowlist.vue') },
    { path: '/platform/sessions', name: 'platform-sessions', component: () => import('./views/PlatformSessions.vue') },
    { path: '/platform/openbao', name: 'platform-openbao', component: () => import('./views/PlatformOpenBao.vue') },
    { path: '/platform/mcp', name: 'platform-mcp', component: () => import('./views/PlatformMcp.vue') },
    { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('./views/NotFound.vue') },
  ],
})

/**
 * Start page by role (plan M7c decision 28): administrators and operators start on the overview, auditors on the
 * audit log, platform administrators on the organizations.
 */
export function homeFor(role: string | null | undefined): RouteLocationRaw {
  switch (role) {
    case 'platform_admin':
      return { name: 'organizations' }
    case 'org_auditor':
      return { name: 'audit' }
    default:
      return { name: 'home' }
  }
}

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const session = useSessionStore()
  const me = await session.load()
  if (!me) return false // the API client redirects to the login
  if (to.name === 'home' && (me.role === 'platform_admin' || me.role === 'org_auditor')) return homeFor(me.role)
  return true
})
